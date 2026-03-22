package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"vscan-mohesr/internal/models"
)

type SSLScanner struct{}

func NewSSLScanner() *SSLScanner {
	return &SSLScanner{}
}

func (s *SSLScanner) Name() string     { return "SSL/TLS Scanner" }
func (s *SSLScanner) Category() string { return "ssl" }
func (s *SSLScanner) Weight() float64  { return 20.0 }

func (s *SSLScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	// Check HTTPS availability
	results = append(results, s.checkHTTPS(url))

	// Check certificate validity
	results = append(results, s.checkCertificate(url))

	// Check TLS version
	results = append(results, s.checkTLSVersion(url))

	// Check HTTPS redirect
	results = append(results, s.checkHTTPSRedirect(url))

	return results
}

func (s *SSLScanner) checkHTTPS(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "HTTPS Enabled",
		Weight:    5.0,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	httpsURL := ensureHTTPS(url)
	resp, err := client.Get(httpsURL)
	if err != nil {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{"error": "HTTPS not available: " + err.Error()})
		return check
	}
	defer resp.Body.Close()

	check.Status = "pass"
	check.Score = 100
	check.Severity = "info"
	check.Details = toJSON(map[string]string{"message": "HTTPS is available"})
	return check
}

func (s *SSLScanner) checkCertificate(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Certificate Validity",
		Weight:    5.0,
	}

	host := extractHost(url)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		host+":443",
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{"error": "Cannot establish TLS connection: " + err.Error()})
		return check
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{"error": "No certificates found"})
		return check
	}

	cert := certs[0]
	now := time.Now()

	details := map[string]interface{}{
		"issuer":     cert.Issuer.CommonName,
		"subject":    cert.Subject.CommonName,
		"not_before": cert.NotBefore.Format(time.RFC3339),
		"not_after":  cert.NotAfter.Format(time.RFC3339),
		"dns_names":  cert.DNSNames,
	}

	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		details["message"] = "Certificate is expired or not yet valid"
	} else {
		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
		details["days_until_expiry"] = daysUntilExpiry

		if daysUntilExpiry < 30 {
			check.Status = "warning"
			check.Score = 50
			check.Severity = "medium"
			details["message"] = fmt.Sprintf("Certificate expires in %d days", daysUntilExpiry)
		} else {
			check.Status = "pass"
			check.Score = 100
			check.Severity = "info"
			details["message"] = fmt.Sprintf("Certificate valid for %d more days", daysUntilExpiry)
		}
	}

	check.Details = toJSON(details)
	return check
}

func (s *SSLScanner) checkTLSVersion(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "TLS Version",
		Weight:    5.0,
	}

	host := extractHost(url)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		host+":443",
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Severity = "high"
		check.Details = toJSON(map[string]string{"error": err.Error()})
		return check
	}
	defer conn.Close()

	version := conn.ConnectionState().Version
	details := map[string]interface{}{}

	switch version {
	case tls.VersionTLS13:
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		details["version"] = "TLS 1.3"
		details["message"] = "Excellent - using latest TLS version"
	case tls.VersionTLS12:
		check.Status = "pass"
		check.Score = 80
		check.Severity = "info"
		details["version"] = "TLS 1.2"
		details["message"] = "Good - TLS 1.2 is acceptable"
	case tls.VersionTLS11:
		check.Status = "warning"
		check.Score = 30
		check.Severity = "high"
		details["version"] = "TLS 1.1"
		details["message"] = "TLS 1.1 is deprecated and insecure"
	default:
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		details["version"] = "TLS 1.0 or older"
		details["message"] = "Very old TLS version - highly insecure"
	}

	check.Details = toJSON(details)
	return check
}

func (s *SSLScanner) checkHTTPSRedirect(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "HTTP to HTTPS Redirect",
		Weight:    5.0,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	httpURL := ensureHTTP(url)
	resp, err := client.Get(httpURL)
	if err != nil {
		check.Status = "warning"
		check.Score = 50
		check.Severity = "medium"
		check.Details = toJSON(map[string]string{"error": "Cannot reach HTTP version: " + err.Error()})
		return check
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && len(location) > 4 && location[:5] == "https" {
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message":     "HTTP correctly redirects to HTTPS",
			"redirect_to": location,
		})
	} else {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "high"
		check.Details = toJSON(map[string]string{
			"message":     "HTTP does not redirect to HTTPS",
			"status_code": fmt.Sprintf("%d", resp.StatusCode),
		})
	}

	return check
}
