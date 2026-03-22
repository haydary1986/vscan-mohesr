package scanner

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type ServerInfoScanner struct{}

func NewServerInfoScanner() *ServerInfoScanner {
	return &ServerInfoScanner{}
}

func (s *ServerInfoScanner) Name() string     { return "Server Information Scanner" }
func (s *ServerInfoScanner) Category() string { return "server_info" }
func (s *ServerInfoScanner) Weight() float64  { return 15.0 }

func (s *ServerInfoScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(ensureHTTPS(url))
	if err != nil {
		resp, err = client.Get(ensureHTTP(url))
		if err != nil {
			return []models.CheckResult{{
				Category:  s.Category(),
				CheckName: "Server Information",
				Status:    "error",
				Score:     0,
				Weight:    s.Weight(),
				Severity:  "high",
				Details:   toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()}),
			}}
		}
	}
	defer resp.Body.Close()

	// Check Server header exposure
	results = append(results, s.checkServerHeader(resp))

	// Check X-Powered-By header
	results = append(results, s.checkPoweredBy(resp))

	// Check CMS detection
	results = append(results, s.detectCMS(resp, url))

	return results
}

func (s *ServerInfoScanner) checkServerHeader(resp *http.Response) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Server Header Exposure",
		Weight:    5.0,
	}

	server := resp.Header.Get("Server")
	if server == "" {
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "Server header is not exposed"})
	} else {
		check.Status = "warning"
		check.Score = 40
		check.Severity = "medium"
		check.Details = toJSON(map[string]string{
			"message": "Server header exposes software information",
			"server":  server,
		})
	}

	return check
}

func (s *ServerInfoScanner) checkPoweredBy(resp *http.Response) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "X-Powered-By Exposure",
		Weight:    5.0,
	}

	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy == "" {
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "X-Powered-By header is not exposed"})
	} else {
		check.Status = "fail"
		check.Score = 20
		check.Severity = "high"
		check.Details = toJSON(map[string]string{
			"message":    "X-Powered-By header exposes technology stack",
			"powered_by": poweredBy,
		})
	}

	return check
}

func (s *ServerInfoScanner) detectCMS(resp *http.Response, url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "CMS Detection",
		Weight:    5.0,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	baseURL := ensureHTTPS(url)
	cms := "Unknown"
	detected := false

	// Check common CMS paths
	cmsChecks := map[string][]string{
		"WordPress": {"/wp-login.php", "/wp-admin/", "/wp-content/"},
		"Joomla":    {"/administrator/", "/components/com_content/"},
		"Drupal":    {"/core/misc/drupal.js", "/sites/default/"},
		"Moodle":    {"/login/index.php", "/theme/boost/"},
	}

	for cmsName, paths := range cmsChecks {
		for _, path := range paths {
			checkURL := baseURL + path
			checkResp, err := client.Get(checkURL)
			if err != nil {
				continue
			}
			checkResp.Body.Close()
			if checkResp.StatusCode == 200 || checkResp.StatusCode == 403 || checkResp.StatusCode == 302 {
				cms = cmsName
				detected = true
				break
			}
		}
		if detected {
			break
		}
	}

	// Check response headers for clues
	generator := resp.Header.Get("X-Generator")
	if generator != "" {
		if strings.Contains(strings.ToLower(generator), "wordpress") {
			cms = "WordPress"
			detected = true
		} else if strings.Contains(strings.ToLower(generator), "drupal") {
			cms = "Drupal"
			detected = true
		}
	}

	if detected {
		check.Status = "info"
		check.Score = 70
		check.Severity = "low"
		check.Details = toJSON(map[string]string{
			"message": fmt.Sprintf("CMS detected: %s", cms),
			"cms":     cms,
		})
	} else {
		check.Status = "info"
		check.Score = 100
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "No common CMS detected",
			"cms":     cms,
		})
	}

	return check
}
