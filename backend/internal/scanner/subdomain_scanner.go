package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vscan-mohesr/internal/models"
)

type SubdomainScanner struct{}

func NewSubdomainScanner() *SubdomainScanner {
	return &SubdomainScanner{}
}

func (s *SubdomainScanner) Name() string     { return "Subdomain Discovery Scanner" }
func (s *SubdomainScanner) Category() string { return "subdomains" }
func (s *SubdomainScanner) Weight() float64  { return 5.0 }

// subdomainPrefixes is the list of common subdomain prefixes to enumerate.
var subdomainPrefixes = []string{
	"www", "mail", "ftp", "admin", "cpanel", "webmail", "remote", "blog",
	"shop", "api", "dev", "staging", "test", "beta", "portal", "vpn",
	"ns1", "ns2", "mx", "smtp", "pop", "imap", "login", "cdn", "media",
	"static", "assets", "app", "dashboard", "db", "sql", "phpmyadmin",
	"mysql", "backup", "old", "new", "demo", "cms", "intranet", "extranet",
	"wiki", "docs", "support", "help", "status", "monitor",
}

// discoveredSubdomain holds the result of a subdomain probe.
type discoveredSubdomain struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
	HasHTTPS  bool     `json:"has_https"`
	CNAME     string   `json:"cname,omitempty"`
}

func (s *SubdomainScanner) Scan(url string) []models.CheckResult {
	host := extractHost(url)
	found := s.enumerateSubdomains(host)

	return []models.CheckResult{
		s.checkSubdomainEnumeration(found),
		s.checkSubdomainSecurity(found),
		s.checkDanglingDNS(host, found),
	}
}

func (s *SubdomainScanner) enumerateSubdomains(baseDomain string) []discoveredSubdomain {
	var (
		mu    sync.Mutex
		found []discoveredSubdomain
		wg    sync.WaitGroup
		sem   = make(chan struct{}, 10) // max 10 concurrent lookups
	)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	for _, prefix := range subdomainPrefixes {
		wg.Add(1)
		sem <- struct{}{}
		go func(prefix string) {
			defer wg.Done()
			defer func() { <-sem }()

			fqdn := prefix + "." + baseDomain
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			ips, err := resolver.LookupHost(ctx, fqdn)
			if err != nil || len(ips) == 0 {
				return
			}

			sub := discoveredSubdomain{
				Subdomain: fqdn,
				IPs:       ips,
			}

			// Check CNAME
			cname, err := resolver.LookupCNAME(ctx, fqdn)
			if err == nil && cname != "" && cname != fqdn+"." {
				sub.CNAME = strings.TrimSuffix(cname, ".")
			}

			// Check HTTPS
			sub.HasHTTPS = s.probeHTTPS(fqdn)

			mu.Lock()
			found = append(found, sub)
			mu.Unlock()
		}(prefix)
	}

	wg.Wait()
	return found
}

func (s *SubdomainScanner) probeHTTPS(host string) bool {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("https://" + host)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func (s *SubdomainScanner) checkSubdomainEnumeration(found []discoveredSubdomain) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Common Subdomain Enumeration",
		Weight:    2.0,
	}

	count := len(found)
	details := map[string]interface{}{
		"subdomains_found": count,
		"subdomains":       found,
	}

	switch {
	case count <= 5:
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = fmt.Sprintf("Small attack surface: %d subdomains discovered", count)
	case count <= 15:
		check.Status = "pass"
		check.Score = 800
		check.Severity = "low"
		details["message"] = fmt.Sprintf("Moderate attack surface: %d subdomains discovered", count)
	case count <= 30:
		check.Status = "warn"
		check.Score = 600
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("Large attack surface: %d subdomains discovered", count)
	default:
		check.Status = "warn"
		check.Score = 400
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("Very large attack surface: %d subdomains discovered", count)
	}

	check.Details = toJSON(details)
	return check
}

func (s *SubdomainScanner) checkSubdomainSecurity(found []discoveredSubdomain) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Subdomain Security Check",
		Weight:    2.0,
	}

	if len(found) == 0 {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "No subdomains to check for HTTPS",
		})
		return check
	}

	// Check up to 10 subdomains
	limit := len(found)
	if limit > 10 {
		limit = 10
	}

	httpsCount := 0
	var withHTTPS, withoutHTTPS []string
	for i := 0; i < limit; i++ {
		if found[i].HasHTTPS {
			httpsCount++
			withHTTPS = append(withHTTPS, found[i].Subdomain)
		} else {
			withoutHTTPS = append(withoutHTTPS, found[i].Subdomain)
		}
	}

	ratio := float64(httpsCount) / float64(limit)
	details := map[string]interface{}{
		"checked":       limit,
		"https_count":   httpsCount,
		"https_ratio":   fmt.Sprintf("%.0f%%", ratio*100),
		"with_https":    withHTTPS,
		"without_https": withoutHTTPS,
	}

	switch {
	case ratio >= 1.0:
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "All checked subdomains support HTTPS"
	case ratio >= 0.8:
		check.Status = "pass"
		check.Score = 800
		check.Severity = "low"
		details["message"] = fmt.Sprintf("%.0f%% of checked subdomains support HTTPS", ratio*100)
	case ratio >= 0.5:
		check.Status = "warn"
		check.Score = 600
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("Only %.0f%% of checked subdomains support HTTPS", ratio*100)
	default:
		check.Status = "fail"
		check.Score = 300
		check.Severity = "high"
		details["message"] = fmt.Sprintf("Only %.0f%% of checked subdomains support HTTPS", ratio*100)
	}

	check.Details = toJSON(details)
	return check
}

// takeoverTargets lists CNAME suffixes that are known to be vulnerable to subdomain takeover.
var takeoverTargets = []string{
	".github.io",
	".herokuapp.com",
	".s3.amazonaws.com",
	".azurewebsites.net",
	".cloudfront.net",
	".shopify.com",
	".ghost.io",
	".pantheon.io",
	".zendesk.com",
	".surge.sh",
	".bitbucket.io",
	".wordpress.com",
	".tumblr.com",
	".flywheel.com",
}

func (s *SubdomainScanner) checkDanglingDNS(baseDomain string, found []discoveredSubdomain) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Dangling DNS / Subdomain Takeover Risk",
		Weight:    1.0,
	}

	if len(found) == 0 {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "No subdomains to check for takeover risk",
		})
		return check
	}

	var potentialTakeovers []map[string]string
	var safeCNAMEs []string

	for _, sub := range found {
		if sub.CNAME == "" {
			continue
		}

		cnameLower := strings.ToLower(sub.CNAME)
		for _, target := range takeoverTargets {
			if strings.HasSuffix(cnameLower, target) {
				// CNAME points to a takeover-vulnerable service; check if it returns 404
				is404 := s.probeReturns404(sub.Subdomain)
				if is404 {
					potentialTakeovers = append(potentialTakeovers, map[string]string{
						"subdomain": sub.Subdomain,
						"cname":     sub.CNAME,
						"status":    "potential_takeover",
					})
				} else {
					safeCNAMEs = append(safeCNAMEs, sub.Subdomain+" -> "+sub.CNAME)
				}
				break
			}
		}
	}

	details := map[string]interface{}{}

	switch {
	case len(potentialTakeovers) > 0:
		check.Status = "fail"
		check.Score = 100
		check.Severity = "critical"
		details["message"] = fmt.Sprintf(
			"%d subdomain(s) potentially vulnerable to takeover",
			len(potentialTakeovers),
		)
		details["potential_takeovers"] = potentialTakeovers
		if len(safeCNAMEs) > 0 {
			details["safe_cnames"] = safeCNAMEs
		}
	case len(safeCNAMEs) > 0:
		check.Status = "pass"
		check.Score = 800
		check.Severity = "low"
		details["message"] = "CNAMEs to external services found but all services respond correctly"
		details["cnames"] = safeCNAMEs
	default:
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "No dangerous CNAME records detected"
	}

	check.Details = toJSON(details)
	return check
}

// probeReturns404 checks whether the given host returns a 404 via HTTP or HTTPS.
func (s *SubdomainScanner) probeReturns404(host string) bool {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Try HTTPS first, then HTTP
	for _, scheme := range []string{"https://", "http://"} {
		resp, err := client.Get(scheme + host)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 404 {
			return true
		}
		return false
	}
	// If neither scheme could be reached, treat as potentially dangling
	return true
}
