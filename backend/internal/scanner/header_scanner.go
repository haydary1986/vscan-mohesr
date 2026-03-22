package scanner

import (
	"crypto/tls"
	"net/http"
	"time"

	"vscan-mohesr/internal/models"
)

type HeaderScanner struct{}

func NewHeaderScanner() *HeaderScanner {
	return &HeaderScanner{}
}

func (s *HeaderScanner) Name() string     { return "Security Headers Scanner" }
func (s *HeaderScanner) Category() string { return "headers" }
func (s *HeaderScanner) Weight() float64  { return 20.0 }

func (s *HeaderScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(ensureHTTPS(url))
	if err != nil {
		// Try HTTP if HTTPS fails
		resp, err = client.Get(ensureHTTP(url))
		if err != nil {
			return []models.CheckResult{{
				Category:  s.Category(),
				CheckName: "Security Headers",
				Status:    "error",
				Score:     0,
				Weight:    s.Weight(),
				Severity:  "critical",
				Details:   toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()}),
			}}
		}
	}
	defer resp.Body.Close()

	headers := resp.Header

	// Check each important security header
	results = append(results, s.checkHeader(headers, "Strict-Transport-Security", "HSTS", "critical",
		"Enforces HTTPS connections, preventing downgrade attacks"))

	results = append(results, s.checkHeader(headers, "Content-Security-Policy", "Content Security Policy", "high",
		"Prevents XSS and data injection attacks"))

	results = append(results, s.checkHeader(headers, "X-Frame-Options", "X-Frame-Options", "high",
		"Prevents clickjacking attacks"))

	results = append(results, s.checkHeader(headers, "X-Content-Type-Options", "X-Content-Type-Options", "medium",
		"Prevents MIME type sniffing"))

	results = append(results, s.checkHeader(headers, "X-XSS-Protection", "X-XSS-Protection", "medium",
		"Legacy XSS protection (modern browsers use CSP instead)"))

	results = append(results, s.checkHeader(headers, "Referrer-Policy", "Referrer-Policy", "medium",
		"Controls how much referrer information is shared"))

	results = append(results, s.checkHeader(headers, "Permissions-Policy", "Permissions-Policy", "medium",
		"Controls which browser features can be used"))

	return results
}

func (s *HeaderScanner) checkHeader(headers http.Header, headerName, displayName, severity, description string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: displayName,
		Weight:    s.Weight() / 7.0, // distribute weight across 7 headers
	}

	value := headers.Get(headerName)
	if value != "" {
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"header":      headerName,
			"value":       value,
			"description": description,
			"message":     displayName + " header is present",
		})
	} else {
		check.Status = "fail"
		check.Score = 0
		check.Severity = severity
		check.Details = toJSON(map[string]string{
			"header":      headerName,
			"description": description,
			"message":     displayName + " header is missing",
		})
	}

	return check
}
