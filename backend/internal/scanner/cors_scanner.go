package scanner

import (
	"crypto/tls"
	"net/http"
	"time"

	"vscan-mohesr/internal/models"
)

type CORSScanner struct{}

func NewCORSScanner() *CORSScanner {
	return &CORSScanner{}
}

func (s *CORSScanner) Name() string     { return "CORS Configuration Scanner" }
func (s *CORSScanner) Category() string { return "cors" }
func (s *CORSScanner) Weight() float64  { return 10.0 }

func (s *CORSScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	results = append(results, s.checkCORSWildcard(url))
	results = append(results, s.checkCORSCredentials(url))

	return results
}

func (s *CORSScanner) checkCORSWildcard(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "CORS Wildcard Origin",
		Weight:    5.0,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	targetURL := ensureHTTPS(url)
	req, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Severity = "medium"
		check.Details = toJSON(map[string]string{"error": err.Error()})
		return check
	}

	req.Header.Set("Origin", "https://evil-attacker.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := client.Do(req)
	if err != nil {
		check.Status = "info"
		check.Score = 80
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "Could not perform CORS check", "error": err.Error()})
		return check
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")

	details := map[string]interface{}{
		"access_control_allow_origin": acao,
	}

	if acao == "*" {
		check.Status = "warning"
		check.Score = 40
		check.Severity = "medium"
		details["message"] = "CORS allows all origins (*) - may expose data to any domain"
	} else if acao == "https://evil-attacker.com" {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		details["message"] = "CORS reflects arbitrary origins - highly insecure"
	} else if acao == "" {
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		details["message"] = "No CORS header exposed to foreign origins"
	} else {
		check.Status = "pass"
		check.Score = 90
		check.Severity = "info"
		details["message"] = "CORS is configured with specific allowed origin"
	}

	check.Details = toJSON(details)
	return check
}

func (s *CORSScanner) checkCORSCredentials(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "CORS Credentials",
		Weight:    5.0,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	targetURL := ensureHTTPS(url)
	req, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Severity = "medium"
		check.Details = toJSON(map[string]string{"error": err.Error()})
		return check
	}

	req.Header.Set("Origin", "https://evil-attacker.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := client.Do(req)
	if err != nil {
		check.Status = "info"
		check.Score = 80
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "Could not perform CORS credentials check"})
		return check
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	details := map[string]interface{}{
		"allow_origin":      acao,
		"allow_credentials": acac,
	}

	if acac == "true" && (acao == "*" || acao == "https://evil-attacker.com") {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		details["message"] = "CORS allows credentials with wildcard/reflected origin - critical vulnerability"
	} else if acac == "true" {
		check.Status = "warning"
		check.Score = 60
		check.Severity = "medium"
		details["message"] = "CORS allows credentials - ensure origins are properly restricted"
	} else {
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		details["message"] = "CORS credentials configuration is secure"
	}

	check.Details = toJSON(details)
	return check
}
