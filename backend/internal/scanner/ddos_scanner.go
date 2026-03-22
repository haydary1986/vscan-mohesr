package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type DDoSScanner struct{}

func NewDDoSScanner() *DDoSScanner {
	return &DDoSScanner{}
}

func (s *DDoSScanner) Name() string     { return "DDoS Protection Scanner" }
func (s *DDoSScanner) Category() string { return "ddos" }
func (s *DDoSScanner) Weight() float64  { return 10.0 }

func (s *DDoSScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	targetURL := ensureHTTPS(url)
	resp, err := client.Get(targetURL)
	if err != nil {
		targetURL = ensureHTTP(url)
		resp, err = client.Get(targetURL)
		if err != nil {
			return []models.CheckResult{{
				Category:  s.Category(),
				CheckName: "DDoS Protection",
				Status:    "error",
				Score:     0,
				Weight:    s.Weight(),
				Severity:  "high",
				Details:   toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()}),
			}}
		}
	}
	defer resp.Body.Close()

	// Check for CDN/DDoS protection services
	results = append(results, s.checkCDNProtection(resp))

	// Check rate limiting headers
	results = append(results, s.checkRateLimiting(resp))

	// Check WAF (Web Application Firewall) indicators
	results = append(results, s.checkWAF(resp, targetURL, client))

	return results
}

func (s *DDoSScanner) checkCDNProtection(resp *http.Response) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "CDN/DDoS Protection Service",
		Weight:    4.0,
	}

	headers := resp.Header
	detected := []string{}
	provider := "None detected"

	// Cloudflare
	if headers.Get("CF-RAY") != "" || headers.Get("cf-cache-status") != "" {
		detected = append(detected, "Cloudflare")
		provider = "Cloudflare"
	}

	// AWS CloudFront
	if headers.Get("X-Amz-Cf-Id") != "" || headers.Get("X-Amz-Cf-Pop") != "" {
		detected = append(detected, "AWS CloudFront")
		provider = "AWS CloudFront"
	}

	// Akamai
	if headers.Get("X-Akamai-Transformed") != "" || strings.Contains(headers.Get("Server"), "AkamaiGHost") {
		detected = append(detected, "Akamai")
		provider = "Akamai"
	}

	// Fastly
	if headers.Get("X-Fastly-Request-ID") != "" || headers.Get("Fastly-Debug-Digest") != "" {
		detected = append(detected, "Fastly")
		provider = "Fastly"
	}

	// Sucuri
	if headers.Get("X-Sucuri-ID") != "" || strings.Contains(headers.Get("Server"), "Sucuri") {
		detected = append(detected, "Sucuri")
		provider = "Sucuri"
	}

	// Incapsula / Imperva
	if headers.Get("X-CDN") == "Imperva" || headers.Get("X-Iinfo") != "" {
		detected = append(detected, "Imperva/Incapsula")
		provider = "Imperva/Incapsula"
	}

	// Azure Front Door
	if headers.Get("X-Azure-Ref") != "" {
		detected = append(detected, "Azure Front Door")
		provider = "Azure Front Door"
	}

	// Google Cloud CDN
	if headers.Get("X-Goog-Component") != "" {
		detected = append(detected, "Google Cloud CDN")
		provider = "Google Cloud CDN"
	}

	// Check server header for generic CDN indicators
	server := strings.ToLower(headers.Get("Server"))
	if strings.Contains(server, "cloudflare") || strings.Contains(server, "cdn") {
		if len(detected) == 0 {
			detected = append(detected, "Generic CDN")
			provider = "Unknown CDN"
		}
	}

	details := map[string]interface{}{
		"provider":          provider,
		"services_detected": detected,
	}

	if len(detected) > 0 {
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		details["message"] = fmt.Sprintf("DDoS protection detected: %s", strings.Join(detected, ", "))
	} else {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "high"
		details["message"] = "No CDN or DDoS protection service detected"
	}

	check.Details = toJSON(details)
	return check
}

func (s *DDoSScanner) checkRateLimiting(resp *http.Response) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Rate Limiting",
		Weight:    3.0,
	}

	headers := resp.Header
	indicators := []string{}

	// Standard rate limit headers
	rateLimitHeaders := []string{
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"X-RateLimit-Reset",
		"RateLimit-Limit",
		"RateLimit-Remaining",
		"RateLimit-Reset",
		"Retry-After",
		"X-Rate-Limit",
	}

	for _, h := range rateLimitHeaders {
		if val := headers.Get(h); val != "" {
			indicators = append(indicators, fmt.Sprintf("%s: %s", h, val))
		}
	}

	details := map[string]interface{}{
		"indicators": indicators,
	}

	if len(indicators) > 0 {
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		details["message"] = "Rate limiting headers detected"
	} else {
		check.Status = "warning"
		check.Score = 30
		check.Severity = "medium"
		details["message"] = "No rate limiting headers detected (may still be configured server-side)"
	}

	check.Details = toJSON(details)
	return check
}

func (s *DDoSScanner) checkWAF(resp *http.Response, baseURL string, client *http.Client) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Web Application Firewall (WAF)",
		Weight:    3.0,
	}

	wafIndicators := []string{}

	// Check response headers for WAF indicators
	headers := resp.Header

	if headers.Get("X-ModSecurity") != "" || headers.Get("X-Mod-Security") != "" {
		wafIndicators = append(wafIndicators, "ModSecurity")
	}

	if headers.Get("X-Sucuri-ID") != "" {
		wafIndicators = append(wafIndicators, "Sucuri WAF")
	}

	if headers.Get("X-CDN") == "Imperva" || headers.Get("X-Iinfo") != "" {
		wafIndicators = append(wafIndicators, "Imperva WAF")
	}

	// Cloudflare WAF
	if headers.Get("CF-RAY") != "" {
		wafIndicators = append(wafIndicators, "Cloudflare WAF")
	}

	// Try a simple WAF detection by sending a suspicious parameter
	testURL := baseURL + "/?test=<script>alert(1)</script>"
	testResp, err := client.Get(testURL)
	if err == nil {
		body, _ := io.ReadAll(io.LimitReader(testResp.Body, 2048))
		testResp.Body.Close()

		bodyStr := strings.ToLower(string(body))

		if testResp.StatusCode == 403 || testResp.StatusCode == 406 || testResp.StatusCode == 429 {
			wafIndicators = append(wafIndicators, fmt.Sprintf("Blocked suspicious request (HTTP %d)", testResp.StatusCode))
		}

		// Check if the script tag was reflected (indicates no WAF)
		if strings.Contains(bodyStr, "<script>alert(1)</script>") {
			wafIndicators = append(wafIndicators, "WARNING: XSS payload reflected without filtering")
		}

		// Check for common WAF block pages
		if strings.Contains(bodyStr, "access denied") || strings.Contains(bodyStr, "blocked") ||
			strings.Contains(bodyStr, "firewall") || strings.Contains(bodyStr, "waf") {
			wafIndicators = append(wafIndicators, "WAF block page detected")
		}
	}

	details := map[string]interface{}{
		"indicators": wafIndicators,
	}

	hasPositiveIndicator := false
	for _, ind := range wafIndicators {
		if !strings.Contains(ind, "WARNING") {
			hasPositiveIndicator = true
			break
		}
	}

	if hasPositiveIndicator {
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		details["message"] = "Web Application Firewall detected"
	} else {
		check.Status = "fail"
		check.Score = 10
		check.Severity = "high"
		details["message"] = "No Web Application Firewall detected"
	}

	check.Details = toJSON(details)
	return check
}
