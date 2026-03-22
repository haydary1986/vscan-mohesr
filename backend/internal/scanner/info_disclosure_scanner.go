package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type InfoDisclosureScanner struct{}

func NewInfoDisclosureScanner() *InfoDisclosureScanner {
	return &InfoDisclosureScanner{}
}

func (s *InfoDisclosureScanner) Name() string     { return "Information Disclosure Scanner" }
func (s *InfoDisclosureScanner) Category() string { return "info_disclosure" }
func (s *InfoDisclosureScanner) Weight() float64  { return 7.0 }

func (s *InfoDisclosureScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	client := &http.Client{
		Timeout: 10 * time.Second,
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
			return nil
		}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	bodyStr := string(body)

	// Check error page information disclosure
	results = append(results, s.checkErrorPages(client, targetURL))

	// Check for comments with sensitive info
	results = append(results, s.checkHTMLComments(bodyStr))

	// Check for version disclosure in HTML
	results = append(results, s.checkVersionDisclosure(bodyStr, resp))

	return results
}

func (s *InfoDisclosureScanner) checkErrorPages(client *http.Client, baseURL string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Error Page Information Disclosure",
		Weight:    3.0,
	}

	errorURL := baseURL + "/this-page-does-not-exist-test-404"
	resp, err := client.Get(errorURL)
	if err != nil {
		check.Status = "info"
		check.Score = 80
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "Cannot check error pages"})
		return check
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := strings.ToLower(string(body))

	disclosures := []string{}

	// Check for stack traces
	if strings.Contains(bodyStr, "stack trace") || strings.Contains(bodyStr, "stacktrace") {
		disclosures = append(disclosures, "Stack trace exposed")
	}
	// Check for server version info
	if strings.Contains(bodyStr, "apache/") || strings.Contains(bodyStr, "nginx/") || strings.Contains(bodyStr, "iis/") {
		disclosures = append(disclosures, "Server version in error page")
	}
	// Check for framework info
	if strings.Contains(bodyStr, "laravel") || strings.Contains(bodyStr, "django") || strings.Contains(bodyStr, "asp.net") {
		disclosures = append(disclosures, "Framework name in error page")
	}
	// Check for path disclosure
	pathPattern := regexp.MustCompile(`(?i)(\/var\/www|\/home\/|c:\\|\/usr\/|\/opt\/)`)
	if pathPattern.MatchString(bodyStr) {
		disclosures = append(disclosures, "Server file paths exposed")
	}
	// Check for SQL errors
	if strings.Contains(bodyStr, "sql") && (strings.Contains(bodyStr, "error") || strings.Contains(bodyStr, "syntax")) {
		disclosures = append(disclosures, "SQL error messages exposed")
	}
	// Debug mode indicators
	if strings.Contains(bodyStr, "debug") && (strings.Contains(bodyStr, "true") || strings.Contains(bodyStr, "mode")) {
		disclosures = append(disclosures, "Debug mode may be enabled")
	}

	if len(disclosures) > 0 {
		check.Status = "fail"
		check.Score = 10
		check.Severity = "high"
		check.Details = toJSON(map[string]interface{}{
			"message":     "Error page reveals sensitive information",
			"disclosures": disclosures,
		})
	} else {
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "Error pages do not reveal sensitive information",
		})
	}

	return check
}

func (s *InfoDisclosureScanner) checkHTMLComments(body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Sensitive HTML Comments",
		Weight:    2.0,
	}

	commentPattern := regexp.MustCompile(`<!--[\s\S]*?-->`)
	comments := commentPattern.FindAllString(body, -1)

	sensitiveKeywords := []string{"password", "todo", "fixme", "hack", "bug", "secret", "api_key", "token", "admin", "debug", "database", "db_"}
	sensitiveComments := []string{}

	for _, comment := range comments {
		lower := strings.ToLower(comment)
		for _, keyword := range sensitiveKeywords {
			if strings.Contains(lower, keyword) {
				if len(comment) > 100 {
					comment = comment[:100] + "..."
				}
				sensitiveComments = append(sensitiveComments, comment)
				break
			}
		}
	}

	if len(sensitiveComments) > 0 {
		check.Status = "warning"
		check.Score = 40
		check.Severity = "medium"
		check.Details = toJSON(map[string]interface{}{
			"message":  "HTML comments contain potentially sensitive information",
			"count":    len(sensitiveComments),
			"examples": sensitiveComments[:min(len(sensitiveComments), 3)],
		})
	} else {
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message":        "No sensitive information found in HTML comments",
			"total_comments": fmt.Sprintf("%d", len(comments)),
		})
	}

	return check
}

func (s *InfoDisclosureScanner) checkVersionDisclosure(body string, resp *http.Response) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Technology Version Disclosure",
		Weight:    2.0,
	}

	disclosures := []string{}

	// Check meta generator tag
	generatorPattern := regexp.MustCompile(`(?i)<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']`)
	if matches := generatorPattern.FindStringSubmatch(body); len(matches) > 1 {
		disclosures = append(disclosures, "Generator: "+matches[1])
	}

	// Check for WordPress version
	wpPattern := regexp.MustCompile(`(?i)wp-content|wp-includes|wordpress\s*([\d.]+)?`)
	if wpPattern.MatchString(body) {
		disclosures = append(disclosures, "WordPress detected in page source")
	}

	// Check for jQuery version
	jqPattern := regexp.MustCompile(`(?i)jquery[.-]?([\d.]+)`)
	if matches := jqPattern.FindStringSubmatch(body); len(matches) > 1 {
		disclosures = append(disclosures, "jQuery version: "+matches[1])
	}

	// Check X-Powered-By header
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		disclosures = append(disclosures, "X-Powered-By: "+poweredBy)
	}

	// Check X-AspNet-Version
	if aspNet := resp.Header.Get("X-AspNet-Version"); aspNet != "" {
		disclosures = append(disclosures, "X-AspNet-Version: "+aspNet)
	}

	// Check X-AspNetMvc-Version
	if aspMvc := resp.Header.Get("X-AspNetMvc-Version"); aspMvc != "" {
		disclosures = append(disclosures, "X-AspNetMvc-Version: "+aspMvc)
	}

	if len(disclosures) > 0 {
		check.Status = "warning"
		check.Score = 40
		check.Severity = "medium"
		check.Details = toJSON(map[string]interface{}{
			"message":     "Technology versions are exposed",
			"disclosures": disclosures,
		})
	} else {
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "No significant technology version disclosures found",
		})
	}

	return check
}
