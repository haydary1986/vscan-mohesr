package scanner

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type HTTPMethodsScanner struct{}

func NewHTTPMethodsScanner() *HTTPMethodsScanner {
	return &HTTPMethodsScanner{}
}

func (s *HTTPMethodsScanner) Name() string     { return "HTTP Methods Scanner" }
func (s *HTTPMethodsScanner) Category() string { return "http_methods" }
func (s *HTTPMethodsScanner) Weight() float64  { return 8.0 }

func (s *HTTPMethodsScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	targetURL := ensureHTTPS(url)

	// Check dangerous HTTP methods
	dangerousMethods := []string{"TRACE", "DELETE", "PUT", "PATCH"}
	allowedDangerous := []string{}

	for _, method := range dangerousMethods {
		req, err := http.NewRequest(method, targetURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 405 && resp.StatusCode != 501 && resp.StatusCode != 403 {
			allowedDangerous = append(allowedDangerous, fmt.Sprintf("%s (HTTP %d)", method, resp.StatusCode))
		}
	}

	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Dangerous HTTP Methods",
		Weight:    4.0,
	}

	if len(allowedDangerous) > 0 {
		check.Status = "fail"
		check.Score = 20
		check.Severity = "high"
		check.Details = toJSON(map[string]interface{}{
			"message":          "Dangerous HTTP methods are enabled",
			"allowed_methods":  allowedDangerous,
		})
	} else {
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "Dangerous HTTP methods (TRACE, DELETE, PUT, PATCH) are properly disabled",
		})
	}
	results = append(results, check)

	// Check OPTIONS response
	optCheck := models.CheckResult{
		Category:  s.Category(),
		CheckName: "OPTIONS Method Disclosure",
		Weight:    4.0,
	}

	req, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			allow := resp.Header.Get("Allow")
			if allow != "" && (strings.Contains(allow, "TRACE") || strings.Contains(allow, "DELETE")) {
				optCheck.Status = "warning"
				optCheck.Score = 40
				optCheck.Severity = "medium"
				optCheck.Details = toJSON(map[string]string{
					"message":         "OPTIONS response discloses available methods including dangerous ones",
					"allowed_methods": allow,
				})
			} else {
				optCheck.Status = "pass"
				optCheck.Score = 100
				optCheck.Severity = "info"
				optCheck.Details = toJSON(map[string]string{
					"message": "OPTIONS method properly configured",
					"allow":   allow,
				})
			}
		} else {
			optCheck.Status = "pass"
			optCheck.Score = 100
			optCheck.Severity = "info"
			optCheck.Details = toJSON(map[string]string{"message": "OPTIONS method not accessible"})
		}
	}
	results = append(results, optCheck)

	return results
}
