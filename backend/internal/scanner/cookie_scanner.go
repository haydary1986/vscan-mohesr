package scanner

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"vscan-mohesr/internal/models"
)

type CookieScanner struct{}

func NewCookieScanner() *CookieScanner {
	return &CookieScanner{}
}

func (s *CookieScanner) Name() string     { return "Cookie Security Scanner" }
func (s *CookieScanner) Category() string { return "cookies" }
func (s *CookieScanner) Weight() float64  { return 10.0 }

func (s *CookieScanner) Scan(url string) []models.CheckResult {
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
				CheckName: "Cookie Security",
				Status:    "error",
				Score:     0,
				Weight:    s.Weight(),
				Severity:  "high",
				Details:   toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()}),
			}}
		}
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()

	if len(cookies) == 0 {
		return []models.CheckResult{{
			Category:  s.Category(),
			CheckName: "Cookie Security",
			Status:    "info",
			Score:     100,
			Weight:    s.Weight(),
			Severity:  "info",
			Details:   toJSON(map[string]string{"message": "No cookies set on initial response"}),
		}}
	}

	var results []models.CheckResult
	weightPerCookie := s.Weight() / float64(len(cookies))

	for _, cookie := range cookies {
		score := 100.0
		issues := []string{}

		if !cookie.Secure {
			score -= 34
			issues = append(issues, "Missing Secure flag")
		}
		if !cookie.HttpOnly {
			score -= 33
			issues = append(issues, "Missing HttpOnly flag")
		}
		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == 0 {
			score -= 33
			issues = append(issues, "Missing SameSite attribute")
		}

		if score < 0 {
			score = 0
		}

		status := "pass"
		severity := "info"
		if score < 50 {
			status = "fail"
			severity = "high"
		} else if score < 100 {
			status = "warning"
			severity = "medium"
		}

		details := map[string]interface{}{
			"cookie_name": cookie.Name,
			"secure":      cookie.Secure,
			"http_only":   cookie.HttpOnly,
			"same_site":   fmt.Sprintf("%v", cookie.SameSite),
			"issues":      issues,
		}

		results = append(results, models.CheckResult{
			Category:  s.Category(),
			CheckName: fmt.Sprintf("Cookie: %s", cookie.Name),
			Status:    status,
			Score:     score,
			Weight:    weightPerCookie,
			Severity:  severity,
			Details:   toJSON(details),
		})
	}

	return results
}
