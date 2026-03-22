package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	"vscan-mohesr/internal/models"
)

type PerformanceScanner struct{}

func NewPerformanceScanner() *PerformanceScanner {
	return &PerformanceScanner{}
}

func (s *PerformanceScanner) Name() string     { return "Performance Scanner" }
func (s *PerformanceScanner) Category() string { return "performance" }
func (s *PerformanceScanner) Weight() float64  { return 15.0 }

func (s *PerformanceScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	results = append(results, s.checkResponseTime(url))
	results = append(results, s.checkTTFB(url))
	results = append(results, s.checkTLSHandshake(url))

	return results
}

func (s *PerformanceScanner) checkResponseTime(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Response Time",
		Weight:    5.0,
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	targetURL := ensureHTTPS(url)
	start := time.Now()
	resp, err := client.Get(targetURL)
	elapsed := time.Since(start)

	if err != nil {
		// Try HTTP
		targetURL = ensureHTTP(url)
		start = time.Now()
		resp, err = client.Get(targetURL)
		elapsed = time.Since(start)
		if err != nil {
			check.Status = "error"
			check.Score = 0
			check.Severity = "critical"
			check.Details = toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()})
			return check
		}
	}
	defer resp.Body.Close()

	ms := elapsed.Milliseconds()

	details := map[string]interface{}{
		"response_time_ms": ms,
		"status_code":      resp.StatusCode,
	}

	switch {
	case ms < 500:
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		details["message"] = fmt.Sprintf("Excellent response time: %dms", ms)
		details["grade"] = "A"
	case ms < 1000:
		check.Status = "pass"
		check.Score = 85
		check.Severity = "info"
		details["message"] = fmt.Sprintf("Good response time: %dms", ms)
		details["grade"] = "B"
	case ms < 2000:
		check.Status = "warning"
		check.Score = 65
		check.Severity = "low"
		details["message"] = fmt.Sprintf("Average response time: %dms", ms)
		details["grade"] = "C"
	case ms < 5000:
		check.Status = "warning"
		check.Score = 40
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("Slow response time: %dms", ms)
		details["grade"] = "D"
	default:
		check.Status = "fail"
		check.Score = 15
		check.Severity = "high"
		details["message"] = fmt.Sprintf("Very slow response time: %dms", ms)
		details["grade"] = "F"
	}

	check.Details = toJSON(details)
	return check
}

func (s *PerformanceScanner) checkTTFB(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Time to First Byte (TTFB)",
		Weight:    5.0,
	}

	var ttfb time.Duration
	var dnsTime time.Duration
	var connectTime time.Duration

	var dnsStart, connectStart, gotFirstByte time.Time

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			dnsTime = time.Since(dnsStart)
		},
		ConnectStart: func(_, _ string) {
			connectStart = time.Now()
		},
		ConnectDone: func(_, _ string, _ error) {
			connectTime = time.Since(connectStart)
		},
		GotFirstResponseByte: func() {
			gotFirstByte = time.Now()
		},
	}

	targetURL := ensureHTTPS(url)
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Severity = "high"
		check.Details = toJSON(map[string]string{"error": err.Error()})
		return check
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Severity = "high"
		check.Details = toJSON(map[string]string{"error": "Cannot measure TTFB: " + err.Error()})
		return check
	}
	defer resp.Body.Close()

	if !gotFirstByte.IsZero() {
		ttfb = gotFirstByte.Sub(start)
	}

	ms := ttfb.Milliseconds()

	details := map[string]interface{}{
		"ttfb_ms":        ms,
		"dns_time_ms":    dnsTime.Milliseconds(),
		"connect_time_ms": connectTime.Milliseconds(),
	}

	switch {
	case ms < 200:
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		details["message"] = fmt.Sprintf("Excellent TTFB: %dms", ms)
		details["grade"] = "A"
	case ms < 500:
		check.Status = "pass"
		check.Score = 85
		check.Severity = "info"
		details["message"] = fmt.Sprintf("Good TTFB: %dms", ms)
		details["grade"] = "B"
	case ms < 1000:
		check.Status = "warning"
		check.Score = 60
		check.Severity = "low"
		details["message"] = fmt.Sprintf("Average TTFB: %dms", ms)
		details["grade"] = "C"
	case ms < 2000:
		check.Status = "warning"
		check.Score = 35
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("Slow TTFB: %dms", ms)
		details["grade"] = "D"
	default:
		check.Status = "fail"
		check.Score = 10
		check.Severity = "high"
		details["message"] = fmt.Sprintf("Very slow TTFB: %dms", ms)
		details["grade"] = "F"
	}

	check.Details = toJSON(details)
	return check
}

func (s *PerformanceScanner) checkTLSHandshake(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "TLS Handshake Time",
		Weight:    5.0,
	}

	host := extractHost(url)

	start := time.Now()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		host+":443",
		&tls.Config{InsecureSkipVerify: true},
	)
	elapsed := time.Since(start)

	if err != nil {
		check.Status = "warning"
		check.Score = 50
		check.Severity = "medium"
		check.Details = toJSON(map[string]string{
			"error":   "Cannot measure TLS handshake: " + err.Error(),
			"message": "TLS connection failed - HTTPS may not be available",
		})
		return check
	}
	defer conn.Close()

	ms := elapsed.Milliseconds()

	details := map[string]interface{}{
		"tls_handshake_ms": ms,
	}

	switch {
	case ms < 100:
		check.Status = "pass"
		check.Score = 100
		check.Severity = "info"
		details["message"] = fmt.Sprintf("Excellent TLS handshake: %dms", ms)
		details["grade"] = "A"
	case ms < 300:
		check.Status = "pass"
		check.Score = 85
		check.Severity = "info"
		details["message"] = fmt.Sprintf("Good TLS handshake: %dms", ms)
		details["grade"] = "B"
	case ms < 700:
		check.Status = "warning"
		check.Score = 60
		check.Severity = "low"
		details["message"] = fmt.Sprintf("Average TLS handshake: %dms", ms)
		details["grade"] = "C"
	case ms < 1500:
		check.Status = "warning"
		check.Score = 35
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("Slow TLS handshake: %dms", ms)
		details["grade"] = "D"
	default:
		check.Status = "fail"
		check.Score = 10
		check.Severity = "high"
		details["message"] = fmt.Sprintf("Very slow TLS handshake: %dms", ms)
		details["grade"] = "F"
	}

	check.Details = toJSON(details)
	return check
}
