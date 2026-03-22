package scanner

import (
	"encoding/json"
	"net/url"
	"strings"
)

func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func extractHost(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return parsed.Hostname()
}

func ensureHTTPS(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	rawURL = strings.TrimRight(rawURL, "/")
	if strings.HasPrefix(rawURL, "https://") {
		return rawURL
	}
	if strings.HasPrefix(rawURL, "http://") {
		return "https://" + rawURL[7:]
	}
	return "https://" + rawURL
}

func ensureHTTP(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	rawURL = strings.TrimRight(rawURL, "/")
	if strings.HasPrefix(rawURL, "http://") {
		return rawURL
	}
	if strings.HasPrefix(rawURL, "https://") {
		return "http://" + rawURL[8:]
	}
	return "http://" + rawURL
}
