package api

import (
	"github.com/gofiber/fiber/v2"
)

// GetAPIDocs returns JSON API documentation
// GET /api/docs (public)
func GetAPIDocs(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"title":    "VScan-MOHESR API Documentation",
		"version":  "1.0",
		"base_url": "https://sec.erticaz.com/api",
		"authentication": fiber.Map{
			"type":        "API Key",
			"header":      "X-API-Key",
			"format":      "vsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			"description": "Include your API key in the X-API-Key header for all requests",
		},
		"endpoints": []fiber.Map{
			{"method": "GET", "path": "/targets", "description": "List all scan targets"},
			{"method": "POST", "path": "/targets", "description": "Add a scan target", "body": "{ url, name, institution }"},
			{"method": "POST", "path": "/scans/start", "description": "Start a security scan", "body": "{ name, target_ids }"},
			{"method": "GET", "path": "/scans/:id", "description": "Get scan job status and progress"},
			{"method": "GET", "path": "/results/:id", "description": "Get detailed scan results"},
			{"method": "GET", "path": "/results/:id/pdf", "description": "Download PDF report"},
			{"method": "GET", "path": "/leaderboard", "description": "Get ranked results"},
			{"method": "GET", "path": "/targets/:id/history", "description": "Get score history for a target"},
		},
		"rate_limits": fiber.Map{
			"requests_per_minute": 60,
			"scans_per_day":      "Based on your plan",
		},
		"example": fiber.Map{
			"curl_list_targets": "curl -H 'X-API-Key: vsk_your_key_here' https://sec.erticaz.com/api/targets",
			"curl_start_scan":   "curl -X POST -H 'X-API-Key: vsk_your_key_here' -H 'Content-Type: application/json' -d '{\"name\":\"My Scan\"}' https://sec.erticaz.com/api/scans/start",
			"curl_get_results":  "curl -H 'X-API-Key: vsk_your_key_here' https://sec.erticaz.com/api/results/1",
		},
	})
}
