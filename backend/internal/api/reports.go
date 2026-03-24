package api

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"

	"vscan-mohesr/internal/config"
	"vscan-mohesr/internal/models"
	"vscan-mohesr/internal/scanner"
	"vscan-mohesr/internal/services"
)

func GeneratePDFReport(c *fiber.Ctx) error {
	id := c.Params("id")

	var result models.ScanResult
	if err := config.DB.Preload("ScanTarget").Preload("Checks").First(&result, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan result not found"})
	}

	pdfBytes, err := services.GenerateScanReport(&result, result.Checks)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate PDF report"})
	}

	// Use website name or URL as filename
	name := result.ScanTarget.Name
	if name == "" {
		name = result.ScanTarget.URL
	}
	// Sanitize filename - replace spaces and special chars
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ReplaceAll(name, "/", "-")
	safeName := url.PathEscape(name)

	filename := fmt.Sprintf("VScan-Report-%s.pdf", safeName)

	c.Set("Content-Type", "application/pdf")
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"; filename*=UTF-8''%s", filename, safeName+".pdf"))

	return c.Send(pdfBytes)
}

// ExportSARIF generates a SARIF v2.1.0 JSON report for a scan result.
func ExportSARIF(c *fiber.Ctx) error {
	id := c.Params("id")

	var result models.ScanResult
	if err := config.DB.Preload("ScanTarget").First(&result, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Result not found"})
	}

	var checks []models.CheckResult
	config.DB.Where("scan_result_id = ?", result.ID).Find(&checks)

	data, err := services.GenerateSARIF(&result, checks)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate SARIF"})
	}

	// Sanitize URL for filename
	name := result.ScanTarget.URL
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, ":", "-")
	safeName := url.PathEscape(name)
	filename := fmt.Sprintf("vscan-%s.sarif", safeName)

	c.Set("Content-Type", "application/sarif+json")
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	return c.Send(data)
}

// GetUpgradeSuggestions returns smart upgrade suggestions for libraries found in a scan.
func GetUpgradeSuggestions(c *fiber.Ctx) error {
	resultID := c.Params("id")

	var checks []models.CheckResult
	config.DB.Where("scan_result_id = ?", resultID).Find(&checks)

	suggestions := scanner.GetUpgradeSuggestions(checks)
	return c.JSON(suggestions)
}
