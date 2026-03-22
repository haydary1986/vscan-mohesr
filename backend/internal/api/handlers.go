package api

import (
	"time"

	"github.com/gofiber/fiber/v2"

	"vscan-mohesr/internal/config"
	"vscan-mohesr/internal/models"
	"vscan-mohesr/internal/scanner"
)

// --- Scan Targets ---

func GetTargets(c *fiber.Ctx) error {
	var targets []models.ScanTarget
	config.DB.Order("created_at desc").Find(&targets)
	return c.JSON(targets)
}

func CreateTarget(c *fiber.Ctx) error {
	var target models.ScanTarget
	if err := c.BodyParser(&target); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if target.URL == "" {
		return c.Status(400).JSON(fiber.Map{"error": "URL is required"})
	}
	config.DB.Create(&target)
	return c.Status(201).JSON(target)
}

type BulkTargetsRequest struct {
	Targets []models.ScanTarget `json:"targets"`
}

func CreateBulkTargets(c *fiber.Ctx) error {
	var req BulkTargetsRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if len(req.Targets) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "At least one target is required"})
	}

	for i := range req.Targets {
		if req.Targets[i].URL == "" {
			return c.Status(400).JSON(fiber.Map{"error": "All targets must have a URL"})
		}
	}

	config.DB.Create(&req.Targets)
	return c.Status(201).JSON(req.Targets)
}

func DeleteTarget(c *fiber.Ctx) error {
	id := c.Params("id")
	var target models.ScanTarget
	if err := config.DB.First(&target, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Target not found"})
	}
	config.DB.Delete(&target)
	return c.JSON(fiber.Map{"message": "Target deleted"})
}

func UpdateTarget(c *fiber.Ctx) error {
	id := c.Params("id")
	var target models.ScanTarget
	if err := config.DB.First(&target, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Target not found"})
	}

	var update models.ScanTarget
	if err := c.BodyParser(&update); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	config.DB.Model(&target).Updates(update)
	return c.JSON(target)
}

// --- Scan Jobs ---

func GetScanJobs(c *fiber.Ctx) error {
	var jobs []models.ScanJob
	config.DB.Order("created_at desc").Find(&jobs)
	return c.JSON(jobs)
}

func GetScanJob(c *fiber.Ctx) error {
	id := c.Params("id")
	var job models.ScanJob
	if err := config.DB.Preload("Results.ScanTarget").Preload("Results.Checks").First(&job, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan job not found"})
	}
	return c.JSON(job)
}

type StartScanRequest struct {
	Name      string `json:"name"`
	TargetIDs []uint `json:"target_ids"`
}

func StartScan(c *fiber.Ctx) error {
	var req StartScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// If no target IDs provided, scan all targets
	var targets []models.ScanTarget
	if len(req.TargetIDs) > 0 {
		config.DB.Where("id IN ?", req.TargetIDs).Find(&targets)
	} else {
		config.DB.Find(&targets)
	}

	if len(targets) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No targets found to scan"})
	}

	// Create scan job
	job := models.ScanJob{
		Name:   req.Name,
		Status: "pending",
	}
	if job.Name == "" {
		job.Name = "Scan " + time.Now().Format("2006-01-02 15:04")
	}
	config.DB.Create(&job)

	// Create scan results for each target
	for _, target := range targets {
		result := models.ScanResult{
			ScanJobID:    job.ID,
			ScanTargetID: target.ID,
			Status:       "pending",
		}
		config.DB.Create(&result)
	}

	// Run scan in background
	engine := scanner.NewEngine()
	go engine.RunScan(&job)

	return c.Status(201).JSON(job)
}

func DeleteScanJob(c *fiber.Ctx) error {
	id := c.Params("id")
	var job models.ScanJob
	if err := config.DB.First(&job, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan job not found"})
	}

	// Delete associated results and checks
	var results []models.ScanResult
	config.DB.Where("scan_job_id = ?", job.ID).Find(&results)
	for _, r := range results {
		config.DB.Where("scan_result_id = ?", r.ID).Delete(&models.CheckResult{})
	}
	config.DB.Where("scan_job_id = ?", job.ID).Delete(&models.ScanResult{})
	config.DB.Delete(&job)

	return c.JSON(fiber.Map{"message": "Scan job deleted"})
}

// --- Dashboard Stats ---

func GetDashboardStats(c *fiber.Ctx) error {
	var targetCount int64
	config.DB.Model(&models.ScanTarget{}).Count(&targetCount)

	var jobCount int64
	config.DB.Model(&models.ScanJob{}).Count(&jobCount)

	var completedJobs int64
	config.DB.Model(&models.ScanJob{}).Where("status = ?", "completed").Count(&completedJobs)

	var latestResults []models.ScanResult
	config.DB.Order("created_at desc").Limit(20).Preload("ScanTarget").Find(&latestResults)

	// Calculate average score
	var avgScore float64
	config.DB.Model(&models.ScanResult{}).Where("status = ?", "completed").Select("COALESCE(AVG(overall_score), 0)").Scan(&avgScore)

	// Score distribution
	type ScoreBucket struct {
		Range string `json:"range"`
		Count int64  `json:"count"`
	}
	var excellent, good, average, poor, critical int64
	config.DB.Model(&models.ScanResult{}).Where("status = ? AND overall_score >= 80", "completed").Count(&excellent)
	config.DB.Model(&models.ScanResult{}).Where("status = ? AND overall_score >= 60 AND overall_score < 80", "completed").Count(&good)
	config.DB.Model(&models.ScanResult{}).Where("status = ? AND overall_score >= 40 AND overall_score < 60", "completed").Count(&average)
	config.DB.Model(&models.ScanResult{}).Where("status = ? AND overall_score >= 20 AND overall_score < 40", "completed").Count(&poor)
	config.DB.Model(&models.ScanResult{}).Where("status = ? AND overall_score < 20", "completed").Count(&critical)

	return c.JSON(fiber.Map{
		"total_targets":  targetCount,
		"total_scans":    jobCount,
		"completed_scans": completedJobs,
		"average_score":  avgScore,
		"latest_results": latestResults,
		"score_distribution": []fiber.Map{
			{"range": "Excellent (80-100)", "count": excellent},
			{"range": "Good (60-79)", "count": good},
			{"range": "Average (40-59)", "count": average},
			{"range": "Poor (20-39)", "count": poor},
			{"range": "Critical (0-19)", "count": critical},
		},
	})
}

// --- Scan Result Detail ---

func GetScanResult(c *fiber.Ctx) error {
	id := c.Params("id")
	var result models.ScanResult
	if err := config.DB.Preload("ScanTarget").Preload("Checks").First(&result, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan result not found"})
	}

	// Group checks by category
	categories := map[string][]models.CheckResult{}
	for _, check := range result.Checks {
		categories[check.Category] = append(categories[check.Category], check)
	}

	return c.JSON(fiber.Map{
		"result":     result,
		"categories": categories,
	})
}
