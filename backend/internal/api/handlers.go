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
	ScopedDB(c).Order("created_at desc").Find(&targets)
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
	target.OrganizationID = GetUserOrgID(c)
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

	orgID := GetUserOrgID(c)
	for i := range req.Targets {
		if req.Targets[i].URL == "" {
			return c.Status(400).JSON(fiber.Map{"error": "All targets must have a URL"})
		}
		req.Targets[i].OrganizationID = orgID
	}

	config.DB.Create(&req.Targets)
	return c.Status(201).JSON(req.Targets)
}

func DeleteTarget(c *fiber.Ctx) error {
	id := c.Params("id")
	var target models.ScanTarget
	if err := ScopedDB(c).First(&target, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Target not found"})
	}
	config.DB.Delete(&target)
	return c.JSON(fiber.Map{"message": "Target deleted"})
}

func UpdateTarget(c *fiber.Ctx) error {
	id := c.Params("id")
	var target models.ScanTarget
	if err := ScopedDB(c).First(&target, id).Error; err != nil {
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
	ScopedDB(c).Order("created_at desc").Find(&jobs)

	// Add progress info to each job
	var result []fiber.Map
	for _, job := range jobs {
		var total, completed, failed int64
		config.DB.Model(&models.ScanResult{}).Where("scan_job_id = ?", job.ID).Count(&total)
		config.DB.Model(&models.ScanResult{}).Where("scan_job_id = ? AND status = ?", job.ID, "completed").Count(&completed)
		config.DB.Model(&models.ScanResult{}).Where("scan_job_id = ? AND status = ?", job.ID, "failed").Count(&failed)

		progress := 0.0
		if total > 0 {
			progress = float64(completed+failed) / float64(total) * 100
		}

		result = append(result, fiber.Map{
			"ID":         job.ID,
			"CreatedAt":  job.CreatedAt,
			"name":       job.Name,
			"status":     job.Status,
			"started_at": job.StartedAt,
			"ended_at":   job.EndedAt,
			"progress": fiber.Map{
				"total":     total,
				"completed": completed,
				"failed":    failed,
				"percent":   progress,
			},
		})
	}

	return c.JSON(result)
}

func GetScanJob(c *fiber.Ctx) error {
	id := c.Params("id")
	var job models.ScanJob
	if err := config.DB.Preload("Results.ScanTarget").Preload("Results.Checks").First(&job, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan job not found"})
	}

	// Calculate progress
	total := len(job.Results)
	completed := 0
	running := 0
	pending := 0
	failed := 0
	for _, r := range job.Results {
		switch r.Status {
		case "completed":
			completed++
		case "running":
			running++
		case "failed":
			failed++
		default:
			pending++
		}
	}

	progress := 0.0
	if total > 0 {
		progress = float64(completed+failed) / float64(total) * 100
	}

	return c.JSON(fiber.Map{
		"ID":         job.ID,
		"CreatedAt":  job.CreatedAt,
		"UpdatedAt":  job.UpdatedAt,
		"name":       job.Name,
		"status":     job.Status,
		"started_at": job.StartedAt,
		"ended_at":   job.EndedAt,
		"user_id":    job.UserID,
		"results":    job.Results,
		"progress": fiber.Map{
			"total":     total,
			"completed": completed,
			"running":   running,
			"pending":   pending,
			"failed":    failed,
			"percent":   progress,
		},
	})
}

type StartScanRequest struct {
	Name      string `json:"name"`
	TargetIDs []uint `json:"target_ids"`
	Policy    string `json:"policy"` // light, standard, deep — overrides plan-based engine
}

func StartScan(c *fiber.Ctx) error {
	var req StartScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	userID := c.Locals("user_id").(uint)

	// Get user's organization via OrgMembership
	var membership models.OrgMembership
	var org models.Organization
	plan := "enterprise" // default for users without org (e.g. legacy admin)

	if err := config.DB.Where("user_id = ?", userID).First(&membership).Error; err == nil {
		if err := config.DB.First(&org, membership.OrganizationID).Error; err == nil {
			plan = org.Plan

			// Check target count against org.MaxTargets
			var targetCount int64
			config.DB.Model(&models.ScanTarget{}).Where("organization_id = ?", org.ID).Count(&targetCount)
			if int(targetCount) >= org.MaxTargets {
				return c.Status(403).JSON(fiber.Map{
					"error": "Target limit reached for your plan. Please upgrade.",
					"limit": org.MaxTargets,
					"current": targetCount,
					"plan":  org.Plan,
				})
			}
		}
	}

	// If no target IDs provided, scan all targets (scoped to org)
	var targets []models.ScanTarget
	if len(req.TargetIDs) > 0 {
		ScopedDB(c).Where("id IN ?", req.TargetIDs).Find(&targets)
	} else {
		ScopedDB(c).Find(&targets)
	}

	if len(targets) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No targets found to scan"})
	}

	// Check domain verification (skip for system admin)
	userRole, _ := c.Locals("role").(string)
	if userRole != "admin" {
		var unverifiedDomains []string
		for _, target := range targets {
			var verification models.DomainVerification
			err := config.DB.Where("scan_target_id = ? AND is_verified = ?", target.ID, true).First(&verification).Error
			if err != nil {
				unverifiedDomains = append(unverifiedDomains, target.URL)
			}
		}
		if len(unverifiedDomains) > 0 {
			return c.Status(403).JSON(fiber.Map{
				"error":              "Some targets are not verified. Please verify domain ownership before scanning.",
				"unverified_domains": unverifiedDomains,
			})
		}
	}

	// Create scan job
	job := models.ScanJob{
		OrganizationID: GetUserOrgID(c),
		Name:           req.Name,
		Status:         "pending",
		UserID:         userID,
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

	// Run scan in background — use policy-based engine if specified, otherwise plan-based
	var engine *scanner.Engine
	if req.Policy != "" {
		engine = scanner.NewEngineForPolicy(req.Policy)
	} else {
		engine = scanner.NewEngineForPlan(plan)
	}
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
	orgID := GetUserOrgID(c)
	role, _ := c.Locals("role").(string)
	isAdmin := role == "admin"

	var targetCount int64
	if isAdmin {
		config.DB.Model(&models.ScanTarget{}).Count(&targetCount)
	} else {
		config.DB.Model(&models.ScanTarget{}).Where("organization_id = ?", orgID).Count(&targetCount)
	}

	var jobCount int64
	if isAdmin {
		config.DB.Model(&models.ScanJob{}).Count(&jobCount)
	} else {
		config.DB.Model(&models.ScanJob{}).Where("organization_id = ?", orgID).Count(&jobCount)
	}

	var completedJobs int64
	if isAdmin {
		config.DB.Model(&models.ScanJob{}).Where("status = ?", "completed").Count(&completedJobs)
	} else {
		config.DB.Model(&models.ScanJob{}).Where("organization_id = ? AND status = ?", orgID, "completed").Count(&completedJobs)
	}

	// Get latest scan results - scoped to org for non-admins
	var latestResults []models.ScanResult
	if isAdmin {
		config.DB.Raw(`
			SELECT sr.* FROM scan_results sr
			INNER JOIN (
				SELECT scan_target_id, MAX(id) AS max_id
				FROM scan_results WHERE status = 'completed'
				GROUP BY scan_target_id
			) latest ON sr.id = latest.max_id
			ORDER BY sr.overall_score DESC LIMIT 20
		`).Preload("ScanTarget").Find(&latestResults)
	} else {
		config.DB.Raw(`
			SELECT sr.* FROM scan_results sr
			INNER JOIN scan_targets st ON st.id = sr.scan_target_id
			INNER JOIN (
				SELECT scan_target_id, MAX(id) AS max_id
				FROM scan_results WHERE status = 'completed'
				GROUP BY scan_target_id
			) latest ON sr.id = latest.max_id
			WHERE st.organization_id = ?
			ORDER BY sr.overall_score DESC LIMIT 20
		`, orgID).Preload("ScanTarget").Find(&latestResults)
	}

	// Average score
	var avgScore float64
	if isAdmin {
		config.DB.Raw(`
			SELECT COALESCE(AVG(sr.overall_score), 0) FROM scan_results sr
			INNER JOIN (SELECT scan_target_id, MAX(id) AS max_id FROM scan_results WHERE status = 'completed' GROUP BY scan_target_id) latest ON sr.id = latest.max_id
		`).Scan(&avgScore)
	} else {
		config.DB.Raw(`
			SELECT COALESCE(AVG(sr.overall_score), 0) FROM scan_results sr
			INNER JOIN scan_targets st ON st.id = sr.scan_target_id
			INNER JOIN (SELECT scan_target_id, MAX(id) AS max_id FROM scan_results WHERE status = 'completed' GROUP BY scan_target_id) latest ON sr.id = latest.max_id
			WHERE st.organization_id = ?
		`, orgID).Scan(&avgScore)
	}

	// Score distribution - scoped
	var excellent, good, average, poor, critical int64
	scoreQuery := config.DB.Model(&models.ScanResult{}).Where("status = ?", "completed")
	if !isAdmin {
		scoreQuery = scoreQuery.Where("scan_target_id IN (SELECT id FROM scan_targets WHERE organization_id = ?)", orgID)
	}
	scoreQuery.Where("overall_score >= 800").Count(&excellent)
	scoreQuery.Where("overall_score >= 600 AND overall_score < 800").Count(&good)
	scoreQuery.Where("overall_score >= 400 AND overall_score < 600").Count(&average)
	scoreQuery.Where("overall_score >= 200 AND overall_score < 400").Count(&poor)
	scoreQuery.Where("overall_score < 200").Count(&critical)

	return c.JSON(fiber.Map{
		"total_targets":   targetCount,
		"total_scans":     jobCount,
		"completed_scans": completedJobs,
		"average_score":   avgScore,
		"latest_results":  latestResults,
		"score_distribution": []fiber.Map{
			{"range": "Excellent (800-1000)", "count": excellent},
			{"range": "Good (600-799)", "count": good},
			{"range": "Average (400-599)", "count": average},
			{"range": "Poor (200-399)", "count": poor},
			{"range": "Critical (0-199)", "count": critical},
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

// --- Leaderboard: All websites ranked by security score ---

func GetLeaderboard(c *fiber.Ctx) error {
	type RankedSite struct {
		ScanTargetID uint    `json:"scan_target_id"`
		URL          string  `json:"url"`
		Name         string  `json:"name"`
		Institution  string  `json:"institution"`
		LatestScore  float64 `json:"latest_score"`
		ScanResultID uint    `json:"scan_result_id"`
		ScannedAt    string  `json:"scanned_at"`
	}

	orgID := GetUserOrgID(c)
	role, _ := c.Locals("role").(string)
	isAdmin := role == "admin"

	var ranked []RankedSite
	if isAdmin {
		config.DB.Raw(`
			SELECT sr.scan_target_id, st.url, st.name, st.institution,
				   sr.overall_score AS latest_score, sr.id AS scan_result_id,
				   sr.ended_at AS scanned_at
			FROM scan_results sr
			INNER JOIN scan_targets st ON st.id = sr.scan_target_id
			INNER JOIN (
				SELECT scan_target_id, MAX(id) AS max_id
				FROM scan_results WHERE status = 'completed'
				GROUP BY scan_target_id
			) latest ON sr.id = latest.max_id
			ORDER BY sr.overall_score DESC
		`).Scan(&ranked)
	} else {
		config.DB.Raw(`
			SELECT sr.scan_target_id, st.url, st.name, st.institution,
				   sr.overall_score AS latest_score, sr.id AS scan_result_id,
				   sr.ended_at AS scanned_at
			FROM scan_results sr
			INNER JOIN scan_targets st ON st.id = sr.scan_target_id
			INNER JOIN (
				SELECT scan_target_id, MAX(id) AS max_id
				FROM scan_results WHERE status = 'completed'
				GROUP BY scan_target_id
			) latest ON sr.id = latest.max_id
			WHERE st.organization_id = ?
			ORDER BY sr.overall_score DESC
		`, orgID).Scan(&ranked)
	}

	// Category breakdown for each site
	type CategoryScore struct {
		Category string  `json:"category"`
		Score    float64 `json:"score"`
	}

	type RankedSiteWithCategories struct {
		RankedSite
		Rank       int             `json:"rank"`
		Grade      string          `json:"grade"`
		Categories []CategoryScore `json:"categories"`
	}

	var result []RankedSiteWithCategories
	for i, site := range ranked {
		entry := RankedSiteWithCategories{
			RankedSite: site,
			Rank:       i + 1,
			Grade:      scoreToGrade(site.LatestScore),
		}

		// Get category scores
		var checks []models.CheckResult
		config.DB.Where("scan_result_id = ?", site.ScanResultID).Find(&checks)

		catScores := map[string]struct{ total, weight float64 }{}
		for _, ch := range checks {
			cs := catScores[ch.Category]
			cs.total += ch.Score * ch.Weight
			cs.weight += ch.Weight
			catScores[ch.Category] = cs
		}

		for cat, cs := range catScores {
			score := 0.0
			if cs.weight > 0 {
				score = cs.total / cs.weight
			}
			entry.Categories = append(entry.Categories, CategoryScore{
				Category: cat,
				Score:    score,
			})
		}

		result = append(result, entry)
	}

	// Summary stats - scoped to org for non-admins
	var totalSites int64
	if isAdmin {
		config.DB.Model(&models.ScanTarget{}).Count(&totalSites)
	} else {
		config.DB.Model(&models.ScanTarget{}).Where("organization_id = ?", orgID).Count(&totalSites)
	}

	var avgScore float64
	if len(ranked) > 0 {
		sum := 0.0
		for _, r := range ranked {
			sum += r.LatestScore
		}
		avgScore = sum / float64(len(ranked))
	}

	return c.JSON(fiber.Map{
		"rankings":     result,
		"total_sites":  totalSites,
		"scanned_sites": len(ranked),
		"average_score": avgScore,
	})
}

// --- Score History ---

func GetScoreHistory(c *fiber.Ctx) error {
	targetID := c.Params("id")

	type HistoryPoint struct {
		Score     float64 `json:"score"`
		ScannedAt string  `json:"scanned_at"`
		ScanJobID uint    `json:"scan_job_id"`
		ResultID  uint    `json:"result_id"`
	}

	var history []HistoryPoint
	config.DB.Raw(`
		SELECT overall_score AS score, ended_at AS scanned_at,
		       scan_job_id, id AS result_id
		FROM scan_results
		WHERE scan_target_id = ? AND status = 'completed'
		ORDER BY created_at ASC
	`, targetID).Scan(&history)

	return c.JSON(history)
}

// --- Scan Comparison ---

func CompareScanResults(c *fiber.Ctx) error {
	oldID := c.Query("old")
	newID := c.Query("new")

	if oldID == "" || newID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Both 'old' and 'new' result IDs are required"})
	}

	var oldResult, newResult models.ScanResult
	if err := config.DB.Preload("ScanTarget").First(&oldResult, oldID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Old result not found"})
	}
	if err := config.DB.Preload("ScanTarget").First(&newResult, newID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "New result not found"})
	}

	var oldChecks, newChecks []models.CheckResult
	config.DB.Where("scan_result_id = ?", oldResult.ID).Find(&oldChecks)
	config.DB.Where("scan_result_id = ?", newResult.ID).Find(&newChecks)

	// Build category scores for both
	type CategoryComparison struct {
		Category string  `json:"category"`
		OldScore float64 `json:"old_score"`
		NewScore float64 `json:"new_score"`
		Change   float64 `json:"change"`
		Status   string  `json:"status"` // improved, declined, unchanged
	}

	type CheckComparison struct {
		CheckName string  `json:"check_name"`
		Category  string  `json:"category"`
		OldScore  float64 `json:"old_score"`
		NewScore  float64 `json:"new_score"`
		OldStatus string  `json:"old_status"`
		NewStatus string  `json:"new_status"`
		Change    float64 `json:"change"`
		Status    string  `json:"status"`
	}

	// Calculate category scores
	calcCatScores := func(checks []models.CheckResult) map[string]float64 {
		catTotal := map[string]float64{}
		catWeight := map[string]float64{}
		for _, ch := range checks {
			catTotal[ch.Category] += ch.Score * ch.Weight
			catWeight[ch.Category] += ch.Weight
		}
		result := map[string]float64{}
		for cat, total := range catTotal {
			if catWeight[cat] > 0 {
				result[cat] = total / catWeight[cat]
			}
		}
		return result
	}

	oldCatScores := calcCatScores(oldChecks)
	newCatScores := calcCatScores(newChecks)

	// All categories
	allCats := map[string]bool{}
	for cat := range oldCatScores {
		allCats[cat] = true
	}
	for cat := range newCatScores {
		allCats[cat] = true
	}

	var categories []CategoryComparison
	for cat := range allCats {
		oldScore := oldCatScores[cat]
		newScore := newCatScores[cat]
		change := newScore - oldScore
		status := "unchanged"
		if change > 10 {
			status = "improved"
		}
		if change < -10 {
			status = "declined"
		}
		categories = append(categories, CategoryComparison{
			Category: cat, OldScore: oldScore, NewScore: newScore, Change: change, Status: status,
		})
	}

	// Check-level comparison
	oldCheckMap := map[string]models.CheckResult{}
	for _, ch := range oldChecks {
		oldCheckMap[ch.CheckName] = ch
	}

	var checks []CheckComparison
	for _, newCh := range newChecks {
		oldCh, exists := oldCheckMap[newCh.CheckName]
		oldScore := 0.0
		oldStatus := "N/A"
		if exists {
			oldScore = oldCh.Score
			oldStatus = oldCh.Status
		}
		change := newCh.Score - oldScore
		status := "unchanged"
		if change > 50 {
			status = "improved"
		}
		if change < -50 {
			status = "declined"
		}
		checks = append(checks, CheckComparison{
			CheckName: newCh.CheckName, Category: newCh.Category,
			OldScore: oldScore, NewScore: newCh.Score,
			OldStatus: oldStatus, NewStatus: newCh.Status,
			Change: change, Status: status,
		})
	}

	// Summary
	improved := 0
	declined := 0
	for _, ch := range checks {
		if ch.Status == "improved" {
			improved++
		}
		if ch.Status == "declined" {
			declined++
		}
	}

	return c.JSON(fiber.Map{
		"old_result": fiber.Map{
			"id": oldResult.ID, "score": oldResult.OverallScore,
			"date": oldResult.EndedAt, "target": oldResult.ScanTarget,
		},
		"new_result": fiber.Map{
			"id": newResult.ID, "score": newResult.OverallScore,
			"date": newResult.EndedAt, "target": newResult.ScanTarget,
		},
		"score_change": newResult.OverallScore - oldResult.OverallScore,
		"categories":   categories,
		"checks":       checks,
		"summary": fiber.Map{
			"total_checks": len(checks),
			"improved":     improved,
			"declined":     declined,
			"unchanged":    len(checks) - improved - declined,
		},
	})
}

// --- Compliance Report ---

func GetComplianceReport(c *fiber.Ctx) error {
	resultID := c.Params("id")

	var checks []models.CheckResult
	config.DB.Where("scan_result_id = ?", resultID).Find(&checks)

	// Group by OWASP category
	type OWASPCompliance struct {
		ID           string      `json:"id"`
		Name         string      `json:"name"`
		TotalChecks  int         `json:"total_checks"`
		PassedChecks int         `json:"passed_checks"`
		FailedChecks int         `json:"failed_checks"`
		WarnChecks   int         `json:"warn_checks"`
		Compliance   float64     `json:"compliance"`
		Severity     string      `json:"severity"`
		Checks       []fiber.Map `json:"checks"`
	}

	owaspMap := map[string]*OWASPCompliance{}

	for _, ch := range checks {
		if ch.OWASP == "" {
			continue
		}

		if _, exists := owaspMap[ch.OWASP]; !exists {
			owaspMap[ch.OWASP] = &OWASPCompliance{
				ID: ch.OWASP, Name: ch.OWASPName,
			}
		}

		entry := owaspMap[ch.OWASP]
		entry.TotalChecks++

		switch ch.Status {
		case "pass":
			entry.PassedChecks++
		case "fail":
			entry.FailedChecks++
		case "warn", "warning":
			entry.WarnChecks++
		}

		entry.Checks = append(entry.Checks, fiber.Map{
			"name": ch.CheckName, "score": ch.Score,
			"status": ch.Status, "severity": ch.Severity,
			"cwe": ch.CWE, "cwe_name": ch.CWEName,
		})
	}

	// Calculate compliance percentages
	var results []OWASPCompliance
	totalCompliant := 0
	totalChecks := 0

	for _, entry := range owaspMap {
		if entry.TotalChecks > 0 {
			entry.Compliance = float64(entry.PassedChecks) / float64(entry.TotalChecks) * 100
		}
		if entry.FailedChecks > 0 {
			entry.Severity = "high"
		}
		if entry.PassedChecks == entry.TotalChecks {
			entry.Severity = "low"
		}

		totalCompliant += entry.PassedChecks
		totalChecks += entry.TotalChecks
		results = append(results, *entry)
	}

	overallCompliance := 0.0
	if totalChecks > 0 {
		overallCompliance = float64(totalCompliant) / float64(totalChecks) * 100
	}

	return c.JSON(fiber.Map{
		"overall_compliance": overallCompliance,
		"total_checks":      totalChecks,
		"total_passed":      totalCompliant,
		"owasp_categories":  results,
	})
}

// --- Remediation Guide ---

func GetRemediationGuide(c *fiber.Ctx) error {
	checkName := c.Query("check")
	serverType := c.Query("server", "all")

	if checkName == "" {
		// Return list of all available remediations
		var keys []string
		for k := range scanner.RemediationDB {
			keys = append(keys, k)
		}
		return c.JSON(fiber.Map{"available_checks": keys})
	}

	guide, exists := scanner.RemediationDB[checkName]
	if !exists {
		return c.Status(404).JSON(fiber.Map{"error": "No remediation guide found for this check"})
	}

	if serverType != "all" {
		if specific, ok := guide.Guides[serverType]; ok {
			guide.Guides = map[string]string{serverType: specific}
		}
	}

	return c.JSON(guide)
}

func scoreToGrade(score float64) string {
	switch {
	case score >= 900:
		return "A+"
	case score >= 800:
		return "A"
	case score >= 700:
		return "B"
	case score >= 600:
		return "C"
	case score >= 500:
		return "D"
	default:
		return "F"
	}
}
