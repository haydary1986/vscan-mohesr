package scanner

import (
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"vscan-mohesr/internal/config"
	"vscan-mohesr/internal/models"
	"vscan-mohesr/internal/services"
	"vscan-mohesr/internal/ws"
)

// MaxScore is the maximum score for any check (1000-point scale)
const MaxScore = 1000.0

// Scanner interface that all security scanners must implement
type Scanner interface {
	Name() string
	Category() string
	Weight() float64
	Scan(url string) []models.CheckResult
}

// Plan tier scanner access
// Free: 5 categories (basic security)
// Basic: 13 categories (standard security)
// Pro: 22 categories (advanced security)
// Enterprise: 25 categories (full scan)
var PlanScanners = map[string][]string{
	"free": { // 5 categories - basic security
		"ssl",
		"headers",
		"cookies",
		"performance",
		"mixed_content",
	},
	"basic": { // 13 categories - standard security
		"ssl",
		"headers",
		"cookies",
		"server_info",
		"directory",
		"performance",
		"ddos",
		"cors",
		"http_methods",
		"dns",
		"mixed_content",
		"seo",
		"secrets",
	},
	"pro": { // 22 categories - advanced security
		"ssl",
		"headers",
		"cookies",
		"server_info",
		"directory",
		"performance",
		"ddos",
		"cors",
		"http_methods",
		"dns",
		"mixed_content",
		"info_disclosure",
		"content",
		"hosting",
		"seo",
		"third_party",
		"js_libraries",
		"wordpress",
		"xss",
		"secrets",
		"subdomains",
		"tech_stack",
	},
	"enterprise": { // 25 categories - full scan
		"ssl",
		"headers",
		"cookies",
		"server_info",
		"directory",
		"performance",
		"ddos",
		"cors",
		"http_methods",
		"dns",
		"mixed_content",
		"info_disclosure",
		"content",
		"hosting",
		"advanced_security",
		"malware",
		"threat_intel",
		"seo",
		"third_party",
		"js_libraries",
		"wordpress",
		"xss",
		"secrets",
		"subdomains",
		"tech_stack",
	},
}

// Engine manages and runs all scanners
type Engine struct {
	scanners []Scanner
	plan     string
}

// ScanPolicy defines preset scanning configurations
type ScanPolicy struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Categories  []string `json:"categories"`
	Timeout     int      `json:"timeout"` // seconds per target
}

// ScanPolicies contains the available scan policy presets
var ScanPolicies = map[string]ScanPolicy{
	"light": {
		Name:        "Light Scan",
		Description: "Quick security check — 8 basic categories, ~30 seconds per site",
		Categories:  []string{"ssl", "headers", "cookies", "mixed_content", "performance", "dns", "seo", "content"},
		Timeout:     30,
	},
	"standard": {
		Name:        "Standard Scan",
		Description: "Comprehensive security audit — 16 categories, ~60 seconds per site",
		Categories:  []string{"ssl", "headers", "cookies", "server_info", "directory", "performance", "ddos", "cors", "http_methods", "dns", "mixed_content", "info_disclosure", "hosting", "content", "seo", "secrets"},
		Timeout:     60,
	},
	"deep": {
		Name:        "Deep Scan",
		Description: "Full security assessment — all categories including XSS, malware, subdomains, ~120 seconds per site",
		Categories:  []string{"ssl", "headers", "cookies", "server_info", "directory", "performance", "ddos", "cors", "http_methods", "dns", "mixed_content", "info_disclosure", "hosting", "content", "advanced_security", "malware", "threat_intel", "seo", "third_party", "js_libraries", "wordpress", "xss", "secrets", "subdomains", "tech_stack"},
		Timeout:     120,
	},
}

// allScanners returns all registered scanners
func allScanners() []Scanner {
	return []Scanner{
		NewSSLScanner(),
		NewHeaderScanner(),
		NewCookieScanner(),
		NewServerInfoScanner(),
		NewDirectoryScanner(),
		NewPerformanceScanner(),
		NewDDoSScanner(),
		NewCORSScanner(),
		NewHTTPMethodsScanner(),
		NewDNSScanner(),
		NewMixedContentScanner(),
		NewInfoDisclosureScanner(),
		NewContentScanner(),
		NewHostingScanner(),
		NewAdvancedSecurityScanner(),
		NewMalwareScanner(),
		NewThreatIntelScanner(),
		NewSEOScanner(),
		NewThirdPartyScanner(),
		NewJSLibScanner(),
		NewWordPressScanner(),
		NewXSSScanner(),
		NewSecretsScanner(),
		NewSubdomainScanner(),
		NewTechDetectScanner(),
	}
}

// NewEngineForPolicy creates a scan engine filtered by scan policy
func NewEngineForPolicy(policy string) *Engine {
	p, ok := ScanPolicies[policy]
	if !ok {
		p = ScanPolicies["standard"]
	}

	allowedMap := map[string]bool{}
	for _, cat := range p.Categories {
		allowedMap[cat] = true
	}

	var filtered []Scanner
	for _, s := range allScanners() {
		if allowedMap[s.Category()] {
			filtered = append(filtered, s)
		}
	}
	return &Engine{scanners: filtered, plan: "enterprise"}
}

// NewEngine creates a scan engine with all scanners (enterprise by default)
func NewEngine() *Engine {
	return &Engine{
		scanners: allScanners(),
		plan:     "enterprise",
	}
}

// NewEngineForPlan creates a scan engine filtered by plan
func NewEngineForPlan(plan string) *Engine {
	allowed, ok := PlanScanners[plan]
	if !ok {
		allowed = PlanScanners["enterprise"]
	}

	allowedMap := map[string]bool{}
	for _, cat := range allowed {
		allowedMap[cat] = true
	}

	var filtered []Scanner
	for _, s := range allScanners() {
		if allowedMap[s.Category()] {
			filtered = append(filtered, s)
		}
	}

	return &Engine{
		scanners: filtered,
		plan:     plan,
	}
}

// RunScan executes all scanners against a target
func (e *Engine) RunScan(job *models.ScanJob) {
	now := time.Now()
	job.Status = "running"
	job.StartedAt = &now
	config.DB.Save(job)

	var results []models.ScanResult
	config.DB.Where("scan_job_id = ?", job.ID).Preload("ScanTarget").Find(&results)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	var completedCount int64

	for i := range results {
		wg.Add(1)
		sem <- struct{}{}
		go func(result *models.ScanResult) {
			defer wg.Done()
			defer func() { <-sem }()
			e.scanTarget(result)

			current := atomic.AddInt64(&completedCount, 1)
			ws.DefaultHub.Broadcast(ws.ScanProgress{
				JobID:      job.ID,
				Status:     "running",
				Total:      len(results),
				Completed:  int(current),
				Percent:    float64(current) / float64(len(results)) * 100,
				CurrentURL: result.ScanTarget.URL,
				Message:    fmt.Sprintf("Completed %d/%d", current, len(results)),
			})
		}(&results[i])
	}

	wg.Wait()

	ws.DefaultHub.Broadcast(ws.ScanProgress{
		JobID:     job.ID,
		Status:    "completed",
		Total:     len(results),
		Completed: len(results),
		Percent:   100,
		Message:   "Scan completed",
	})

	ended := time.Now()
	job.Status = "completed"
	job.EndedAt = &ended
	config.DB.Save(job)

	// Send webhook notifications
	var completedResults []models.ScanResult
	config.DB.Where("scan_job_id = ?", job.ID).Preload("ScanTarget").Find(&completedResults)
	services.SendScanCompletedWebhooks(job, completedResults)

	// Send email notifications
	services.SendScanCompletedEmail(job, completedResults)
}

func (e *Engine) scanTarget(result *models.ScanResult) {
	now := time.Now()
	result.Status = "running"
	result.StartedAt = &now
	config.DB.Save(result)

	var allChecks []models.CheckResult
	var totalScore, totalWeight float64

	for _, s := range e.scanners {
		checks := s.Scan(result.ScanTarget.URL)
		for i := range checks {
			checks[i].ScanResultID = result.ID
		}
		allChecks = append(allChecks, checks...)
	}

	// Populate OWASP/CWE mappings
	for i := range allChecks {
		if m := GetOWASPMapping(allChecks[i].CheckName); m != nil {
			allChecks[i].OWASP = m.OWASP
			allChecks[i].OWASPName = m.OWASPName
			allChecks[i].CWE = m.CWE
			allChecks[i].CWEName = m.CWEName
		}
	}

	// Populate confidence scores
	for i := range allChecks {
		allChecks[i].Confidence = GetConfidence(allChecks[i].CheckName)
	}

	// Populate CVSS v3.1 scores for failed checks
	for i := range allChecks {
		if m := GetCVSSMapping(allChecks[i].CheckName); m != nil && allChecks[i].Status == "fail" {
			allChecks[i].CVSSScore = m.Score
			allChecks[i].CVSSVector = m.Vector
			allChecks[i].CVSSRating = m.Rating
		}
	}

	// Save all checks
	if len(allChecks) > 0 {
		config.DB.Create(&allChecks)
	}

	// Calculate overall score (0-1000)
	for _, check := range allChecks {
		if check.Weight > 0 {
			totalScore += check.Score * check.Weight
			totalWeight += check.Weight
		}
	}

	if totalWeight > 0 {
		result.OverallScore = math.Round(totalScore / totalWeight)
	}

	ended := time.Now()
	result.Status = "completed"
	result.EndedAt = &ended
	config.DB.Save(result)
}

// GetScanners returns the list of scanners in this engine
func (e *Engine) GetScanners() []Scanner {
	return e.scanners
}

// GetPlanCategories returns the allowed categories for a plan
func GetPlanCategories(plan string) []string {
	if cats, ok := PlanScanners[plan]; ok {
		return cats
	}
	return PlanScanners["enterprise"]
}

// GetPlanCategoryCount returns how many categories a plan can scan
func GetPlanCategoryCount(plan string) int {
	return len(GetPlanCategories(plan))
}
