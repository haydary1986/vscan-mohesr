package models

import (
	"time"

	"gorm.io/gorm"
)

// ScanTarget represents a website to be scanned
type ScanTarget struct {
	gorm.Model
	URL         string `json:"url" gorm:"not null"`
	Name        string `json:"name"`        // e.g., "University of Baghdad"
	Institution string `json:"institution"` // institution name
}

// ScanJob represents a batch scan job
type ScanJob struct {
	gorm.Model
	Name      string     `json:"name"`
	Status    string     `json:"status" gorm:"default:pending"` // pending, running, completed, failed
	StartedAt *time.Time `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at"`
	Results   []ScanResult `json:"results" gorm:"foreignKey:ScanJobID"`
}

// ScanResult represents the result of scanning a single target
type ScanResult struct {
	gorm.Model
	ScanJobID    uint       `json:"scan_job_id" gorm:"not null"`
	ScanTargetID uint       `json:"scan_target_id" gorm:"not null"`
	ScanTarget   ScanTarget `json:"scan_target" gorm:"foreignKey:ScanTargetID"`
	OverallScore float64    `json:"overall_score"` // 0-100
	Status       string     `json:"status" gorm:"default:pending"` // pending, running, completed, failed
	StartedAt    *time.Time `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at"`
	Checks       []CheckResult `json:"checks" gorm:"foreignKey:ScanResultID"`
}

// CheckResult represents a single security check result
type CheckResult struct {
	gorm.Model
	ScanResultID uint    `json:"scan_result_id" gorm:"not null"`
	Category     string  `json:"category"`  // ssl, headers, cookies, xss, sqli, ports, cms, directory
	CheckName    string  `json:"check_name"`
	Status       string  `json:"status"`    // pass, fail, warning, info, error
	Score        float64 `json:"score"`     // 0-100
	Weight       float64 `json:"weight"`    // weight for overall score calculation
	Details      string  `json:"details"`   // detailed findings as JSON
	Severity     string  `json:"severity"`  // critical, high, medium, low, info
}
