package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a system user
type User struct {
	gorm.Model
	Username string `json:"username" gorm:"uniqueIndex;not null"`
	Password string `json:"-" gorm:"not null"` // never expose in JSON
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	Role     string `json:"role" gorm:"default:user"` // admin, user
	IsActive bool   `json:"is_active" gorm:"default:true"`
}

// Settings stores application settings (AI config, etc.)
type Settings struct {
	gorm.Model
	Key   string `json:"key" gorm:"uniqueIndex;not null"`
	Value string `json:"value"`
}

// AIAnalysis stores AI-generated analysis for scan results
type AIAnalysis struct {
	gorm.Model
	ScanResultID uint   `json:"scan_result_id" gorm:"not null"`
	Provider     string `json:"provider"` // deepseek, openai, etc.
	Analysis     string `json:"analysis"` // full AI response
	Status       string `json:"status" gorm:"default:pending"` // pending, completed, failed
}

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
	Name      string       `json:"name"`
	Status    string       `json:"status" gorm:"default:pending"` // pending, running, completed, failed
	StartedAt *time.Time   `json:"started_at"`
	EndedAt   *time.Time   `json:"ended_at"`
	UserID    uint         `json:"user_id"`
	Results   []ScanResult `json:"results" gorm:"foreignKey:ScanJobID"`
}

// ScanResult represents the result of scanning a single target
type ScanResult struct {
	gorm.Model
	ScanJobID    uint        `json:"scan_job_id" gorm:"not null"`
	ScanTargetID uint        `json:"scan_target_id" gorm:"not null"`
	ScanTarget   ScanTarget  `json:"scan_target" gorm:"foreignKey:ScanTargetID"`
	OverallScore float64     `json:"overall_score"` // 0-100
	Status       string      `json:"status" gorm:"default:pending"`
	StartedAt    *time.Time  `json:"started_at"`
	EndedAt      *time.Time  `json:"ended_at"`
	Checks       []CheckResult `json:"checks" gorm:"foreignKey:ScanResultID"`
	AIAnalysis   *AIAnalysis `json:"ai_analysis,omitempty" gorm:"foreignKey:ScanResultID"`
}

// CheckResult represents a single security check result
type CheckResult struct {
	gorm.Model
	ScanResultID uint    `json:"scan_result_id" gorm:"not null"`
	Category     string  `json:"category"`
	CheckName    string  `json:"check_name"`
	Status       string  `json:"status"`    // pass, fail, warning, info, error
	Score        float64 `json:"score"`     // 0-100
	Weight       float64 `json:"weight"`    // weight for overall score
	Details      string  `json:"details"`   // detailed findings as JSON
	Severity     string  `json:"severity"`  // critical, high, medium, low, info
}
