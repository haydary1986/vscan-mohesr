package config

import (
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"vscan-mohesr/internal/models"
)

var DB *gorm.DB

func InitDatabase() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "vscan.db"
	}

	var err error
	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	err = DB.AutoMigrate(
		&models.User{},
		&models.Settings{},
		&models.AIAnalysis{},
		&models.ScanTarget{},
		&models.ScanJob{},
		&models.ScanResult{},
		&models.CheckResult{},
	)
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Create default admin if no users exist
	var userCount int64
	DB.Model(&models.User{}).Count(&userCount)
	if userCount == 0 {
		hashed, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		admin := models.User{
			Username: "admin",
			Password: string(hashed),
			FullName: "System Administrator",
			Email:    "admin@mohesr.gov.iq",
			Role:     "admin",
			IsActive: true,
		}
		DB.Create(&admin)
		log.Println("Default admin user created (username: admin, password: admin123)")
	}

	log.Println("Database initialized successfully")
}
