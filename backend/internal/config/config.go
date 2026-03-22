package config

import (
	"log"
	"os"

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
		&models.ScanTarget{},
		&models.ScanJob{},
		&models.ScanResult{},
		&models.CheckResult{},
	)
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	log.Println("Database initialized successfully")
}
