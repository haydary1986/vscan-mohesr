package api

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func SetupRoutes(app *fiber.App) {
	// Middleware
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "http://localhost:5173, http://localhost:3000",
		AllowHeaders: "Origin, Content-Type, Accept",
		AllowMethods: "GET, POST, PUT, DELETE",
	}))

	// API routes
	api := app.Group("/api")

	// Targets
	targets := api.Group("/targets")
	targets.Get("/", GetTargets)
	targets.Post("/", CreateTarget)
	targets.Post("/bulk", CreateBulkTargets)
	targets.Put("/:id", UpdateTarget)
	targets.Delete("/:id", DeleteTarget)

	// Scan Jobs
	scans := api.Group("/scans")
	scans.Get("/", GetScanJobs)
	scans.Get("/:id", GetScanJob)
	scans.Post("/start", StartScan)
	scans.Delete("/:id", DeleteScanJob)

	// Scan Results
	results := api.Group("/results")
	results.Get("/:id", GetScanResult)

	// Dashboard
	api.Get("/dashboard", GetDashboardStats)
}
