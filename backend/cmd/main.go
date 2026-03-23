package main

import (
	"log"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"

	"vscan-mohesr/internal/api"
	"vscan-mohesr/internal/config"
	"vscan-mohesr/internal/scheduler"
	"vscan-mohesr/internal/ws"
)

func main() {
	// Initialize database
	config.InitDatabase()

	// Seed universities from MOHESR list
	config.SeedUniversities()

	// Start scheduler
	scheduler.Start()

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "VScan-MOHESR v1.0",
	})

	// Setup routes
	api.SetupRoutes(app)

	// WebSocket upgrade middleware
	app.Use("/ws", func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})
	app.Get("/ws/scan", websocket.New(ws.HandleWebSocket))

	// Start server
	log.Println("VScan-MOHESR server starting on :8080")
	log.Fatal(app.Listen(":8080"))
}
