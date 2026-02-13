package routes

import (
	"os"

	"ducksrow/backend/handlers"
	"ducksrow/backend/middleware"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// Setup registers all routes.
func Setup(app *fiber.App, db *gorm.DB) {
	jwtSecret := os.Getenv("JWT_SECRET")

	// Health
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Auth (public)
	app.Post("/auth/register", handlers.Register(db, jwtSecret))
	app.Post("/auth/login", handlers.Login(db, jwtSecret))
	app.Post("/auth/logout", handlers.Logout())

	// Protected routes
	api := app.Group("/api", middleware.Protected(db))
	api.Post("/places", handlers.CreatePlace(db))

	// Admin-only routes (JWT must contain role "admin")
	admin := app.Group("/admin", middleware.AdminOnly())
	admin.Get("/stats", handlers.AdminStats)
}
