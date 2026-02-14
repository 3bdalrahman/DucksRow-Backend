package routes

import (
	"os"

	"ducksrow/backend/handlers"
	"ducksrow/backend/middleware"
	"ducksrow/backend/services"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// Setup registers all routes.
func Setup(app *fiber.App, db *gorm.DB) {
	jwtSecret := os.Getenv("JWT_SECRET")
	authSvc := services.NewAuthService(db)

	// Health
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Auth (public)
	app.Post("/auth/register", handlers.Register(authSvc, jwtSecret))
	app.Post("/auth/login", handlers.Login(authSvc, jwtSecret))
	app.Post("/auth/logout", handlers.Logout())

	// Protected routes (require auth + permission per route)
	api := app.Group("/api", middleware.Protected(db))
	api.Post("/places", middleware.RequirePermission(db, "places:write"), handlers.CreatePlace(db))
	// Place update/delete (when added): use middleware.RequireOwnershipOrPermission(permSvc, ownerSvc, "places:write", "places:own", "id")
	SetupRBAC(api, db)

	// Admin-only routes (user must have admin role via user_roles)
	admin := app.Group("/admin", middleware.AdminOnly(db))
	admin.Get("/stats", handlers.AdminStats)
}
