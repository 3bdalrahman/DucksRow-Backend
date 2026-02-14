package routes

import (
	"ducksrow/backend/handlers"
	"ducksrow/backend/middleware"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// SetupRBAC registers RBAC-related routes under the given API group.
// The group must already use Protected(db). This adds AdminOnly(db) for admin-only RBAC endpoints.
// CORS and rate limiting: same app-level middleware as other routes; no RBAC-specific limits (see Constitution Principle IV).
func SetupRBAC(api fiber.Router, db *gorm.DB) {
	admin := api.Group("", middleware.AdminOnly(db))
	// User roles
	admin.Get("/users/:id/roles", handlers.ListUserRoles(db))
	admin.Post("/users/:id/roles", handlers.AssignRole(db))
	admin.Delete("/users/:id/roles/:roleId", handlers.UnassignRole(db))
	// Audit (more specific before /roles/:id)
	admin.Get("/roles/audit", handlers.ListRoleAudit(db))
	// Permissions catalog
	admin.Get("/permissions", handlers.ListPermissions())
	// Role CRUD
	admin.Get("/roles", handlers.ListRoles(db))
	admin.Post("/roles", handlers.CreateRole(db))
	admin.Get("/roles/:id", handlers.GetRole(db))
	admin.Put("/roles/:id", handlers.UpdateRole(db))
	admin.Delete("/roles/:id", handlers.DeleteRole(db))
}
