package handlers

import (
	"ducksrow/backend/permissions"

	"github.com/gofiber/fiber/v2"
)

// ListPermissions returns GET /api/permissions — the fixed permission catalog (no pagination).
func ListPermissions() fiber.Handler {
	return func(c *fiber.Ctx) error {
		data := permissions.All()
		return c.JSON(fiber.Map{"data": data})
	}
}
