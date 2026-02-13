package handlers

import (
	"github.com/gofiber/fiber/v2"
)

// AdminStats returns a simple message for testing admin access.
func AdminStats(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"message": "Welcome Admin"})
}
