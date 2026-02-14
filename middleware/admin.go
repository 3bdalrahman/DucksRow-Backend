package middleware

import (
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AdminOnly parses the JWT and returns 403 if the user does not have the admin role (via user_roles).
// Expects "Authorization: Bearer <token>". Use for admin-only routes. Pass db to query user_roles.
func AdminOnly(db *gorm.DB) fiber.Handler {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "change-me-in-production"
	}
	return func(c *fiber.Ctx) error {
		auth := c.Get("Authorization")
		if auth == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing authorization header",
				"code":  "UNAUTHORIZED",
			})
		}
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid authorization format",
				"code":  "UNAUTHORIZED",
			})
		}
		token, err := jwt.ParseWithClaims(parts[1], &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		})
		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid or expired token",
				"code":  "UNAUTHORIZED",
			})
		}
		claims, ok := token.Claims.(*JWTClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid token claims",
				"code":  "UNAUTHORIZED",
			})
		}
		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid user id in token",
				"code":  "UNAUTHORIZED",
			})
		}
		var n int
		err = db.Raw(
			"SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id AND r.deleted_at IS NULL WHERE ur.user_id = ? AND r.slug = 'admin' LIMIT 1",
			userID,
		).Scan(&n).Error
		if err != nil || n != 1 {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Insufficient permissions",
				"code":  "FORBIDDEN",
			})
		}
		c.Locals("userID", userID)
		return c.Next()
	}
}
