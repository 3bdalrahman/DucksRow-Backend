package middleware

import (
	"context"

	"ducksrow/backend/services"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// permissionChecker is used by RequireOwnershipOrPermission (consumer-side interface).
type permissionChecker interface {
	HasPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error)
}

// ownershipChecker is used by RequireOwnershipOrPermission (consumer-side interface).
type ownershipChecker interface {
	IsOwner(ctx context.Context, placeID, userID uuid.UUID) (bool, error)
}

// RequirePermission returns a handler that allows the request only if the authenticated user has the given permission.
// Expects Protected(db) to have run first so c.Locals("userID") is set (uuid.UUID).
func RequirePermission(db *gorm.DB, permission string) fiber.Handler {
	svc := services.NewPermissionService(db)
	return requirePermissionSvc(svc, permission)
}

func requirePermissionSvc(svc permissionChecker, permission string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		uid, ok := c.Locals("userID").(uuid.UUID)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "user not authenticated",
				"code":  "UNAUTHORIZED",
			})
		}
		hasPerm, err := svc.HasPermission(c.Context(), uid, permission)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "permission check failed",
				"code":  "INTERNAL_ERROR",
			})
		}
		if !hasPerm {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Insufficient permissions",
				"code":  "FORBIDDEN",
			})
		}
		return c.Next()
	}
}

// RequireOwnershipOrPermission allows the request if the user has fullPerm, or has ownPerm and owns the resource.
// Expects Protected(db) to have run first. paramName is the route param holding the place ID (e.g. "id").
func RequireOwnershipOrPermission(permSvc permissionChecker, ownerSvc ownershipChecker, fullPerm, ownPerm, paramName string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		uid, ok := c.Locals("userID").(uuid.UUID)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "user not authenticated",
				"code":  "UNAUTHORIZED",
			})
		}
		hasFull, err := permSvc.HasPermission(c.Context(), uid, fullPerm)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "permission check failed",
				"code":  "INTERNAL_ERROR",
			})
		}
		if hasFull {
			return c.Next()
		}
		hasOwn, err := permSvc.HasPermission(c.Context(), uid, ownPerm)
		if err != nil || !hasOwn {
			if !hasOwn {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "Insufficient permissions",
					"code":  "FORBIDDEN",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "permission check failed",
				"code":  "INTERNAL_ERROR",
			})
		}
		placeIDStr := c.Params(paramName)
		placeID, err := uuid.Parse(placeIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid place id",
				"code":  "VALIDATION_ERROR",
			})
		}
		owned, err := ownerSvc.IsOwner(c.Context(), placeID, uid)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "ownership check failed",
				"code":  "INTERNAL_ERROR",
			})
		}
		if !owned {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Insufficient permissions",
				"code":  "FORBIDDEN",
			})
		}
		return c.Next()
	}
}
