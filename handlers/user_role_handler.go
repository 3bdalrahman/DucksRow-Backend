package handlers

import (
	"context"
	"errors"

	rbacerrors "ducksrow/backend/errors"
	"ducksrow/backend/services"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AssignRoleRequest is the body for POST /api/users/:id/roles.
type AssignRoleRequest struct {
	RoleID string `json:"role_id"` // UUID, required
}

// ListUserRoles returns GET /api/users/:id/roles — list roles for a user.
func ListUserRoles(db *gorm.DB) fiber.Handler {
	svc := services.NewUserRoleService(db)
	return func(c *fiber.Ctx) error {
		userID, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid user id",
				"code":  "VALIDATION_ERROR",
			})
		}
		list, err := svc.ListForUser(context.Background(), userID)
		if err != nil {
			if errors.Is(err, rbacerrors.ErrUserNotFound) {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "user not found",
					"code":  "NOT_FOUND",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to list roles",
				"code":  "INTERNAL_ERROR",
			})
		}
		return c.JSON(fiber.Map{"data": list})
	}
}

// AssignRole handles POST /api/users/:id/roles — assign role to user.
func AssignRole(db *gorm.DB) fiber.Handler {
	svc := services.NewUserRoleService(db)
	return func(c *fiber.Ctx) error {
		userID, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid user id",
				"code":  "VALIDATION_ERROR",
			})
		}
		var req AssignRoleRequest
		if err := c.BodyParser(&req); err != nil || req.RoleID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "role_id is required",
				"code":  "VALIDATION_ERROR",
			})
		}
		roleID, err := uuid.Parse(req.RoleID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid role_id",
				"code":  "VALIDATION_ERROR",
			})
		}
		actorID, ok := c.Locals("userID").(uuid.UUID)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "user not authenticated",
				"code":  "UNAUTHORIZED",
			})
		}
		result, err := svc.Assign(context.Background(), actorID, userID, roleID)
		if err != nil {
			if errors.Is(err, rbacerrors.ErrUserNotFound) || errors.Is(err, rbacerrors.ErrRoleNotFound) {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": err.Error(),
					"code":  "NOT_FOUND",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to assign role",
				"code":  "INTERNAL_ERROR",
			})
		}
		if result.Created {
			return c.Status(fiber.StatusCreated).JSON(fiber.Map{
				"data": fiber.Map{
					"user_id":     result.UserID,
					"role_id":     result.RoleID,
					"role_slug":   result.RoleSlug,
					"role_name":   result.RoleName,
					"assigned_at": result.AssignedAt,
				},
			})
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"data": fiber.Map{
				"user_id":     result.UserID,
				"role_id":     result.RoleID,
				"role_slug":   result.RoleSlug,
				"role_name":   result.RoleName,
				"assigned_at": result.AssignedAt,
			},
		})
	}
}

// UnassignRole handles DELETE /api/users/:id/roles/:roleId.
func UnassignRole(db *gorm.DB) fiber.Handler {
	svc := services.NewUserRoleService(db)
	return func(c *fiber.Ctx) error {
		userID, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid user id",
				"code":  "VALIDATION_ERROR",
			})
		}
		roleID, err := uuid.Parse(c.Params("roleId"))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid role id",
				"code":  "VALIDATION_ERROR",
			})
		}
		actorID, ok := c.Locals("userID").(uuid.UUID)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "user not authenticated",
				"code":  "UNAUTHORIZED",
			})
		}
		if err := svc.Unassign(context.Background(), actorID, userID, roleID); err != nil {
			if errors.Is(err, rbacerrors.ErrAssignmentNotFound) || errors.Is(err, rbacerrors.ErrUserNotFound) || errors.Is(err, rbacerrors.ErrRoleNotFound) {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": err.Error(),
					"code":  "NOT_FOUND",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to remove role",
				"code":  "INTERNAL_ERROR",
			})
		}
		return c.SendStatus(fiber.StatusNoContent)
	}
}
