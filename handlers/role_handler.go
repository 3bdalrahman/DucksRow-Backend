package handlers

import (
	"errors"
	"strconv"

	rbacerrors "ducksrow/backend/errors"
	"ducksrow/backend/services"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CreateRoleRequest is the body for POST /api/roles.
type CreateRoleRequest struct {
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// UpdateRoleRequest is the body for PUT /api/roles/:id.
type UpdateRoleRequest struct {
	Name        *string  `json:"name"`
	Permissions []string `json:"permissions"`
}

// ListRoles returns GET /api/roles — paginated list of roles.
func ListRoles(db *gorm.DB) fiber.Handler {
	svc := services.NewRoleService(db)
	return func(c *fiber.Ctx) error {
		page, _ := strconv.Atoi(c.Query("page", "1"))
		limit, _ := strconv.Atoi(c.Query("limit", "20"))
		list, total, err := svc.List(c.Context(), page, limit)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to list roles",
				"code":  "INTERNAL_ERROR",
			})
		}
		return c.JSON(fiber.Map{
			"data": list,
			"meta": fiber.Map{"page": page, "limit": limit, "total": total},
		})
	}
}

// CreateRole handles POST /api/roles.
func CreateRole(db *gorm.DB) fiber.Handler {
	svc := services.NewRoleService(db)
	return func(c *fiber.Ctx) error {
		var req CreateRoleRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid body",
				"code":  "VALIDATION_ERROR",
			})
		}
		role, err := svc.Create(c.Context(), req.Slug, req.Name, req.Permissions)
		if err != nil {
			status, code := rbacerrors.HTTPStatusAndCode(err)
			return c.Status(status).JSON(fiber.Map{"error": err.Error(), "code": code})
		}
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{"data": role})
	}
}

// GetRole returns GET /api/roles/:id.
func GetRole(db *gorm.DB) fiber.Handler {
	svc := services.NewRoleService(db)
	return func(c *fiber.Ctx) error {
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid role id",
				"code":  "VALIDATION_ERROR",
			})
		}
		role, err := svc.GetByID(c.Context(), id)
		if err != nil {
			if errors.Is(err, rbacerrors.ErrRoleNotFound) {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "role not found",
					"code":  "NOT_FOUND",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to get role",
				"code":  "INTERNAL_ERROR",
			})
		}
		return c.JSON(fiber.Map{"data": role})
	}
}

// UpdateRole handles PUT /api/roles/:id.
func UpdateRole(db *gorm.DB) fiber.Handler {
	svc := services.NewRoleService(db)
	return func(c *fiber.Ctx) error {
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid role id",
				"code":  "VALIDATION_ERROR",
			})
		}
		var req UpdateRoleRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid body",
				"code":  "VALIDATION_ERROR",
			})
		}
		role, err := svc.Update(c.Context(), id, req.Name, req.Permissions)
		if err != nil {
			status, code := rbacerrors.HTTPStatusAndCode(err)
			return c.Status(status).JSON(fiber.Map{"error": err.Error(), "code": code})
		}
		return c.JSON(fiber.Map{"data": role})
	}
}

// DeleteRole handles DELETE /api/roles/:id.
func DeleteRole(db *gorm.DB) fiber.Handler {
	svc := services.NewRoleService(db)
	return func(c *fiber.Ctx) error {
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid role id",
				"code":  "VALIDATION_ERROR",
			})
		}
		if err := svc.Delete(c.Context(), id); err != nil {
			if errors.Is(err, rbacerrors.ErrRoleNotFound) {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "role not found",
					"code":  "NOT_FOUND",
				})
			}
			if errors.Is(err, rbacerrors.ErrSystemRoleProtected) {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": err.Error(),
					"code":  "FORBIDDEN",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to delete role",
				"code":  "INTERNAL_ERROR",
			})
		}
		return c.SendStatus(fiber.StatusNoContent)
	}
}
