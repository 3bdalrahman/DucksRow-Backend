package handlers

import (
	rbacerrors "ducksrow/backend/errors"

	"github.com/gofiber/fiber/v2"
)

// RespondError maps a domain error to an HTTP response using the standard envelope.
// Uses the backend errors package to determine status and code; unknown errors return 500 INTERNAL_ERROR.
func RespondError(c *fiber.Ctx, err error) error {
	status, code := rbacerrors.HTTPStatusAndCode(err)
	return c.Status(status).JSON(fiber.Map{
		"error": err.Error(),
		"code":  code,
	})
}
