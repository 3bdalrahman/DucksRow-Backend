package errors

import "errors"

// RBAC sentinel errors for handlers to map to HTTP status and code.
var (
	ErrRoleNotFound        = errors.New("role not found")
	ErrUserNotFound        = errors.New("user not found")
	ErrAssignmentNotFound  = errors.New("user role assignment not found")
	ErrPermissionInvalid   = errors.New("permission not in catalog")
	ErrSystemRoleProtected = errors.New("system role cannot be deleted or have permissions reduced")
	ErrRoleSlugConflict    = errors.New("role slug already exists")
	ErrRoleNameConflict    = errors.New("role name already exists")
	ErrForbidden           = errors.New("insufficient permissions")
	ErrValidation          = errors.New("validation error")
	ErrConflict            = errors.New("resource already exists")
	ErrUnauthorized        = errors.New("invalid credentials")
)

// HTTPStatusAndCode returns (statusCode, machineCode) for the standard error envelope.
// Returns (500, "INTERNAL_ERROR") if err is nil or unknown.
func HTTPStatusAndCode(err error) (int, string) {
	if err == nil {
		return 500, "INTERNAL_ERROR"
	}
	switch {
	case errors.Is(err, ErrRoleNotFound), errors.Is(err, ErrUserNotFound), errors.Is(err, ErrAssignmentNotFound):
		return 404, "NOT_FOUND"
	case errors.Is(err, ErrValidation):
		return 400, "VALIDATION_ERROR"
	case errors.Is(err, ErrUnauthorized):
		return 401, "UNAUTHORIZED"
	case errors.Is(err, ErrPermissionInvalid):
		return 422, "UNPROCESSABLE"
	case errors.Is(err, ErrSystemRoleProtected), errors.Is(err, ErrForbidden):
		return 403, "FORBIDDEN"
	case errors.Is(err, ErrRoleSlugConflict), errors.Is(err, ErrRoleNameConflict), errors.Is(err, ErrConflict):
		return 409, "CONFLICT"
	default:
		return 500, "INTERNAL_ERROR"
	}
}
