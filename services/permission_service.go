package services

import (
	"context"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PermissionService checks whether a user has a given permission (via roles or admin).
type PermissionService struct {
	db *gorm.DB
}

// NewPermissionService returns a PermissionService using the given DB.
func NewPermissionService(db *gorm.DB) *PermissionService {
	return &PermissionService{db: db}
}

// HasPermission returns true if the user has the given permission (either via a role that has it, or via the admin role).
func (s *PermissionService) HasPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	var one int
	err := s.db.WithContext(ctx).Raw(
		`SELECT 1 FROM user_roles ur
		 JOIN roles r ON r.id = ur.role_id AND r.deleted_at IS NULL
		 LEFT JOIN role_permissions rp ON rp.role_id = ur.role_id
		 WHERE ur.user_id = ? AND (rp.permission = ? OR r.slug = 'admin')
		 LIMIT 1`,
		userID, permission,
	).Scan(&one).Error
	if err != nil {
		return false, err
	}
	return one == 1, nil
}
