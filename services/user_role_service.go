package services

import (
	"context"
	"time"

	"ducksrow/backend/errors"
	"ducksrow/backend/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserRoleService handles role assignment and listing.
type UserRoleService struct {
	db *gorm.DB
}

// NewUserRoleService returns a UserRoleService.
func NewUserRoleService(db *gorm.DB) *UserRoleService {
	return &UserRoleService{db: db}
}

// AssignResult is returned by Assign; Created is true when a new assignment was created.
type AssignResult struct {
	UserID     uuid.UUID
	RoleID     uuid.UUID
	RoleSlug   string
	RoleName   string
	AssignedAt string // ISO 8601
	Created    bool
}

// Assign assigns a role to a user. Idempotent; if already assigned, returns existing with Created=false.
// Appends an audit log entry on new assignment.
func (s *UserRoleService) Assign(ctx context.Context, actorID, targetUserID, roleID uuid.UUID) (*AssignResult, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("id = ?", targetUserID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.ErrUserNotFound
		}
		return nil, err
	}
	var role models.Role
	if err := s.db.WithContext(ctx).Where("id = ?", roleID).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.ErrRoleNotFound
		}
		return nil, err
	}
	var existingUR models.UserRole
	err := s.db.WithContext(ctx).Where("user_id = ? AND role_id = ?", targetUserID, roleID).First(&existingUR).Error
	if err == nil {
		return &AssignResult{
			UserID:     targetUserID,
			RoleID:     roleID,
			RoleSlug:   role.Slug,
			RoleName:   role.Name,
			AssignedAt: existingUR.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			Created:    false,
		}, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, err
	}
	ur := models.UserRole{UserID: targetUserID, RoleID: roleID}
	if err := s.db.WithContext(ctx).Create(&ur).Error; err != nil {
		return nil, err
	}
	audit := models.RoleAuditLog{
		ActorID:      actorID,
		Action:       models.AuditActionAssign,
		TargetUserID: targetUserID,
		RoleID:       roleID,
		RoleSlug:     role.Slug,
	}
	if err := s.db.WithContext(ctx).Create(&audit).Error; err != nil {
		return nil, err
	}
	return &AssignResult{
		UserID:     targetUserID,
		RoleID:     roleID,
		RoleSlug:   role.Slug,
		RoleName:   role.Name,
		AssignedAt: ur.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		Created:    true,
	}, nil
}

// Unassign removes a role from a user. Returns ErrAssignmentNotFound if not assigned.
// Appends an audit log entry.
func (s *UserRoleService) Unassign(ctx context.Context, actorID, targetUserID, roleID uuid.UUID) error {
	var ur models.UserRole
	if err := s.db.WithContext(ctx).Where("user_id = ? AND role_id = ?", targetUserID, roleID).First(&ur).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.ErrAssignmentNotFound
		}
		return err
	}
	var role models.Role
	if err := s.db.WithContext(ctx).Where("id = ?", roleID).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.ErrRoleNotFound
		}
		return err
	}
	if err := s.db.WithContext(ctx).Delete(&ur).Error; err != nil {
		return err
	}
	audit := models.RoleAuditLog{
		ActorID:      actorID,
		Action:       models.AuditActionRemove,
		TargetUserID: targetUserID,
		RoleID:       roleID,
		RoleSlug:     role.Slug,
	}
	return s.db.WithContext(ctx).Create(&audit).Error
}

// UserRoleListItem is one role assigned to a user (for ListForUser).
type UserRoleListItem struct {
	ID         uuid.UUID `json:"id"`
	Slug       string    `json:"slug"`
	Name       string    `json:"name"`
	IsSystem   bool      `json:"is_system"`
	AssignedAt string    `json:"assigned_at"` // ISO 8601
}

// ListForUser returns all roles assigned to the user with assigned_at.
func (s *UserRoleService) ListForUser(ctx context.Context, userID uuid.UUID) ([]UserRoleListItem, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.ErrUserNotFound
		}
		return nil, err
	}
	type row struct {
		ID        uuid.UUID
		Slug      string
		Name      string
		IsSystem  bool
		CreatedAt time.Time
	}
	var rows []row
	err := s.db.WithContext(ctx).Table("user_roles").
		Select("roles.id, roles.slug, roles.name, roles.is_system, user_roles.created_at").
		Joins("JOIN roles ON roles.id = user_roles.role_id AND roles.deleted_at IS NULL").
		Where("user_roles.user_id = ?", userID).
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	result := make([]UserRoleListItem, len(rows))
	for i, r := range rows {
		result[i] = UserRoleListItem{
			ID:         r.ID,
			Slug:       r.Slug,
			Name:       r.Name,
			IsSystem:   r.IsSystem,
			AssignedAt: r.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		}
	}
	return result, nil
}
