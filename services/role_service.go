package services

import (
	"context"
	"regexp"

	"ducksrow/backend/errors"
	"ducksrow/backend/models"
	"ducksrow/backend/permissions"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Slug format: lowercase alphanumeric and hyphens only.
var slugRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$`)

// RoleService handles role CRUD and permission sets.
type RoleService struct {
	db *gorm.DB
}

// NewRoleService returns a RoleService.
func NewRoleService(db *gorm.DB) *RoleService {
	return &RoleService{db: db}
}

// RoleDTO is the response shape for a single role (with permissions).
type RoleDTO struct {
	ID          uuid.UUID `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	IsSystem    bool      `json:"is_system"`
	Permissions []string  `json:"permissions"`
	CreatedAt   string    `json:"created_at"`
	UpdatedAt   string    `json:"updated_at"`
}

// Create creates a new role with the given permissions. Validates slug/name and permission keys.
func (s *RoleService) Create(ctx context.Context, slug, name string, perms []string) (*RoleDTO, error) {
	if slug == "" || name == "" || len(perms) == 0 {
		return nil, errors.ErrValidation
	}
	if !slugRegex.MatchString(slug) {
		return nil, errors.ErrValidation
	}
	for _, p := range perms {
		if !permissions.IsValid(p) {
			return nil, errors.ErrPermissionInvalid
		}
	}
	var existing models.Role
	if err := s.db.WithContext(ctx).Where("slug = ?", slug).First(&existing).Error; err == nil {
		return nil, errors.ErrRoleSlugConflict
	}
	if err := s.db.WithContext(ctx).Where("name = ?", name).First(&existing).Error; err == nil {
		return nil, errors.ErrRoleNameConflict
	}
	role := models.Role{Slug: slug, Name: name, IsSystem: false}
	if err := s.db.WithContext(ctx).Create(&role).Error; err != nil {
		return nil, err
	}
	for _, p := range perms {
		rp := models.RolePermission{RoleID: role.ID, Permission: p}
		if err := s.db.WithContext(ctx).Create(&rp).Error; err != nil {
			return nil, err
		}
	}
	return s.getRoleDTO(ctx, &role, perms)
}

// GetByID returns a role by ID or ErrRoleNotFound.
func (s *RoleService) GetByID(ctx context.Context, id uuid.UUID) (*RoleDTO, error) {
	var role models.Role
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.ErrRoleNotFound
		}
		return nil, err
	}
	var perms []string
	if err := s.db.WithContext(ctx).Model(&models.RolePermission{}).Where("role_id = ?", role.ID).Pluck("permission", &perms).Error; err != nil {
		return nil, err
	}
	return s.getRoleDTO(ctx, &role, perms)
}

// List returns paginated roles with their permissions.
func (s *RoleService) List(ctx context.Context, page, limit int) ([]RoleDTO, int64, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	var total int64
	if err := s.db.WithContext(ctx).Model(&models.Role{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var roles []models.Role
	offset := (page - 1) * limit
	if err := s.db.WithContext(ctx).Offset(offset).Limit(limit).Find(&roles).Error; err != nil {
		return nil, 0, err
	}
	result := make([]RoleDTO, len(roles))
	for i := range roles {
		var perms []string
		_ = s.db.WithContext(ctx).Model(&models.RolePermission{}).Where("role_id = ?", roles[i].ID).Pluck("permission", &perms).Error
		dto, _ := s.getRoleDTO(ctx, &roles[i], perms)
		result[i] = *dto
	}
	return result, total, nil
}

// Update updates name and/or permissions. For system roles, permissions can only be added (superset).
func (s *RoleService) Update(ctx context.Context, id uuid.UUID, name *string, perms []string) (*RoleDTO, error) {
	var role models.Role
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.ErrRoleNotFound
		}
		return nil, err
	}
	if name != nil {
		var existing models.Role
		if err := s.db.WithContext(ctx).Where("name = ? AND id != ?", *name, id).First(&existing).Error; err == nil {
			return nil, errors.ErrRoleNameConflict
		}
		role.Name = *name
		if err := s.db.WithContext(ctx).Save(&role).Error; err != nil {
			return nil, err
		}
	}
	if perms != nil {
		for _, p := range perms {
			if !permissions.IsValid(p) {
				return nil, errors.ErrPermissionInvalid
			}
		}
		if role.IsSystem {
			var current []string
			if err := s.db.WithContext(ctx).Model(&models.RolePermission{}).Where("role_id = ?", id).Pluck("permission", &current).Error; err != nil {
				return nil, err
			}
			permSet := make(map[string]bool)
			for _, p := range perms {
				permSet[p] = true
			}
			for _, c := range current {
				if !permSet[c] {
					return nil, errors.ErrSystemRoleProtected
				}
			}
		}
		if err := s.db.WithContext(ctx).Where("role_id = ?", id).Delete(&models.RolePermission{}).Error; err != nil {
			return nil, err
		}
		for _, p := range perms {
			if err := s.db.WithContext(ctx).Create(&models.RolePermission{RoleID: id, Permission: p}).Error; err != nil {
				return nil, err
			}
		}
	}
	return s.GetByID(ctx, id)
}

// Delete soft-deletes a role. Rejects system roles.
func (s *RoleService) Delete(ctx context.Context, id uuid.UUID) error {
	var role models.Role
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.ErrRoleNotFound
		}
		return err
	}
	if role.IsSystem {
		return errors.ErrSystemRoleProtected
	}
	return s.db.WithContext(ctx).Delete(&role).Error
}

func (s *RoleService) getRoleDTO(ctx context.Context, role *models.Role, perms []string) (*RoleDTO, error) {
	return &RoleDTO{
		ID:          role.ID,
		Slug:        role.Slug,
		Name:        role.Name,
		IsSystem:    role.IsSystem,
		Permissions: perms,
		CreatedAt:   role.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		UpdatedAt:   role.UpdatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
	}, nil
}
