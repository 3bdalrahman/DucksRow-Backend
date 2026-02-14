package services

import (
	"context"
	"strings"

	"ducksrow/backend/errors"
	"ducksrow/backend/models"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// AuthService handles auth-related business logic (registration, login, role slugs).
type AuthService struct {
	db *gorm.DB
}

// NewAuthService returns an AuthService using the given DB.
func NewAuthService(db *gorm.DB) *AuthService {
	return &AuthService{db: db}
}

// RegisterUser creates a user, assigns the "client" role, and returns the user and role slugs.
// Returns errors.ErrConflict if email or username already exists.
func (s *AuthService) RegisterUser(ctx context.Context, username, email, passwordHash string) (*models.User, []string, error) {
	user := models.User{
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
		Name:         username,
		Name_local:   username,
	}
	if err := s.db.WithContext(ctx).Create(&user).Error; err != nil {
		if isUniqueViolation(err) {
			return nil, nil, errors.ErrConflict
		}
		return nil, nil, err
	}
	// Assign client role
	var clientRole models.Role
	if err := s.db.WithContext(ctx).Where("slug = ?", "client").First(&clientRole).Error; err != nil {
		return nil, nil, err
	}
	ur := models.UserRole{UserID: user.ID, RoleID: clientRole.ID}
	if err := s.db.WithContext(ctx).Create(&ur).Error; err != nil {
		return nil, nil, err
	}
	slugs, err := s.UserRoleSlugs(ctx, user.ID)
	if err != nil {
		return &user, []string{"client"}, nil // best effort
	}
	return &user, slugs, nil
}

// AuthenticateUser verifies credentials and returns the user and their role slugs.
// Returns errors.ErrUserNotFound if email not found or password invalid.
func (s *AuthService) AuthenticateUser(ctx context.Context, email, password string) (*models.User, []string, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil, errors.ErrUnauthorized
		}
		return nil, nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, nil, errors.ErrUnauthorized
	}
	slugs, err := s.UserRoleSlugs(ctx, user.ID)
	if err != nil {
		return &user, nil, err
	}
	return &user, slugs, nil
}

// UserRoleSlugs loads the RBAC role slugs for a user.
func (s *AuthService) UserRoleSlugs(ctx context.Context, userID uuid.UUID) ([]string, error) {
	var slugs []string
	err := s.db.WithContext(ctx).Table("user_roles").
		Select("roles.slug").
		Joins("JOIN roles ON roles.id = user_roles.role_id AND roles.deleted_at IS NULL").
		Where("user_roles.user_id = ?", userID).
		Pluck("roles.slug", &slugs).Error
	return slugs, err
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "duplicate key") ||
		strings.Contains(err.Error(), "unique constraint") ||
		strings.Contains(err.Error(), "23505")
}
