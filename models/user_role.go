package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserRole assigns a role to a user (join table).
type UserRole struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_user_roles_user_role" json:"user_id"`
	RoleID    uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_user_roles_user_role" json:"role_id"`
	CreatedAt time.Time `json:"created_at"`
}

// TableName overrides the table name.
func (UserRole) TableName() string {
	return "user_roles"
}

// BeforeCreate sets ID if not set.
func (ur *UserRole) BeforeCreate(tx *gorm.DB) error {
	if ur.ID == uuid.Nil {
		ur.ID = uuid.New()
	}
	return nil
}
