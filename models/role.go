package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Role is a named grouping of permissions (e.g. viewer, editor, admin).
type Role struct {
	ID        uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	Slug      string         `gorm:"size:100;not null;uniqueIndex:idx_roles_slug,where:deleted_at IS NULL" json:"slug"`
	Name      string         `gorm:"size:255;not null;uniqueIndex:idx_roles_name,where:deleted_at IS NULL" json:"name"`
	IsSystem  bool           `gorm:"not null;default:false" json:"is_system"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName overrides the table name.
func (Role) TableName() string {
	return "roles"
}

// BeforeCreate sets ID if not set.
func (r *Role) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}
