package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RolePermission associates a role with a permission from the fixed catalog.
type RolePermission struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	RoleID     uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_role_permissions_role_perm" json:"role_id"`
	Permission string    `gorm:"size:100;not null;uniqueIndex:idx_role_permissions_role_perm;index:idx_role_permissions_permission" json:"permission"`
	CreatedAt  time.Time `json:"created_at"`
}

// TableName overrides the table name.
func (RolePermission) TableName() string {
	return "role_permissions"
}

// BeforeCreate sets ID if not set.
func (rp *RolePermission) BeforeCreate(tx *gorm.DB) error {
	if rp.ID == uuid.Nil {
		rp.ID = uuid.New()
	}
	return nil
}
