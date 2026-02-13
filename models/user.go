package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserRole is the role for RBAC.
const (
	RoleUser  = "user"
	RoleAdmin = "admin"
)

type User struct {
	ID           uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	Username     string         `gorm:"size:100;not null;index" json:"username"`
	Email        string         `gorm:"size:255;not null;uniqueIndex" json:"email"`
	PasswordHash string         `gorm:"size:255;not null" json:"-"`
	AvatarURL    string         `gorm:"size:512" json:"avatar_url,omitempty"`
	Role         string         `gorm:"size:50;not null;default:user" json:"role"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`

	Places []Place `gorm:"foreignKey:OwnerID" json:"-"`
	Plans  []Plan  `gorm:"foreignKey:CreatorID" json:"-"`
}

// TableName overrides the table name.
func (User) TableName() string {
	return "users"
}

// BeforeCreate ensures ID and default Role are set.
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	if u.Role == "" {
		u.Role = RoleUser
	}
	return nil
}
