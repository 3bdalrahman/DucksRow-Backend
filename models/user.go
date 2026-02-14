package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID           uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	Username     string         `gorm:"size:100;not null;index" json:"username"`
	Name         string         `gorm:"size:100;not null;index;default:''" json:"name"`
	Name_local   string         `gorm:"size:100;not null;index;default:''" json:"name_local"`
	DateOfBirth  time.Time      `gorm:"not null;index;default:1970-01-01 00:00:00" json:"date_of_birth"`
	Gender       string         `gorm:"size:50;not null;index;default:''" json:"gender"`
	Email        string         `gorm:"size:255;not null;uniqueIndex" json:"email"`
	PasswordHash string         `gorm:"size:255;not null" json:"-"`
	AvatarURL    string         `gorm:"size:512" json:"avatar_url,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`

	Places []Place `gorm:"foreignKey:OwnerID" json:"-"`
	Plans  []Plan  `gorm:"foreignKey:CreatorID" json:"-"`

	// Roles are assigned via user_roles (RBAC). Use Preload("Roles") to load.
	Roles []Role `gorm:"many2many:user_roles;foreignKey:ID;joinForeignKey:UserID;References:ID;joinReferences:RoleID" json:"-"`
}

// TableName overrides the table name.
func (User) TableName() string {
	return "users"
}

// BeforeCreate ensures ID is set (roles are assigned via user_roles).
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}
