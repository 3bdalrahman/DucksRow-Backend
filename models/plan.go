package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PlanVisibility represents who can see the plan.
type PlanVisibility string

const (
	VisibilityPublic  PlanVisibility = "Public"
	VisibilityPrivate PlanVisibility = "Private"
)

type Plan struct {
	ID          uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	Title       string         `gorm:"size:255;not null" json:"title"`
	Description string         `gorm:"type:text" json:"description"`
	CreatorID   uuid.UUID      `gorm:"type:uuid;not null;index" json:"creator_id"`
	Visibility  PlanVisibility `gorm:"type:varchar(20);default:'Public'" json:"visibility"`
	IsTemplate  bool           `gorm:"default:false" json:"is_template"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`

	Creator   User       `gorm:"foreignKey:CreatorID" json:"creator,omitempty"`
	PlanItems []PlanItem `gorm:"foreignKey:PlanID" json:"plan_items,omitempty"`
}

// TableName overrides the table name.
func (Plan) TableName() string {
	return "plans"
}

// BeforeCreate ensures ID is set.
func (p *Plan) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}
