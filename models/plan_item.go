package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SelectedOptionsJSON stores user choices from the dynamic menu (JSONB).
type SelectedOptionsJSON map[string]interface{}

// Value implements driver.Valuer for GORM JSONB.
func (j SelectedOptionsJSON) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan implements sql.Scanner for GORM JSONB.
func (j *SelectedOptionsJSON) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	var b []byte
	switch v := value.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return errors.New("selected_options: unsupported type")
	}
	return json.Unmarshal(b, j)
}

type PlanItem struct {
	ID              uuid.UUID           `gorm:"type:uuid;primaryKey" json:"id"`
	PlanID          uuid.UUID           `gorm:"type:uuid;not null;index" json:"plan_id"`
	PlaceID         uuid.UUID           `gorm:"type:uuid;not null;index" json:"place_id"`
	Order           int                 `gorm:"not null;default:0" json:"order"`
	StartTime       *time.Time          `json:"start_time,omitempty"`
	SelectedOptions SelectedOptionsJSON `gorm:"type:jsonb" json:"selected_options"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
	DeletedAt       gorm.DeletedAt      `gorm:"index" json:"-"`

	Plan  Plan  `gorm:"foreignKey:PlanID" json:"-"`
	Place Place `gorm:"foreignKey:PlaceID" json:"place,omitempty"`
}

// TableName overrides the table name.
func (PlanItem) TableName() string {
	return "plan_items"
}

// BeforeCreate ensures ID is set.
func (p *PlanItem) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}
