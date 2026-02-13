package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DetailsJSON holds dynamic attributes for a Place based on its PlaceType (JSONB).
type DetailsJSON map[string]interface{}

// Value implements driver.Valuer for GORM JSONB.
func (j DetailsJSON) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan implements sql.Scanner for GORM JSONB.
func (j *DetailsJSON) Scan(value interface{}) error {
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
		return errors.New("details: unsupported type")
	}
	return json.Unmarshal(b, j)
}

type Place struct {
	ID          uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	Name        string         `gorm:"size:255;not null" json:"name"`
	Description string         `gorm:"type:text" json:"description"`
	Address     string         `gorm:"size:512" json:"address"`
	Latitude    float64        `json:"latitude"`
	Longitude   float64        `json:"longitude"`
	Details     DetailsJSON    `gorm:"type:jsonb" json:"details"`
	PlaceTypeID uuid.UUID      `gorm:"type:uuid;not null;index" json:"place_type_id"`
	OwnerID     *uuid.UUID     `gorm:"type:uuid;index" json:"owner_id,omitempty"`
	IsVerified  bool           `gorm:"default:false" json:"is_verified"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`

	PlaceType *PlaceType `gorm:"foreignKey:PlaceTypeID" json:"place_type,omitempty"`
	Owner     *User      `gorm:"foreignKey:OwnerID" json:"owner,omitempty"`
}

// TableName overrides the table name.
func (Place) TableName() string {
	return "places"
}

// BeforeCreate ensures ID is set.
func (p *Place) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}
