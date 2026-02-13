package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// FormSchemaJSON holds the dynamic form definition for a PlaceType (JSONB).
type FormSchemaJSON map[string]interface{}

// Value implements driver.Valuer for GORM JSONB.
func (j FormSchemaJSON) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan implements sql.Scanner for GORM JSONB.
func (j *FormSchemaJSON) Scan(value interface{}) error {
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
		return errors.New("form_schema: unsupported type")
	}
	return json.Unmarshal(b, j)
}

type PlaceType struct {
	ID         uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	Name       string         `gorm:"size:100;not null;uniqueIndex" json:"name"`
	Slug       string         `gorm:"size:100;not null;uniqueIndex" json:"slug"`
	FormSchema FormSchemaJSON `gorm:"type:jsonb" json:"form_schema"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`

	Places []Place `gorm:"foreignKey:PlaceTypeID" json:"-"`
}

// TableName overrides the table name.
func (PlaceType) TableName() string {
	return "place_types"
}

// BeforeCreate ensures ID is set.
func (p *PlaceType) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}
