package models

import "gorm.io/gorm"

// MigrateAll runs GORM AutoMigrate for all models in the correct order
// (respecting foreign key dependencies).
func MigrateAll(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&PlaceType{},
		&Place{},
		&Plan{},
		&PlanItem{},
	)
}
