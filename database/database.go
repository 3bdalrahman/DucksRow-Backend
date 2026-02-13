package database

import (
	"fmt"
	"log"
	"os"

	"ducksrow/backend/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Connect opens a connection to PostgreSQL and returns a GORM DB instance.
func Connect() (*gorm.DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = buildDSN()
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("gorm open: %w", err)
	}
	return db, nil
}

func buildDSN() string {
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "postgres")
	pass := getEnv("DB_PASSWORD", "postgres")
	dbname := getEnv("DB_NAME", "ducksrow")
	sslmode := getEnv("DB_SSLMODE", "disable")
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, pass, dbname, sslmode)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Migrate enables the PostGIS extension when available, then runs GORM AutoMigrate.
// If PostGIS is not installed, migration continues without it (Place uses latitude/longitude columns).
func Migrate(db *gorm.DB) error {
	if err := enablePostGIS(db); err != nil {
		// PostGIS not available (e.g. not installed); log and continue. Place model uses lat/lon columns.
		log.Printf("PostGIS extension not available (optional): %v", err)
	}
	if err := models.MigrateAll(db); err != nil {
		return fmt.Errorf("migrate models: %w", err)
	}
	return nil
}

// enablePostGIS runs "CREATE EXTENSION IF NOT EXISTS postgis". Returns error if extension is not available.
func enablePostGIS(db *gorm.DB) error {
	return db.Exec("CREATE EXTENSION IF NOT EXISTS postgis").Error
}
