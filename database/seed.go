package database

import (
	"log"
	"os"

	"ducksrow/backend/models"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// SeedAdmin creates a super admin user if ADMIN_EMAIL is set and no admin with that email exists.
// Password is taken from ADMIN_PASSWORD. Safe to call on every startup.
func SeedAdmin(db *gorm.DB) error {
	email := os.Getenv("ADMIN_EMAIL")
	password := os.Getenv("ADMIN_PASSWORD")
	if email == "" || password == "" {
		log.Println("SeedAdmin: ADMIN_EMAIL and ADMIN_PASSWORD not set, skipping admin seed")
		return nil
	}
	var existing models.User
	err := db.Where("email = ? AND role = ?", email, models.RoleAdmin).First(&existing).Error
	if err == nil {
		log.Println("SeedAdmin: admin already exists for", email)
		return nil
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	admin := models.User{
		Username:     "admin",
		Email:        email,
		PasswordHash: string(hash),
		Role:         models.RoleAdmin,
	}
	if err := db.Create(&admin).Error; err != nil {
		return err
	}
	log.Println("SeedAdmin: created super admin for", email)
	return nil
}
