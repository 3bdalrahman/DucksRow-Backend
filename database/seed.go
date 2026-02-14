package database

import (
	"log"
	"os"

	"ducksrow/backend/models"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// SeedAdmin creates a super admin user if ADMIN_EMAIL is set and no admin with that email exists.
// Password is taken from ADMIN_PASSWORD. Assigns the "admin" role via user_roles. Safe to call on every startup.
func SeedAdmin(db *gorm.DB) error {
	email := os.Getenv("ADMIN_EMAIL")
	password := os.Getenv("ADMIN_PASSWORD")
	if email == "" || password == "" {
		log.Println("SeedAdmin: ADMIN_EMAIL and ADMIN_PASSWORD not set, skipping admin seed")
		return nil
	}
	var existing models.User
	err := db.Where("email = ?", email).First(&existing).Error
	if err == nil {
		// User exists; ensure they have admin role
		var adminRole models.Role
		if err := db.Where("slug = ?", "admin").First(&adminRole).Error; err != nil {
			return err
		}
		var ur models.UserRole
		if err := db.Where("user_id = ? AND role_id = ?", existing.ID, adminRole.ID).First(&ur).Error; err == nil {
			log.Println("SeedAdmin: admin already exists for", email)
			return nil
		}
		if err != gorm.ErrRecordNotFound {
			return err
		}
		ur = models.UserRole{UserID: existing.ID, RoleID: adminRole.ID}
		if err := db.Create(&ur).Error; err != nil {
			return err
		}
		log.Println("SeedAdmin: assigned admin role to existing user", email)
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
		Name:         "admin",
		Name_local:   "admin",
	}
	if err := db.Create(&admin).Error; err != nil {
		return err
	}
	var adminRole models.Role
	if err := db.Where("slug = ?", "admin").First(&adminRole).Error; err != nil {
		return err
	}
	ur := models.UserRole{UserID: admin.ID, RoleID: adminRole.ID}
	if err := db.Create(&ur).Error; err != nil {
		return err
	}
	log.Println("SeedAdmin: created super admin for", email)
	return nil
}
