package database

import (
	"log"

	"ducksrow/backend/models"
	"ducksrow/backend/permissions"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SeedRBAC creates default roles (admin, editor, client, owner), their permissions, and assigns default roles to users.
// Safe to call on every startup (idempotent). Call after Migrate and after SeedAdmin.
func SeedRBAC(db *gorm.DB) error {
	admin, err := ensureRole(db, "admin", "Administrator", true)
	if err != nil {
		return err
	}
	editor, err := ensureRole(db, "editor", "Editor", false)
	if err != nil {
		return err
	}
	client, err := ensureRole(db, "client", "Client", false)
	if err != nil {
		return err
	}
	owner, err := ensureRole(db, "owner", "Owner", false)
	if err != nil {
		return err
	}

	if err := ensureRolePermissions(db, admin.ID, permissions.AllKeys()); err != nil {
		return err
	}
	editorPerms := []string{
		permissions.PlacesRead, permissions.PlacesWrite,
		permissions.PlaceTypesRead, permissions.PlaceTypesWrite,
		permissions.PlansRead, permissions.PlansWrite,
		permissions.UsersRead,
	}
	if err := ensureRolePermissions(db, editor.ID, editorPerms); err != nil {
		return err
	}
	clientPerms := []string{
		permissions.PlacesRead, permissions.PlaceTypesRead,
		permissions.PlansRead, permissions.PlansWrite, permissions.PlansDelete,
	}
	if err := ensureRolePermissions(db, client.ID, clientPerms); err != nil {
		return err
	}
	ownerPerms := []string{
		permissions.PlacesRead, permissions.PlacesOwn, permissions.PlaceTypesRead,
	}
	if err := ensureRolePermissions(db, owner.ID, ownerPerms); err != nil {
		return err
	}

	if err := assignDefaultRoles(db, admin.ID, client.ID); err != nil {
		return err
	}
	return nil
}

func ensureRole(db *gorm.DB, slug, name string, isSystem bool) (*models.Role, error) {
	var r models.Role
	err := db.Where("slug = ?", slug).FirstOrCreate(&r, models.Role{
		Slug:     slug,
		Name:     name,
		IsSystem: isSystem,
	}).Error
	return &r, err
}

func ensureRolePermissions(db *gorm.DB, roleID uuid.UUID, perms []string) error {
	for _, p := range perms {
		rp := models.RolePermission{RoleID: roleID, Permission: p}
		if err := db.Where("role_id = ? AND permission = ?", roleID, p).FirstOrCreate(&rp).Error; err != nil {
			return err
		}
	}
	return nil
}

// assignDefaultRoles assigns admin role to users with legacy role column = 'admin', and client role to users with no roles.
func assignDefaultRoles(db *gorm.DB, adminRoleID, clientRoleID uuid.UUID) error {
	// Backward compat: users table may still have role column; assign admin role to those with role = 'admin'
	var legacyAdminIDs []uuid.UUID
	if err := db.Raw("SELECT id FROM users WHERE role = ?", "admin").Scan(&legacyAdminIDs).Error; err != nil {
		// Column might not exist in some environments
		log.Println("SeedRBAC: skip legacy admin assign", err)
	} else {
		for _, uid := range legacyAdminIDs {
			ur := models.UserRole{UserID: uid, RoleID: adminRoleID}
			_ = db.Where("user_id = ? AND role_id = ?", uid, adminRoleID).FirstOrCreate(&ur).Error
		}
	}
	// Assign client to any user with zero roles
	var userIDs []uuid.UUID
	if err := db.Raw(`
		SELECT u.id FROM users u
		LEFT JOIN user_roles ur ON ur.user_id = u.id
		WHERE ur.id IS NULL
	`).Scan(&userIDs).Error; err != nil {
		return err
	}
	n := 0
	for _, uid := range userIDs {
		ur := models.UserRole{UserID: uid, RoleID: clientRoleID}
		if err := db.Where("user_id = ? AND role_id = ?", uid, clientRoleID).FirstOrCreate(&ur).Error; err != nil {
			return err
		}
		n++
	}
	if n > 0 {
		log.Printf("SeedRBAC: assigned client role to %d user(s) with no roles", n)
	}
	return nil
}
