package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AuditAction is assign or remove.
const (
	AuditActionAssign = "assign"
	AuditActionRemove = "remove"
)

// RoleAuditLog records each role-assignment change (append-only).
// role_id is not a FK so the record survives role deletion.
type RoleAuditLog struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ActorID      uuid.UUID `gorm:"type:uuid;not null;index:idx_role_audit_target_user" json:"actor_id"`
	Action       string    `gorm:"size:20;not null" json:"action"` // assign | remove
	TargetUserID uuid.UUID `gorm:"type:uuid;not null;index:idx_role_audit_target_user" json:"target_user_id"`
	RoleID       uuid.UUID `gorm:"type:uuid;not null" json:"role_id"`
	RoleSlug     string    `gorm:"size:100;not null" json:"role_slug"`
	CreatedAt    time.Time `gorm:"index:idx_role_audit_created_at" json:"created_at"`
}

// TableName overrides the table name.
func (RoleAuditLog) TableName() string {
	return "role_audit_logs"
}

// BeforeCreate sets ID and CreatedAt if not set.
func (ral *RoleAuditLog) BeforeCreate(tx *gorm.DB) error {
	if ral.ID == uuid.Nil {
		ral.ID = uuid.New()
	}
	if ral.CreatedAt.IsZero() {
		ral.CreatedAt = time.Now()
	}
	return nil
}
