package handlers

import (
	"strconv"

	"ducksrow/backend/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AuditEntryDTO is one audit log entry for GET /api/roles/audit.
type AuditEntryDTO struct {
	ID         uuid.UUID    `json:"id"`
	Actor      ActorTarget  `json:"actor"`
	Action     string       `json:"action"`
	TargetUser ActorTarget  `json:"target_user"`
	Role       AuditRoleDTO `json:"role"`
	CreatedAt  string       `json:"created_at"`
}

// ActorTarget is { id, name } for actor or target_user.
type ActorTarget struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// AuditRoleDTO is { id, slug, name } for the role in audit.
type AuditRoleDTO struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
	Name string    `json:"name"`
}

// ListRoleAudit returns GET /api/roles/audit — paginated audit log.
func ListRoleAudit(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		page, _ := strconv.Atoi(c.Query("page", "1"))
		if page < 1 {
			page = 1
		}
		limit, _ := strconv.Atoi(c.Query("limit", "20"))
		if limit < 1 {
			limit = 20
		}
		if limit > 100 {
			limit = 100
		}
		userIDStr := c.Query("user_id")
		roleIDStr := c.Query("role_id")
		action := c.Query("action")

		q := db.Model(&models.RoleAuditLog{}).Order("created_at DESC")
		if userIDStr != "" {
			uid, err := uuid.Parse(userIDStr)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "invalid user_id",
					"code":  "VALIDATION_ERROR",
				})
			}
			q = q.Where("target_user_id = ?", uid)
		}
		if roleIDStr != "" {
			rid, err := uuid.Parse(roleIDStr)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "invalid role_id",
					"code":  "VALIDATION_ERROR",
				})
			}
			q = q.Where("role_id = ?", rid)
		}
		if action != "" {
			if action != models.AuditActionAssign && action != models.AuditActionRemove {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "action must be assign or remove",
					"code":  "VALIDATION_ERROR",
				})
			}
			q = q.Where("action = ?", action)
		}

		var total int64
		if err := q.Count(&total).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to count audit log",
				"code":  "INTERNAL_ERROR",
			})
		}
		offset := (page - 1) * limit
		var logs []models.RoleAuditLog
		if err := q.Offset(offset).Limit(limit).Find(&logs).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to list audit log",
				"code":  "INTERNAL_ERROR",
			})
		}

		// Load actor and target user names, and role names
		actorIDs := make(map[uuid.UUID]bool)
		targetIDs := make(map[uuid.UUID]bool)
		roleIDs := make(map[uuid.UUID]bool)
		for _, l := range logs {
			actorIDs[l.ActorID] = true
			targetIDs[l.TargetUserID] = true
			roleIDs[l.RoleID] = true
		}
		users := make(map[uuid.UUID]string) // id -> name
		var userList []models.User
		allIDs := make([]uuid.UUID, 0, len(actorIDs)+len(targetIDs))
		for id := range actorIDs {
			allIDs = append(allIDs, id)
		}
		for id := range targetIDs {
			allIDs = append(allIDs, id)
		}
		if len(allIDs) > 0 {
			if err := db.Where("id IN ?", allIDs).Find(&userList).Error; err == nil {
				for i := range userList {
					users[userList[i].ID] = userList[i].Name
				}
			}
		}
		roles := make(map[uuid.UUID]string) // id -> name
		var roleList []models.Role
		rids := make([]uuid.UUID, 0, len(roleIDs))
		for id := range roleIDs {
			rids = append(rids, id)
		}
		if len(rids) > 0 {
			if err := db.Where("id IN ?", rids).Find(&roleList).Error; err == nil {
				for i := range roleList {
					roles[roleList[i].ID] = roleList[i].Name
				}
			}
		}

		data := make([]AuditEntryDTO, len(logs))
		for i, l := range logs {
			data[i] = AuditEntryDTO{
				ID:         l.ID,
				Action:     l.Action,
				Actor:      ActorTarget{ID: l.ActorID, Name: users[l.ActorID]},
				TargetUser: ActorTarget{ID: l.TargetUserID, Name: users[l.TargetUserID]},
				Role: AuditRoleDTO{
					ID:   l.RoleID,
					Slug: l.RoleSlug,
					Name: roles[l.RoleID],
				},
				CreatedAt: l.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			}
		}
		return c.JSON(fiber.Map{
			"data": data,
			"meta": fiber.Map{
				"page":  page,
				"limit": limit,
				"total": total,
			},
		})
	}
}
