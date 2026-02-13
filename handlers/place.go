package handlers

import (
	"ducksrow/backend/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CreatePlaceRequest is the JSON body for creating a place (includes JSONB details).
type CreatePlaceRequest struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Address     string                 `json:"address"`
	Lat         float64                `json:"lat"`
	Lon         float64                `json:"lon"`
	Details     map[string]interface{} `json:"details"`
	PlaceTypeID string                 `json:"place_type_id"` // UUID string
	IsVerified  bool                   `json:"is_verified"`
}

// CreatePlace creates a new place with dynamic Details (JSONB).
func CreatePlace(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req CreatePlaceRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
		}
		placeTypeID, err := uuid.Parse(req.PlaceTypeID)
		if err != nil || req.Name == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name and valid place_type_id (UUID) required"})
		}
		var ownerID *uuid.UUID
		if uid, ok := c.Locals("userID").(uuid.UUID); ok && uid != uuid.Nil {
			ownerID = &uid
		}
		place := models.Place{
			Name:        req.Name,
			Description: req.Description,
			Address:     req.Address,
			Latitude:    req.Lat,
			Longitude:   req.Lon,
			Details:     models.DetailsJSON(req.Details),
			PlaceTypeID: placeTypeID,
			OwnerID:     ownerID,
			IsVerified:  req.IsVerified,
		}
		if err := db.Create(&place).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusCreated).JSON(place)
	}
}
