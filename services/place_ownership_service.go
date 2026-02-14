package services

import (
	"context"

	"ducksrow/backend/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PlaceOwnershipService checks place ownership for the RBAC ownership guard.
type PlaceOwnershipService struct {
	db *gorm.DB
}

// NewPlaceOwnershipService returns a PlaceOwnershipService using the given DB.
func NewPlaceOwnershipService(db *gorm.DB) *PlaceOwnershipService {
	return &PlaceOwnershipService{db: db}
}

// IsOwner returns true if the given user owns the place identified by placeID.
// A place with no owner (OwnerID nil) is not owned by any user.
func (s *PlaceOwnershipService) IsOwner(ctx context.Context, placeID, userID uuid.UUID) (bool, error) {
	var place models.Place
	if err := s.db.WithContext(ctx).Select("owner_id").Where("id = ?", placeID).First(&place).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, err
	}
	if place.OwnerID == nil {
		return false, nil
	}
	return *place.OwnerID == userID, nil
}
