package models

import (
	"database/sql/driver"
	"fmt"
	"strconv"
	"strings"
)

// GeographyPoint represents a PostGIS geography(Point, 4326) (WGS84).
// Implements sql.Scanner and driver.Valuer for GORM.
type GeographyPoint struct {
	Lat float64
	Lon float64
}

// Value implements driver.Valuer. Returns EWKT for PostGIS.
// If your driver does not cast string to geography, set location via a separate
// Update using gorm.Expr("ST_GeomFromEWKT(?)", ewkt) after Create.
func (g GeographyPoint) Value() (driver.Value, error) {
	if g.Lat == 0 && g.Lon == 0 {
		return nil, nil
	}
	return fmt.Sprintf("SRID=4326;POINT(%f %f)", g.Lon, g.Lat), nil
}

// Scan implements sql.Scanner. Accepts WKT/EWKT or byte slice from PostGIS.
func (g *GeographyPoint) Scan(value interface{}) error {
	if value == nil {
		g.Lat, g.Lon = 0, 0
		return nil
	}
	var s string
	switch v := value.(type) {
	case []byte:
		s = string(v)
	case string:
		s = v
	default:
		return fmt.Errorf("geography: unsupported type %T", value)
	}
	s = strings.TrimSpace(s)
	// Strip SRID prefix if present
	if idx := strings.Index(s, ";"); idx != -1 {
		s = s[idx+1:]
	}
	s = strings.TrimPrefix(s, "POINT(")
	s = strings.TrimSuffix(s, ")")
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return fmt.Errorf("geography: invalid point format %q", s)
	}
	lon, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return err
	}
	lat, err := strconv.ParseFloat(parts[1], 64)
	if err != nil {
		return err
	}
	g.Lon = lon
	g.Lat = lat
	return nil
}
