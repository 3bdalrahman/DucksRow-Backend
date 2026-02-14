package permissions

// Permission keys (fixed catalog). Use these when checking or assigning permissions.
const (
	PlacesRead      = "places:read"
	PlacesWrite     = "places:write"
	PlacesOwn       = "places:own" // can write only places owned by the user
	PlacesDelete    = "places:delete"
	PlaceTypesRead  = "place_types:read"
	PlaceTypesWrite = "place_types:write"
	PlansRead       = "plans:read"
	PlansWrite      = "plans:write"
	PlansDelete     = "plans:delete"
	UsersRead       = "users:read"
	UsersWrite      = "users:write"
	RolesManage     = "roles:manage"
)

// DTO is the response shape for one permission (key, resource, action, description).
type DTO struct {
	Key         string `json:"key"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

// All returns the full fixed permission catalog for GET /api/permissions.
func All() []DTO {
	return []DTO{
		{Key: PlacesRead, Resource: "places", Action: "read", Description: "View places"},
		{Key: PlacesWrite, Resource: "places", Action: "write", Description: "Create / edit places"},
		{Key: PlacesOwn, Resource: "places", Action: "own", Description: "Edit only places you own"},
		{Key: PlacesDelete, Resource: "places", Action: "delete", Description: "Delete places"},
		{Key: PlaceTypesRead, Resource: "place_types", Action: "read", Description: "View place types"},
		{Key: PlaceTypesWrite, Resource: "place_types", Action: "write", Description: "Create / edit place types"},
		{Key: PlansRead, Resource: "plans", Action: "read", Description: "View plans"},
		{Key: PlansWrite, Resource: "plans", Action: "write", Description: "Create / edit plans"},
		{Key: PlansDelete, Resource: "plans", Action: "delete", Description: "Delete plans"},
		{Key: UsersRead, Resource: "users", Action: "read", Description: "View user profiles"},
		{Key: UsersWrite, Resource: "users", Action: "write", Description: "Edit user profiles"},
		{Key: RolesManage, Resource: "roles", Action: "manage", Description: "Create, update, delete roles and assign roles to users"},
	}
}

// AllKeys returns all permission keys for validation and seeding.
func AllKeys() []string {
	return []string{
		PlacesRead, PlacesWrite, PlacesOwn, PlacesDelete,
		PlaceTypesRead, PlaceTypesWrite,
		PlansRead, PlansWrite, PlansDelete,
		UsersRead, UsersWrite,
		RolesManage,
	}
}

// IsValid returns true if key is in the fixed catalog.
func IsValid(key string) bool {
	for _, k := range AllKeys() {
		if k == key {
			return true
		}
	}
	return false
}
