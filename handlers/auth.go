package handlers

import (
	"context"
	"time"

	rbacerrors "ducksrow/backend/errors"
	"ducksrow/backend/middleware"
	"ducksrow/backend/models"
	"ducksrow/backend/services"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// authService is the interface the auth handlers depend on (consumer-side, per constitution).
type authService interface {
	RegisterUser(ctx context.Context, username, email, passwordHash string) (*models.User, []string, error)
	AuthenticateUser(ctx context.Context, email, password string) (*models.User, []string, error)
}

// Ensure authService is implemented by *services.AuthService (compile-time check).
var _ authService = (*services.AuthService)(nil)

// RegisterRequest is the JSON body for registration.
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest is the JSON body for login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthResponse is returned on login/register with token, user, and role slugs.
type AuthResponse struct {
	Token string       `json:"token"`
	User  *models.User `json:"user"`
	Roles []string     `json:"roles"`
}

// Register hashes the password and delegates to AuthService; returns token and user with roles.
func Register(svc authService, secret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req RegisterRequest
		if err := c.BodyParser(&req); err != nil {
			return RespondError(c, rbacerrors.ErrValidation)
		}
		if req.Username == "" || req.Email == "" || req.Password == "" {
			return RespondError(c, rbacerrors.ErrValidation)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to hash password", "code": "INTERNAL_ERROR"})
		}
		user, roles, err := svc.RegisterUser(c.Context(), req.Username, req.Email, string(hash))
		if err != nil {
			return RespondError(c, err)
		}
		token, err := issueJWT(secret, user.ID.String(), user.Email)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create token", "code": "INTERNAL_ERROR"})
		}
		return c.Status(fiber.StatusCreated).JSON(AuthResponse{Token: token, User: user, Roles: roles})
	}
}

// Login verifies credentials via AuthService and returns token and user with roles.
func Login(svc authService, secret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req LoginRequest
		if err := c.BodyParser(&req); err != nil {
			return RespondError(c, rbacerrors.ErrValidation)
		}
		if req.Email == "" || req.Password == "" {
			return RespondError(c, rbacerrors.ErrValidation)
		}
		user, roles, err := svc.AuthenticateUser(c.Context(), req.Email, req.Password)
		if err != nil {
			return RespondError(c, err)
		}
		token, err := issueJWT(secret, user.ID.String(), user.Email)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create token", "code": "INTERNAL_ERROR"})
		}
		return c.JSON(AuthResponse{Token: token, User: user, Roles: roles})
	}
}

// Logout is handled client-side by discarding the token.
func Logout() fiber.Handler {
	return func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "logged out; discard token on client"})
	}
}

func issueJWT(secret string, userID string, email string) (string, error) {
	claims := &middleware.JWTClaims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
