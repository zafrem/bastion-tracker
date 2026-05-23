// Package auth provides JWT generation and validation for Bastion-Tracker.
package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const DefaultExpiry = 24 * time.Hour

// Claims are the JWT payload fields Tracker uses.
type Claims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"` // admin, operator, viewer
	jwt.RegisteredClaims
}

// GenerateToken creates a signed HS256 JWT for the given user and role.
func GenerateToken(userID, role, secret string, expiry time.Duration) (string, error) {
	if expiry <= 0 {
		expiry = DefaultExpiry
	}
	claims := &Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

// ValidateToken parses and validates a JWT string, returning its claims.
func ValidateToken(tokenStr, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// RoleLevel maps a role string to a numeric level for hierarchical comparison.
// admin (3) > operator (2) > viewer (1) > unknown (0)
func RoleLevel(role string) int {
	switch role {
	case "admin":
		return 3
	case "operator":
		return 2
	case "viewer":
		return 1
	default:
		return 0
	}
}
