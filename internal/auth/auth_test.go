package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// makeExpiredToken creates a JWT whose ExpiresAt is 2 hours in the past.
// Used to test expiry rejection without triggering GenerateToken's guard.
func makeExpiredToken(userID, role, secret string) string {
	claims := &Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-3 * time.Hour)),
			Subject:   userID,
		},
	}
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	return tok
}

func TestGenerateAndValidate_RoundTrip(t *testing.T) {
	token, err := GenerateToken("alice", "admin", "secret", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := ValidateToken(token, "secret")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.UserID != "alice" {
		t.Errorf("expected user alice, got %s", claims.UserID)
	}
	if claims.Role != "admin" {
		t.Errorf("expected role admin, got %s", claims.Role)
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	token, _ := GenerateToken("alice", "viewer", "secret", time.Hour)
	_, err := ValidateToken(token, "wrong-secret")
	if err == nil {
		t.Error("expected error with wrong secret")
	}
}

func TestValidateToken_Expired(t *testing.T) {
	// Build an expired JWT directly; GenerateToken rejects non-positive durations.
	token := makeExpiredToken("alice", "viewer", "secret")
	_, err := ValidateToken(token, "secret")
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestRefreshToken_IssuedWithSameRole(t *testing.T) {
	original, _ := GenerateToken("bob", "operator", "secret", time.Hour)
	newToken, claims, err := RefreshToken(original, "secret", 2*time.Hour)
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if newToken == original {
		t.Error("refreshed token should differ from original")
	}
	if claims.UserID != "bob" {
		t.Errorf("expected user bob, got %s", claims.UserID)
	}
	if claims.Role != "operator" {
		t.Errorf("expected operator, got %s", claims.Role)
	}
}

func TestRefreshToken_ExpiredTokenRejected(t *testing.T) {
	expired := makeExpiredToken("alice", "viewer", "secret")
	_, _, err := RefreshToken(expired, "secret", time.Hour)
	if err == nil {
		t.Error("RefreshToken should reject an expired token")
	}
}

func TestRefreshToken_WrongSecret(t *testing.T) {
	token, _ := GenerateToken("alice", "viewer", "secret", time.Hour)
	_, _, err := RefreshToken(token, "other-secret", time.Hour)
	if err == nil {
		t.Error("RefreshToken should reject wrong secret")
	}
}

func TestRoleLevel_Ordering(t *testing.T) {
	if RoleLevel("admin") <= RoleLevel("operator") {
		t.Error("admin should outrank operator")
	}
	if RoleLevel("operator") <= RoleLevel("viewer") {
		t.Error("operator should outrank viewer")
	}
	if RoleLevel("viewer") <= RoleLevel("unknown") {
		t.Error("viewer should outrank unknown")
	}
}

func TestRoleLevel_UnknownRole(t *testing.T) {
	if RoleLevel("superuser") != 0 {
		t.Error("unknown role should return 0")
	}
}

func TestGenerateToken_DefaultExpiry(t *testing.T) {
	// Zero expiry should use DefaultExpiry (no error).
	token, err := GenerateToken("alice", "viewer", "secret", 0)
	if err != nil {
		t.Fatalf("zero expiry should use default: %v", err)
	}
	claims, err := ValidateToken(token, "secret")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.UserID != "alice" {
		t.Errorf("unexpected user: %s", claims.UserID)
	}
}
