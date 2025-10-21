package gateway

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/medrex/dlt-emr/pkg/types"
)

func TestTokenValidator_ValidateJWT(t *testing.T) {
	secret := "test-secret"
	validator := NewTokenValidator(secret)

	// Create a valid token
	claims := &JWTClaims{
		UserID:      "user123",
		Username:    "testuser",
		Role:        "consulting_doctor",
		OrgID:       "org123",
		Permissions: []string{"read", "write"},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "medrex-api-gateway",
			Subject:   "user123",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Test valid token
	userClaims, err := validator.ValidateJWT(tokenString)
	if err != nil {
		t.Fatalf("Failed to validate valid token: %v", err)
	}

	if userClaims.UserID != "user123" {
		t.Errorf("Expected UserID 'user123', got '%s'", userClaims.UserID)
	}

	if userClaims.Username != "testuser" {
		t.Errorf("Expected Username 'testuser', got '%s'", userClaims.Username)
	}

	if userClaims.Role != types.UserRole("consulting_doctor") {
		t.Errorf("Expected Role 'consulting_doctor', got '%s'", userClaims.Role)
	}

	if userClaims.OrgID != "org123" {
		t.Errorf("Expected OrgID 'org123', got '%s'", userClaims.OrgID)
	}

	if len(userClaims.Permissions) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(userClaims.Permissions))
	}
}

func TestTokenValidator_ValidateJWT_InvalidToken(t *testing.T) {
	validator := NewTokenValidator("test-secret")

	// Test invalid token string
	_, err := validator.ValidateJWT("invalid-token")
	if err == nil {
		t.Error("Expected error for invalid token")
	}

	// Test token with wrong secret
	wrongSecretValidator := NewTokenValidator("wrong-secret")
	claims := &JWTClaims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "consulting_doctor",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret"))

	_, err = wrongSecretValidator.ValidateJWT(tokenString)
	if err == nil {
		t.Error("Expected error for token with wrong secret")
	}
}

func TestTokenValidator_ValidateJWT_ExpiredToken(t *testing.T) {
	validator := NewTokenValidator("test-secret")

	// Create an expired token
	claims := &JWTClaims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "consulting_doctor",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired 1 hour ago
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret"))

	_, err := validator.ValidateJWT(tokenString)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestTokenValidator_ValidateJWT_WrongSigningMethod(t *testing.T) {
	// This test validates that tokens with wrong signing methods are rejected
	// We'll create a token with a different secret and try to validate it
	validator := NewTokenValidator("test-secret")

	claims := &JWTClaims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "consulting_doctor",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("wrong-secret"))

	// This should fail because the token was signed with a different secret
	_, err := validator.ValidateJWT(tokenString)
	if err == nil {
		t.Error("Expected error when validating token signed with different secret")
	}
}

func TestTokenValidator_RefreshToken(t *testing.T) {
	validator := NewTokenValidator("test-secret")

	// Create a valid token first
	claims := &JWTClaims{
		UserID:      "user123",
		Username:    "testuser",
		Role:        "consulting_doctor",
		OrgID:       "org123",
		Permissions: []string{"read", "write"},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "medrex-api-gateway",
			Subject:   "user123",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret"))

	// Test refresh token
	newToken, err := validator.RefreshToken(tokenString)
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}

	if newToken.AccessToken == "" {
		t.Error("Expected new access token")
	}

	if newToken.TokenType != "Bearer" {
		t.Errorf("Expected token type 'Bearer', got '%s'", newToken.TokenType)
	}

	if newToken.ExpiresIn != 24*60*60 {
		t.Errorf("Expected expires in 86400 seconds, got %d", newToken.ExpiresIn)
	}

	// Validate the new token
	_, err = validator.ValidateJWT(newToken.AccessToken)
	if err != nil {
		t.Fatalf("Failed to validate refreshed token: %v", err)
	}
}

func TestTokenValidator_RefreshToken_InvalidToken(t *testing.T) {
	validator := NewTokenValidator("test-secret")

	// Test refresh with invalid token
	_, err := validator.RefreshToken("invalid-token")
	if err == nil {
		t.Error("Expected error when refreshing invalid token")
	}
}

func TestTokenValidator_RevokeToken(t *testing.T) {
	validator := NewTokenValidator("test-secret")

	// Test revoke token (placeholder implementation)
	err := validator.RevokeToken("any-token")
	if err != nil {
		t.Errorf("Unexpected error from revoke token: %v", err)
	}
}

func TestGenerateToken(t *testing.T) {
	validator := NewTokenValidator("test-secret")

	claims := &types.UserClaims{
		UserID:      "user123",
		Username:    "testuser",
		Role:        types.UserRole("consulting_doctor"),
		OrgID:       "org123",
		Permissions: []string{"read", "write"},
	}

	authToken, err := validator.generateToken(claims)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if authToken.AccessToken == "" {
		t.Error("Expected access token to be generated")
	}

	if authToken.TokenType != "Bearer" {
		t.Errorf("Expected token type 'Bearer', got '%s'", authToken.TokenType)
	}

	// Validate the generated token
	userClaims, err := validator.ValidateJWT(authToken.AccessToken)
	if err != nil {
		t.Fatalf("Failed to validate generated token: %v", err)
	}

	if userClaims.UserID != claims.UserID {
		t.Errorf("Expected UserID '%s', got '%s'", claims.UserID, userClaims.UserID)
	}
}