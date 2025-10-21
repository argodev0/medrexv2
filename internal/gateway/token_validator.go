package gateway

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/medrex/dlt-emr/pkg/types"
)

// TokenValidator implements JWT token validation
type TokenValidator struct {
	jwtSecret []byte
}

// NewTokenValidator creates a new token validator
func NewTokenValidator(secret string) *TokenValidator {
	return &TokenValidator{
		jwtSecret: []byte(secret),
	}
}

// ValidateJWT validates a JWT token and returns user claims
func (tv *TokenValidator) ValidateJWT(tokenString string) (*types.UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tv.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}

	return &types.UserClaims{
		UserID:      claims.UserID,
		Username:    claims.Username,
		Role:        types.UserRole(claims.Role),
		OrgID:       claims.OrgID,
		Permissions: claims.Permissions,
	}, nil
}

// RefreshToken refreshes an existing token
func (tv *TokenValidator) RefreshToken(tokenString string) (*types.AuthToken, error) {
	// Validate the existing token first
	claims, err := tv.ValidateJWT(tokenString)
	if err != nil {
		return nil, fmt.Errorf("cannot refresh invalid token: %w", err)
	}

	// Generate new token with same claims but extended expiration
	newToken, err := tv.generateToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new token: %w", err)
	}

	return newToken, nil
}

// RevokeToken revokes a token (placeholder implementation)
func (tv *TokenValidator) RevokeToken(tokenString string) error {
	// In a production system, you would maintain a blacklist of revoked tokens
	// For now, this is a placeholder implementation
	return nil
}

// generateToken generates a new JWT token
func (tv *TokenValidator) generateToken(claims *types.UserClaims) (*types.AuthToken, error) {
	now := time.Now()
	expirationTime := now.Add(24 * time.Hour) // 24 hour expiration

	jwtClaims := &JWTClaims{
		UserID:      claims.UserID,
		Username:    claims.Username,
		Role:        string(claims.Role),
		OrgID:       claims.OrgID,
		Permissions: claims.Permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "medrex-api-gateway",
			Subject:   claims.UserID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	tokenString, err := token.SignedString(tv.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return &types.AuthToken{
		AccessToken:  tokenString,
		RefreshToken: "", // Implement refresh token logic if needed
		TokenType:    "Bearer",
		ExpiresIn:    int64(24 * 60 * 60), // 24 hours in seconds
		IssuedAt:     now,
	}, nil
}

// JWTClaims represents JWT token claims
type JWTClaims struct {
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	OrgID       string   `json:"org_id"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}