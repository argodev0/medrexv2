package iam

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strconv"
	"time"

	"github.com/medrex/dlt-emr/pkg/logger"
)

// MFAProvider implements multi-factor authentication using TOTP
type MFAProvider struct {
	logger logger.Logger
	issuer string
}

// NewMFAProvider creates a new MFA provider
func NewMFAProvider(log logger.Logger, issuer string) *MFAProvider {
	return &MFAProvider{
		logger: log,
		issuer: issuer,
	}
}

// GenerateSecret generates a new TOTP secret for a user
func (mfa *MFAProvider) GenerateSecret(userID string) (string, error) {
	// Generate 20 random bytes for the secret
	secretBytes := make([]byte, 20)
	_, err := rand.Read(secretBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random secret: %w", err)
	}

	// Encode as base32
	secret := base32.StdEncoding.EncodeToString(secretBytes)
	
	mfa.logger.Info("Generated MFA secret for user", "user_id", userID)
	return secret, nil
}

// GenerateQRCode generates a QR code for TOTP setup
func (mfa *MFAProvider) GenerateQRCode(userID, secret string) ([]byte, error) {
	// In a real implementation, this would generate a QR code image
	// For now, we'll return the TOTP URL as bytes
	url := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", 
		mfa.issuer, userID, secret, mfa.issuer)
	
	mfa.logger.Info("Generated QR code for user", "user_id", userID)
	return []byte(url), nil
}

// VerifyToken verifies a TOTP token
func (mfa *MFAProvider) VerifyToken(secret, token string) (bool, error) {
	// Parse the token
	tokenInt, err := strconv.Atoi(token)
	if err != nil {
		return false, fmt.Errorf("invalid token format: %w", err)
	}

	// Get current time window (30-second intervals)
	currentTime := time.Now().Unix() / 30

	// Check current window and adjacent windows for clock skew tolerance
	for i := -1; i <= 1; i++ {
		timeWindow := currentTime + int64(i)
		expectedToken := mfa.generateTOTP(secret, timeWindow)
		
		if expectedToken == tokenInt {
			mfa.logger.Info("MFA token verified successfully")
			return true, nil
		}
	}

	mfa.logger.Warn("MFA token verification failed")
	return false, nil
}

// GetBackupCodes generates backup codes for MFA recovery
func (mfa *MFAProvider) GetBackupCodes(userID string) ([]string, error) {
	codes := make([]string, 10)
	
	for i := range codes {
		// Generate 8-digit backup codes
		codeBytes := make([]byte, 4)
		_, err := rand.Read(codeBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		
		// Convert to 8-digit number
		code := fmt.Sprintf("%08d", 
			int(codeBytes[0])<<24 | int(codeBytes[1])<<16 | int(codeBytes[2])<<8 | int(codeBytes[3]))
		codes[i] = code
	}

	mfa.logger.Info("Generated backup codes for user", "user_id", userID, "count", len(codes))
	return codes, nil
}

// generateTOTP generates a TOTP token for a given secret and time window
func (mfa *MFAProvider) generateTOTP(secret string, timeWindow int64) int {
	// This is a simplified TOTP implementation
	// In production, use a proper TOTP library like github.com/pquerna/otp
	
	// Decode base32 secret
	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return 0
	}

	// Simple hash-based calculation (not cryptographically secure)
	// This is just for demonstration - use proper HMAC-SHA1 in production
	hash := int(timeWindow)
	for _, b := range secretBytes {
		hash = hash*31 + int(b)
	}
	
	// Return 6-digit code
	return (hash & 0x7fffffff) % 1000000
}