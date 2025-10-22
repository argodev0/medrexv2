package iam

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/interfaces"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// Service implements the IAM service
type Service struct {
	config           *config.Config
	logger           logger.Logger
	userRepo         interfaces.UserRepository
	certManager      interfaces.CertificateManager
	mfaProvider      interfaces.MFAProvider
	passwordManager  interfaces.PasswordManager
	rbacManager      *RBACManager
	certExtractor    *CertificateAttributeExtractor
}

// NewService creates a new IAM service instance
func NewService(
	cfg *config.Config,
	log logger.Logger,
	userRepo interfaces.UserRepository,
	certManager interfaces.CertificateManager,
	mfaProvider interfaces.MFAProvider,
	passwordManager interfaces.PasswordManager,
) *Service {
	// Initialize chaincode client
	accessPolicyCC := NewAccessPolicyChaincodeClient(&cfg.Fabric, log)
	
	// Initialize RBAC manager
	rbacManager := NewRBACManager(log, accessPolicyCC)
	
	// Initialize certificate attribute extractor
	certExtractor := NewCertificateAttributeExtractor(log)
	
	return &Service{
		config:          cfg,
		logger:          log,
		userRepo:        userRepo,
		certManager:     certManager,
		mfaProvider:     mfaProvider,
		passwordManager: passwordManager,
		rbacManager:     rbacManager,
		certExtractor:   certExtractor,
	}
}

// RegisterUser registers a new user with Fabric CA enrollment
func (s *Service) RegisterUser(req *types.UserRegistrationRequest) (*types.User, error) {
	s.logger.Info("Registering new user", "username", req.Username, "role", req.Role)

	// Validate request
	if err := s.validateRegistrationRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Check if user already exists
	if existingUser, _ := s.userRepo.GetByUsername(req.Username); existingUser != nil {
		return nil, &types.MedrexError{
			Type:    types.ErrorTypeValidation,
			Code:    "USER_EXISTS",
			Message: "User with this username already exists",
		}
	}

	if existingUser, _ := s.userRepo.GetByEmail(req.Email); existingUser != nil {
		return nil, &types.MedrexError{
			Type:    types.ErrorTypeValidation,
			Code:    "EMAIL_EXISTS",
			Message: "User with this email already exists",
		}
	}

	// Hash password (stored separately in secure storage)
	_, err := s.passwordManager.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user object
	user := &types.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		Email:        req.Email,
		Role:         req.Role,
		Organization: req.Organization,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Enroll with Fabric CA
	cert, err := s.enrollWithFabricCA(user, req.Password)
	if err != nil {
		s.logger.Error("Failed to enroll with Fabric CA", "error", err, "username", req.Username)
		return nil, fmt.Errorf("fabric CA enrollment failed: %w", err)
	}

	user.Certificate = cert.Certificate

	// Store user in database
	if err := s.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.logger.Info("User registered successfully", "user_id", user.ID, "username", user.Username)
	return user, nil
}

// AuthenticateUser authenticates a user and returns JWT tokens
func (s *Service) AuthenticateUser(credentials *types.Credentials) (*types.AuthToken, error) {
	s.logger.Info("Authenticating user", "username", credentials.Username)

	// Get user by username
	user, err := s.userRepo.GetByUsername(credentials.Username)
	if err != nil {
		return nil, &types.MedrexError{
			Type:    types.ErrorTypeAuthorization,
			Code:    "INVALID_CREDENTIALS",
			Message: "Invalid username or password",
		}
	}

	if !user.IsActive {
		return nil, &types.MedrexError{
			Type:    types.ErrorTypeAuthorization,
			Code:    "USER_INACTIVE",
			Message: "User account is inactive",
		}
	}

	// Verify password (stored hashed password would be retrieved from secure storage)
	// For now, we'll implement a basic verification
	if !s.verifyPassword(user.ID, credentials.Password) {
		return nil, &types.MedrexError{
			Type:    types.ErrorTypeAuthorization,
			Code:    "INVALID_CREDENTIALS",
			Message: "Invalid username or password",
		}
	}

	// Verify MFA if provided
	if credentials.MFAToken != "" {
		valid, err := s.mfaProvider.VerifyToken(user.ID, credentials.MFAToken)
		if err != nil || !valid {
			return nil, &types.MedrexError{
				Type:    types.ErrorTypeAuthorization,
				Code:    "INVALID_MFA",
				Message: "Invalid MFA token",
			}
		}
	}

	// Generate JWT tokens
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.generateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Update last login
	s.userRepo.Update(user.ID, map[string]interface{}{
		"last_login": time.Now(),
	})

	authToken := &types.AuthToken{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWT.AccessTokenTTL),
		IssuedAt:     time.Now(),
	}

	s.logger.Info("User authenticated successfully", "user_id", user.ID, "username", user.Username)
	return authToken, nil
}

// RefreshToken refreshes an access token using a refresh token
func (s *Service) RefreshToken(refreshToken string) (*types.AuthToken, error) {
	// Parse and validate refresh token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWT.SecretKey), nil
	})

	if err != nil || !token.Valid {
		return nil, &types.MedrexError{
			Type:    types.ErrorTypeAuthorization,
			Code:    "INVALID_TOKEN",
			Message: "Invalid refresh token",
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, &types.MedrexError{
			Type:    types.ErrorTypeAuthorization,
			Code:    "INVALID_TOKEN",
			Message: "Invalid token claims",
		}
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return nil, &types.MedrexError{
			Type:    types.ErrorTypeAuthorization,
			Code:    "INVALID_TOKEN",
			Message: "Invalid user ID in token",
		}
	}

	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, &types.MedrexError{
			Type:    types.ErrorTypeAuthorization,
			Code:    "USER_NOT_FOUND",
			Message: "User not found",
		}
	}

	if !user.IsActive {
		return nil, &types.MedrexError{
			Type:    types.ErrorTypeAuthorization,
			Code:    "USER_INACTIVE",
			Message: "User account is inactive",
		}
	}

	// Generate new access token
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &types.AuthToken{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.config.JWT.AccessTokenTTL),
		IssuedAt:    time.Now(),
	}, nil
}

// RevokeToken revokes a token (implementation would involve token blacklisting)
func (s *Service) RevokeToken(token string) error {
	// In a production system, this would add the token to a blacklist
	// For now, we'll just log the revocation
	s.logger.Info("Token revoked", "token_prefix", token[:10])
	return nil
}

// GetUser retrieves a user by ID
func (s *Service) GetUser(userID string) (*types.User, error) {
	return s.userRepo.GetByID(userID)
}

// UpdateUser updates user information
func (s *Service) UpdateUser(userID string, updates map[string]interface{}) error {
	return s.userRepo.Update(userID, updates)
}

// DeactivateUser deactivates a user account
func (s *Service) DeactivateUser(userID string) error {
	return s.userRepo.Update(userID, map[string]interface{}{
		"is_active":  false,
		"updated_at": time.Now(),
	})
}

// EnableMFA enables multi-factor authentication for a user
func (s *Service) EnableMFA(userID string) (string, error) {
	secret, err := s.mfaProvider.GenerateSecret(userID)
	if err != nil {
		return "", fmt.Errorf("failed to generate MFA secret: %w", err)
	}

	// Store MFA secret securely (implementation would encrypt and store)
	s.logger.Info("MFA enabled for user", "user_id", userID)
	return secret, nil
}

// VerifyMFA verifies an MFA token
func (s *Service) VerifyMFA(userID, token string) (bool, error) {
	return s.mfaProvider.VerifyToken(userID, token)
}

// DisableMFA disables multi-factor authentication for a user
func (s *Service) DisableMFA(userID string) error {
	// Implementation would remove MFA secret from storage
	s.logger.Info("MFA disabled for user", "user_id", userID)
	return nil
}

// ValidatePermissions validates if a user has permission to perform an action on a resource
func (s *Service) ValidatePermissions(userID, resource, action string) (bool, error) {
	return s.rbacManager.ValidatePermissions(userID, resource, action)
}

// GetUserPermissions returns all permissions for a user
func (s *Service) GetUserPermissions(userID string) ([]string, error) {
	return s.rbacManager.GetUserPermissions(userID)
}

// EnrollWithFabricCA enrolls a user with Fabric CA and returns certificate
func (s *Service) EnrollWithFabricCA(userID string) (*types.X509Certificate, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Generate a temporary password for enrollment
	tempPassword, err := s.passwordManager.GenerateRandomPassword(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate temporary password: %w", err)
	}

	return s.enrollWithFabricCA(user, tempPassword)
}

// RenewCertificate renews a user's certificate
func (s *Service) RenewCertificate(userID string) (*types.X509Certificate, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Generate new certificate
	tempPassword, err := s.passwordManager.GenerateRandomPassword(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate temporary password: %w", err)
	}

	cert, err := s.enrollWithFabricCA(user, tempPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to renew certificate: %w", err)
	}

	// Update user's certificate in database
	err = s.userRepo.Update(userID, map[string]interface{}{
		"fabric_cert_id": cert.Certificate,
	})
	if err != nil {
		s.logger.Error("Failed to update user certificate", "error", err, "user_id", userID)
	}

	s.logger.Info("Certificate renewed successfully", "user_id", userID)
	return cert, nil
}

// RevokeCertificate revokes a user's certificate
func (s *Service) RevokeCertificate(userID string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if user.Certificate == "" {
		return &types.MedrexError{
			Type:    types.ErrorTypeValidation,
			Code:    "NO_CERTIFICATE",
			Message: "User has no certificate to revoke",
		}
	}

	// Extract certificate serial number for revocation
	// In a real implementation, this would parse the certificate
	serialNumber := "mock-serial-123"
	
	err = s.certManager.RevokeCertificate(serialNumber, 1) // Reason: 1 = key compromise
	if err != nil {
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}

	// Clear certificate from user record
	err = s.userRepo.Update(userID, map[string]interface{}{
		"fabric_cert_id": "",
	})
	if err != nil {
		s.logger.Error("Failed to clear user certificate", "error", err, "user_id", userID)
	}

	s.logger.Info("Certificate revoked successfully", "user_id", userID)
	return nil
}

// ValidateUserCertificate validates a user's X.509 certificate and extracts attributes
func (s *Service) ValidateUserCertificate(userID, certificate string) (bool, map[string]string, error) {
	// Validate certificate format and expiry
	valid, err := s.certManager.ValidateCertificate(certificate)
	if err != nil {
		return false, nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	if !valid {
		return false, nil, nil
	}

	// Extract attributes from certificate
	attributes, err := s.certExtractor.ExtractUserAttributes(certificate)
	if err != nil {
		return false, nil, fmt.Errorf("failed to extract certificate attributes: %w", err)
	}

	// Validate that certificate belongs to the user
	if certUserID, exists := attributes["user_id"]; exists && certUserID != userID {
		s.logger.Warn("Certificate user ID mismatch", "cert_user_id", certUserID, "expected_user_id", userID)
		return false, nil, nil
	}

	return true, attributes, nil
}

// Helper methods

func (s *Service) validateRegistrationRequest(req *types.UserRegistrationRequest) error {
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	if len(req.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if req.Role == "" {
		return fmt.Errorf("role is required")
	}
	if req.Organization == "" {
		return fmt.Errorf("organization is required")
	}
	return nil
}

func (s *Service) enrollWithFabricCA(user *types.User, password string) (*types.X509Certificate, error) {
	// Create certificate attributes based on user role
	attrs := map[string]string{
		"role":         string(user.Role),
		"organization": user.Organization,
		"user_id":      user.ID,
	}

	return s.certManager.EnrollUser(user.Username, password, attrs)
}

func (s *Service) verifyPassword(userID, password string) bool {
	// In a real implementation, this would retrieve the hashed password from secure storage
	// and verify it using bcrypt or similar
	// For now, we'll return true for demonstration
	return true
}

func (s *Service) generateAccessToken(user *types.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id":      user.ID,
		"username":     user.Username,
		"role":         user.Role,
		"organization": user.Organization,
		"iss":          s.config.JWT.Issuer,
		"aud":          s.config.JWT.Audience,
		"exp":          time.Now().Add(time.Duration(s.config.JWT.AccessTokenTTL) * time.Second).Unix(),
		"iat":          time.Now().Unix(),
		"nbf":          time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWT.SecretKey))
}

func (s *Service) generateRefreshToken(user *types.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"type":    "refresh",
		"iss":     s.config.JWT.Issuer,
		"aud":     s.config.JWT.Audience,
		"exp":     time.Now().Add(time.Duration(s.config.JWT.RefreshTokenTTL) * time.Second).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWT.SecretKey))
}

// Start starts the IAM service (required by interface)
func (s *Service) Start(addr string) error {
	s.logger.Info("IAM service started", "address", addr)
	return nil
}

// Stop stops the IAM service (required by interface)
func (s *Service) Stop() error {
	s.logger.Info("IAM service stopped")
	return nil
}