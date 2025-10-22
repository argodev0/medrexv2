package iam

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/medrex/dlt-emr/pkg/interfaces"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// Handlers contains HTTP handlers for IAM operations
type Handlers struct {
	service interfaces.IAMService
	logger  logger.Logger
}

// NewHandlers creates new IAM HTTP handlers
func NewHandlers(service interfaces.IAMService, log logger.Logger) *Handlers {
	return &Handlers{
		service: service,
		logger:  log,
	}
}

// RegisterRoutes registers IAM routes with the router
func (h *Handlers) RegisterRoutes(router *gin.Engine) {
	v1 := router.Group("/api/v1")
	{
		// Authentication routes
		auth := v1.Group("/auth")
		{
			auth.POST("/register", h.RegisterUser)
			auth.POST("/login", h.Login)
			auth.POST("/refresh", h.RefreshToken)
			auth.POST("/logout", h.Logout)
		}

		// User management routes (require authentication)
		users := v1.Group("/users")
		users.Use(h.AuthMiddleware())
		{
			users.GET("/:id", h.GetUser)
			users.PUT("/:id", h.UpdateUser)
			users.DELETE("/:id", h.DeactivateUser)
			users.GET("", h.ListUsers)
		}

		// MFA routes (require authentication)
		mfa := v1.Group("/mfa")
		mfa.Use(h.AuthMiddleware())
		{
			mfa.POST("/enable", h.EnableMFA)
			mfa.POST("/verify", h.VerifyMFA)
			mfa.POST("/disable", h.DisableMFA)
		}

		// Certificate management routes (require authentication)
		certs := v1.Group("/certificates")
		certs.Use(h.AuthMiddleware())
		{
			certs.POST("/renew", h.RenewCertificate)
			certs.POST("/revoke", h.RevokeCertificate)
		}
	}
}

// RegisterUser handles user registration
func (h *Handlers) RegisterUser(c *gin.Context) {
	var req types.UserRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid registration request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	user, err := h.service.RegisterUser(&req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Remove sensitive information from response
	response := map[string]interface{}{
		"id":           user.ID,
		"username":     user.Username,
		"email":        user.Email,
		"role":         user.Role,
		"organization": user.Organization,
		"is_active":    user.IsActive,
		"created_at":   user.CreatedAt,
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user":    response,
	})
}

// Login handles user authentication
func (h *Handlers) Login(c *gin.Context) {
	var credentials types.Credentials
	if err := c.ShouldBindJSON(&credentials); err != nil {
		h.logger.Error("Invalid login request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	token, err := h.service.AuthenticateUser(&credentials)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Authentication successful",
		"token":   token,
	})
}

// RefreshToken handles token refresh
func (h *Handlers) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	token, err := h.service.RefreshToken(req.RefreshToken)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Token refreshed successfully",
		"token":   token,
	})
}

// Logout handles user logout
func (h *Handlers) Logout(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Authorization header required",
		})
		return
	}

	// Remove "Bearer " prefix
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	err := h.service.RevokeToken(token)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successful",
	})
}

// GetUser retrieves user information
func (h *Handlers) GetUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "User ID is required",
		})
		return
	}

	user, err := h.service.GetUser(userID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Remove sensitive information
	response := map[string]interface{}{
		"id":           user.ID,
		"username":     user.Username,
		"email":        user.Email,
		"role":         user.Role,
		"organization": user.Organization,
		"is_active":    user.IsActive,
		"created_at":   user.CreatedAt,
		"updated_at":   user.UpdatedAt,
	}

	c.JSON(http.StatusOK, gin.H{
		"user": response,
	})
}

// UpdateUser updates user information
func (h *Handlers) UpdateUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "User ID is required",
		})
		return
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	err := h.service.UpdateUser(userID, updates)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User updated successfully",
	})
}

// DeactivateUser deactivates a user account
func (h *Handlers) DeactivateUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "User ID is required",
		})
		return
	}

	err := h.service.DeactivateUser(userID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User deactivated successfully",
	})
}

// ListUsers lists users with filtering and pagination
func (h *Handlers) ListUsers(c *gin.Context) {
	// Parse query parameters
	filters := make(map[string]interface{})
	
	if role := c.Query("role"); role != "" {
		filters["role"] = role
	}
	if org := c.Query("organization"); org != "" {
		filters["organization"] = org
	}
	if username := c.Query("username"); username != "" {
		filters["username"] = username
	}
	if active := c.Query("active"); active != "" {
		if isActive, err := strconv.ParseBool(active); err == nil {
			filters["is_active"] = isActive
		}
	}

	limit := 50 // default limit
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	offset := 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// This would need to be implemented in the service interface
	// For now, we'll return a placeholder response
	c.JSON(http.StatusOK, gin.H{
		"message": "List users endpoint - implementation pending",
		"filters": filters,
		"limit":   limit,
		"offset":  offset,
	})
}

// EnableMFA enables multi-factor authentication
func (h *Handlers) EnableMFA(c *gin.Context) {
	userID := h.getUserIDFromContext(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	secret, err := h.service.EnableMFA(userID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "MFA enabled successfully",
		"secret":  secret,
	})
}

// VerifyMFA verifies an MFA token
func (h *Handlers) VerifyMFA(c *gin.Context) {
	userID := h.getUserIDFromContext(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	var req struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	valid, err := h.service.VerifyMFA(userID, req.Token)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid": valid,
	})
}

// DisableMFA disables multi-factor authentication
func (h *Handlers) DisableMFA(c *gin.Context) {
	userID := h.getUserIDFromContext(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	err := h.service.DisableMFA(userID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "MFA disabled successfully",
	})
}

// RenewCertificate renews a user's certificate
func (h *Handlers) RenewCertificate(c *gin.Context) {
	userID := h.getUserIDFromContext(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	cert, err := h.service.RenewCertificate(userID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Certificate renewed successfully",
		"certificate": cert,
	})
}

// RevokeCertificate revokes a user's certificate
func (h *Handlers) RevokeCertificate(c *gin.Context) {
	userID := h.getUserIDFromContext(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	err := h.service.RevokeCertificate(userID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Certificate revoked successfully",
	})
}

// AuthMiddleware provides JWT authentication middleware
func (h *Handlers) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}

		// Remove "Bearer " prefix
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		// Validate token (this would use JWT validation)
		// For now, we'll just check if token is not empty
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
			return
		}

		// In a real implementation, extract user info from token
		// and set it in context
		c.Set("user_id", "mock-user-id")
		c.Next()
	}
}

// Helper methods

func (h *Handlers) handleError(c *gin.Context, err error) {
	if medrexErr, ok := err.(*types.MedrexError); ok {
		statusCode := h.getStatusCodeFromErrorType(medrexErr.Type)
		c.JSON(statusCode, gin.H{
			"error":   medrexErr.Code,
			"message": medrexErr.Message,
			"details": medrexErr.Details,
		})
		return
	}

	h.logger.Error("Internal server error", "error", err)
	c.JSON(http.StatusInternalServerError, gin.H{
		"error":   "INTERNAL_ERROR",
		"message": "An internal error occurred",
	})
}

func (h *Handlers) getStatusCodeFromErrorType(errorType types.ErrorType) int {
	switch errorType {
	case types.ErrorTypeValidation:
		return http.StatusBadRequest
	case types.ErrorTypeAuthorization:
		return http.StatusUnauthorized
	case types.ErrorTypeNotFound:
		return http.StatusNotFound
	case types.ErrorTypeCompliance:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusInternalServerError
	}
}

func (h *Handlers) getUserIDFromContext(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}