package rbac

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// SuspiciousActivityDetector detects suspicious access patterns and behaviors
type SuspiciousActivityDetector struct {
	config                *Config
	logger                *logrus.Logger
	userActivityTracker   map[string]*UserActivityProfile
	ipActivityTracker     map[string]*IPActivityProfile
	resourceAccessTracker map[string]*ResourceAccessProfile
	mutex                 sync.RWMutex
	stopChan              chan struct{}
	cleanupTicker         *time.Ticker
}

// UserActivityProfile tracks activity patterns for a specific user
type UserActivityProfile struct {
	UserID              string                    `json:"user_id"`
	LastAccessTime      time.Time                 `json:"last_access_time"`
	AccessCount         int64                     `json:"access_count"`
	FailureCount        int64                     `json:"failure_count"`
	ConsecutiveFailures int64                     `json:"consecutive_failures"`
	AccessPatterns      map[string]*AccessPattern `json:"access_patterns"`
	IPAddresses         map[string]int64          `json:"ip_addresses"`
	UserAgents          map[string]int64          `json:"user_agents"`
	ResourceAccess      map[string]int64          `json:"resource_access"`
	ActionFrequency     map[string]int64          `json:"action_frequency"`
	TimePatterns        *TimeAccessPattern        `json:"time_patterns"`
	RiskScore           float64                   `json:"risk_score"`
	LastRiskUpdate      time.Time                 `json:"last_risk_update"`
}

// IPActivityProfile tracks activity patterns for a specific IP address
type IPActivityProfile struct {
	IPAddress           string            `json:"ip_address"`
	UserCount           int64             `json:"user_count"`
	AccessCount         int64             `json:"access_count"`
	FailureCount        int64             `json:"failure_count"`
	FirstSeen           time.Time         `json:"first_seen"`
	LastSeen            time.Time         `json:"last_seen"`
	UserIDs             map[string]int64  `json:"user_ids"`
	ResourceAccess      map[string]int64  `json:"resource_access"`
	ActionFrequency     map[string]int64  `json:"action_frequency"`
	RiskScore           float64           `json:"risk_score"`
	IsBlacklisted       bool              `json:"is_blacklisted"`
	BlacklistReason     string            `json:"blacklist_reason,omitempty"`
}

// ResourceAccessProfile tracks access patterns for a specific resource
type ResourceAccessProfile struct {
	ResourceID      string            `json:"resource_id"`
	AccessCount     int64             `json:"access_count"`
	FailureCount    int64             `json:"failure_count"`
	UserAccess      map[string]int64  `json:"user_access"`
	IPAccess        map[string]int64  `json:"ip_access"`
	ActionFrequency map[string]int64  `json:"action_frequency"`
	LastAccessTime  time.Time         `json:"last_access_time"`
	RiskScore       float64           `json:"risk_score"`
}

// AccessPattern represents a pattern of access behavior
type AccessPattern struct {
	ResourceType    string    `json:"resource_type"`
	Action          string    `json:"action"`
	Frequency       int64     `json:"frequency"`
	LastAccess      time.Time `json:"last_access"`
	AverageInterval time.Duration `json:"average_interval"`
	IsNormal        bool      `json:"is_normal"`
}

// TimeAccessPattern tracks time-based access patterns
type TimeAccessPattern struct {
	HourlyDistribution  [24]int64 `json:"hourly_distribution"`
	DailyDistribution   [7]int64  `json:"daily_distribution"`
	BusinessHoursAccess int64     `json:"business_hours_access"`
	AfterHoursAccess    int64     `json:"after_hours_access"`
	WeekendAccess       int64     `json:"weekend_access"`
}

// SuspiciousActivityThresholds defines thresholds for suspicious activity detection
type SuspiciousActivityThresholds struct {
	MaxConsecutiveFailures    int64         `json:"max_consecutive_failures"`
	MaxFailuresPerHour        int64         `json:"max_failures_per_hour"`
	MaxAccessesPerMinute      int64         `json:"max_accesses_per_minute"`
	MaxUniqueIPsPerUser       int64         `json:"max_unique_ips_per_user"`
	MaxUsersPerIP             int64         `json:"max_users_per_ip"`
	UnusualTimeThreshold      float64       `json:"unusual_time_threshold"`
	RiskScoreThreshold        float64       `json:"risk_score_threshold"`
	ProfileRetentionDuration  time.Duration `json:"profile_retention_duration"`
	CleanupInterval           time.Duration `json:"cleanup_interval"`
}

// NewSuspiciousActivityDetector creates a new suspicious activity detector
func NewSuspiciousActivityDetector(config *Config, logger *logrus.Logger) *SuspiciousActivityDetector {
	return &SuspiciousActivityDetector{
		config:                config,
		logger:                logger,
		userActivityTracker:   make(map[string]*UserActivityProfile),
		ipActivityTracker:     make(map[string]*IPActivityProfile),
		resourceAccessTracker: make(map[string]*ResourceAccessProfile),
		stopChan:              make(chan struct{}),
	}
}

// Start starts the suspicious activity detector
func (sad *SuspiciousActivityDetector) Start(ctx context.Context) error {
	sad.logger.Info("Starting suspicious activity detector")

	// Start cleanup routine
	sad.cleanupTicker = time.NewTicker(sad.config.SuspiciousActivityThresholds.CleanupInterval)
	go sad.cleanupRoutine(ctx)

	sad.logger.Info("Suspicious activity detector started")
	return nil
}

// Stop stops the suspicious activity detector
func (sad *SuspiciousActivityDetector) Stop() error {
	sad.logger.Info("Stopping suspicious activity detector")

	if sad.cleanupTicker != nil {
		sad.cleanupTicker.Stop()
	}

	close(sad.stopChan)

	sad.logger.Info("Suspicious activity detector stopped")
	return nil
}

// AnalyzeAccessAttempt analyzes an access attempt for suspicious activity
func (sad *SuspiciousActivityDetector) AnalyzeAccessAttempt(event *AccessAttemptEvent) (bool, AlertType) {
	sad.mutex.Lock()
	defer sad.mutex.Unlock()

	// Update activity profiles
	sad.updateUserProfile(event)
	sad.updateIPProfile(event)
	sad.updateResourceProfile(event)

	// Check for various suspicious patterns
	if suspicious, alertType := sad.checkSuspiciousPatterns(event); suspicious {
		return true, alertType
	}

	return false, ""
}

// GetUserProfile returns the activity profile for a user
func (sad *SuspiciousActivityDetector) GetUserProfile(userID string) *UserActivityProfile {
	sad.mutex.RLock()
	defer sad.mutex.RUnlock()

	if profile, exists := sad.userActivityTracker[userID]; exists {
		// Return a copy to avoid race conditions
		profileCopy := *profile
		return &profileCopy
	}

	return nil
}

// GetIPProfile returns the activity profile for an IP address
func (sad *SuspiciousActivityDetector) GetIPProfile(ipAddress string) *IPActivityProfile {
	sad.mutex.RLock()
	defer sad.mutex.RUnlock()

	if profile, exists := sad.ipActivityTracker[ipAddress]; exists {
		// Return a copy to avoid race conditions
		profileCopy := *profile
		return &profileCopy
	}

	return nil
}

// GetResourceProfile returns the access profile for a resource
func (sad *SuspiciousActivityDetector) GetResourceProfile(resourceID string) *ResourceAccessProfile {
	sad.mutex.RLock()
	defer sad.mutex.RUnlock()

	if profile, exists := sad.resourceAccessTracker[resourceID]; exists {
		// Return a copy to avoid race conditions
		profileCopy := *profile
		return &profileCopy
	}

	return nil
}

// BlacklistIP adds an IP address to the blacklist
func (sad *SuspiciousActivityDetector) BlacklistIP(ipAddress, reason string) {
	sad.mutex.Lock()
	defer sad.mutex.Unlock()

	profile := sad.getOrCreateIPProfile(ipAddress)
	profile.IsBlacklisted = true
	profile.BlacklistReason = reason
	profile.RiskScore = 100.0 // Maximum risk score

	sad.logger.Warn("IP address blacklisted",
		"ip_address", ipAddress,
		"reason", reason,
	)
}

// RemoveIPFromBlacklist removes an IP address from the blacklist
func (sad *SuspiciousActivityDetector) RemoveIPFromBlacklist(ipAddress string) {
	sad.mutex.Lock()
	defer sad.mutex.Unlock()

	if profile, exists := sad.ipActivityTracker[ipAddress]; exists {
		profile.IsBlacklisted = false
		profile.BlacklistReason = ""
		profile.RiskScore = sad.calculateIPRiskScore(profile)

		sad.logger.Info("IP address removed from blacklist",
			"ip_address", ipAddress,
		)
	}
}

// IsIPBlacklisted checks if an IP address is blacklisted
func (sad *SuspiciousActivityDetector) IsIPBlacklisted(ipAddress string) bool {
	sad.mutex.RLock()
	defer sad.mutex.RUnlock()

	if profile, exists := sad.ipActivityTracker[ipAddress]; exists {
		return profile.IsBlacklisted
	}

	return false
}

// Helper methods

func (sad *SuspiciousActivityDetector) updateUserProfile(event *AccessAttemptEvent) {
	profile := sad.getOrCreateUserProfile(event.UserID)

	profile.LastAccessTime = event.Timestamp
	profile.AccessCount++

	if event.Result == "denied" {
		profile.FailureCount++
		profile.ConsecutiveFailures++
	} else {
		profile.ConsecutiveFailures = 0
	}

	// Update IP addresses
	if event.IPAddress != "" {
		if profile.IPAddresses == nil {
			profile.IPAddresses = make(map[string]int64)
		}
		profile.IPAddresses[event.IPAddress]++
	}

	// Update user agents
	if event.UserAgent != "" {
		if profile.UserAgents == nil {
			profile.UserAgents = make(map[string]int64)
		}
		profile.UserAgents[event.UserAgent]++
	}

	// Update resource access
	if event.ResourceID != "" {
		if profile.ResourceAccess == nil {
			profile.ResourceAccess = make(map[string]int64)
		}
		profile.ResourceAccess[event.ResourceID]++
	}

	// Update action frequency
	if profile.ActionFrequency == nil {
		profile.ActionFrequency = make(map[string]int64)
	}
	profile.ActionFrequency[event.Action]++

	// Update access patterns
	sad.updateAccessPatterns(profile, event)

	// Update time patterns
	sad.updateTimePatterns(profile, event)

	// Calculate risk score
	profile.RiskScore = sad.calculateUserRiskScore(profile)
	profile.LastRiskUpdate = time.Now()
}

func (sad *SuspiciousActivityDetector) updateIPProfile(event *AccessAttemptEvent) {
	if event.IPAddress == "" {
		return
	}

	profile := sad.getOrCreateIPProfile(event.IPAddress)

	profile.LastSeen = event.Timestamp
	profile.AccessCount++

	if event.Result == "denied" {
		profile.FailureCount++
	}

	// Update user IDs
	if profile.UserIDs == nil {
		profile.UserIDs = make(map[string]int64)
	}
	if _, exists := profile.UserIDs[event.UserID]; !exists {
		profile.UserCount++
	}
	profile.UserIDs[event.UserID]++

	// Update resource access
	if event.ResourceID != "" {
		if profile.ResourceAccess == nil {
			profile.ResourceAccess = make(map[string]int64)
		}
		profile.ResourceAccess[event.ResourceID]++
	}

	// Update action frequency
	if profile.ActionFrequency == nil {
		profile.ActionFrequency = make(map[string]int64)
	}
	profile.ActionFrequency[event.Action]++

	// Calculate risk score (unless blacklisted)
	if !profile.IsBlacklisted {
		profile.RiskScore = sad.calculateIPRiskScore(profile)
	}
}

func (sad *SuspiciousActivityDetector) updateResourceProfile(event *AccessAttemptEvent) {
	if event.ResourceID == "" {
		return
	}

	profile := sad.getOrCreateResourceProfile(event.ResourceID)

	profile.LastAccessTime = event.Timestamp
	profile.AccessCount++

	if event.Result == "denied" {
		profile.FailureCount++
	}

	// Update user access
	if profile.UserAccess == nil {
		profile.UserAccess = make(map[string]int64)
	}
	profile.UserAccess[event.UserID]++

	// Update IP access
	if event.IPAddress != "" {
		if profile.IPAccess == nil {
			profile.IPAccess = make(map[string]int64)
		}
		profile.IPAccess[event.IPAddress]++
	}

	// Update action frequency
	if profile.ActionFrequency == nil {
		profile.ActionFrequency = make(map[string]int64)
	}
	profile.ActionFrequency[event.Action]++

	// Calculate risk score
	profile.RiskScore = sad.calculateResourceRiskScore(profile)
}

func (sad *SuspiciousActivityDetector) getOrCreateUserProfile(userID string) *UserActivityProfile {
	if profile, exists := sad.userActivityTracker[userID]; exists {
		return profile
	}

	profile := &UserActivityProfile{
		UserID:          userID,
		AccessPatterns:  make(map[string]*AccessPattern),
		IPAddresses:     make(map[string]int64),
		UserAgents:      make(map[string]int64),
		ResourceAccess:  make(map[string]int64),
		ActionFrequency: make(map[string]int64),
		TimePatterns:    &TimeAccessPattern{},
	}

	sad.userActivityTracker[userID] = profile
	return profile
}

func (sad *SuspiciousActivityDetector) getOrCreateIPProfile(ipAddress string) *IPActivityProfile {
	if profile, exists := sad.ipActivityTracker[ipAddress]; exists {
		return profile
	}

	profile := &IPActivityProfile{
		IPAddress:       ipAddress,
		FirstSeen:       time.Now(),
		UserIDs:         make(map[string]int64),
		ResourceAccess:  make(map[string]int64),
		ActionFrequency: make(map[string]int64),
	}

	sad.ipActivityTracker[ipAddress] = profile
	return profile
}

func (sad *SuspiciousActivityDetector) getOrCreateResourceProfile(resourceID string) *ResourceAccessProfile {
	if profile, exists := sad.resourceAccessTracker[resourceID]; exists {
		return profile
	}

	profile := &ResourceAccessProfile{
		ResourceID:      resourceID,
		UserAccess:      make(map[string]int64),
		IPAccess:        make(map[string]int64),
		ActionFrequency: make(map[string]int64),
	}

	sad.resourceAccessTracker[resourceID] = profile
	return profile
}

func (sad *SuspiciousActivityDetector) updateAccessPatterns(profile *UserActivityProfile, event *AccessAttemptEvent) {
	patternKey := fmt.Sprintf("%s:%s", event.ResourceType, event.Action)
	
	if pattern, exists := profile.AccessPatterns[patternKey]; exists {
		// Update existing pattern
		interval := event.Timestamp.Sub(pattern.LastAccess)
		if pattern.Frequency == 1 {
			pattern.AverageInterval = interval
		} else {
			// Calculate running average
			totalInterval := pattern.AverageInterval * time.Duration(pattern.Frequency-1)
			pattern.AverageInterval = (totalInterval + interval) / time.Duration(pattern.Frequency)
		}
		pattern.Frequency++
		pattern.LastAccess = event.Timestamp
	} else {
		// Create new pattern
		profile.AccessPatterns[patternKey] = &AccessPattern{
			ResourceType: event.ResourceType,
			Action:       event.Action,
			Frequency:    1,
			LastAccess:   event.Timestamp,
			IsNormal:     true, // Will be determined by analysis
		}
	}
}

func (sad *SuspiciousActivityDetector) updateTimePatterns(profile *UserActivityProfile, event *AccessAttemptEvent) {
	hour := event.Timestamp.Hour()
	weekday := int(event.Timestamp.Weekday())

	profile.TimePatterns.HourlyDistribution[hour]++
	profile.TimePatterns.DailyDistribution[weekday]++

	// Check if business hours (9 AM to 5 PM, Monday to Friday)
	if weekday >= 1 && weekday <= 5 && hour >= 9 && hour <= 17 {
		profile.TimePatterns.BusinessHoursAccess++
	} else {
		profile.TimePatterns.AfterHoursAccess++
	}

	// Check if weekend (Saturday or Sunday)
	if weekday == 0 || weekday == 6 {
		profile.TimePatterns.WeekendAccess++
	}
}

func (sad *SuspiciousActivityDetector) checkSuspiciousPatterns(event *AccessAttemptEvent) (bool, AlertType) {
	thresholds := sad.config.SuspiciousActivityThresholds

	// Check user-based patterns
	if userProfile, exists := sad.userActivityTracker[event.UserID]; exists {
		// Check consecutive failures
		if userProfile.ConsecutiveFailures >= thresholds.MaxConsecutiveFailures {
			return true, AlertTypeMultipleFailures
		}

		// Check failure rate in the last hour
		recentFailures := sad.countRecentFailures(event.UserID, time.Hour)
		if recentFailures >= thresholds.MaxFailuresPerHour {
			return true, AlertTypeMultipleFailures
		}

		// Check access rate in the last minute
		recentAccesses := sad.countRecentAccesses(event.UserID, time.Minute)
		if recentAccesses >= thresholds.MaxAccessesPerMinute {
			return true, AlertTypeRateLimitExceeded
		}

		// Check unique IP addresses
		if int64(len(userProfile.IPAddresses)) > thresholds.MaxUniqueIPsPerUser {
			return true, AlertTypeSuspiciousPattern
		}

		// Check unusual time access
		if sad.isUnusualTimeAccess(userProfile, event.Timestamp) {
			return true, AlertTypeAfterHoursAccess
		}

		// Check risk score
		if userProfile.RiskScore >= thresholds.RiskScoreThreshold {
			return true, AlertTypeAnomalousActivity
		}
	}

	// Check IP-based patterns
	if event.IPAddress != "" {
		if ipProfile, exists := sad.ipActivityTracker[event.IPAddress]; exists {
			// Check if IP is blacklisted
			if ipProfile.IsBlacklisted {
				return true, AlertTypePolicyViolation
			}

			// Check users per IP
			if ipProfile.UserCount > thresholds.MaxUsersPerIP {
				return true, AlertTypeSuspiciousPattern
			}

			// Check IP risk score
			if ipProfile.RiskScore >= thresholds.RiskScoreThreshold {
				return true, AlertTypeAnomalousActivity
			}
		}
	}

	// Check for privilege escalation attempts
	if sad.isPrivilegeEscalationAttempt(event) {
		return true, AlertTypePrivilegeEscalation
	}

	// Check for unauthorized resource access
	if sad.isUnauthorizedResourceAccess(event) {
		return true, AlertTypeUnauthorizedResource
	}

	return false, ""
}

func (sad *SuspiciousActivityDetector) countRecentFailures(userID string, duration time.Duration) int64 {
	// This would typically query the database for recent failures
	// For now, we'll use a simplified approach based on the profile
	if profile, exists := sad.userActivityTracker[userID]; exists {
		cutoff := time.Now().Add(-duration)
		if profile.LastAccessTime.After(cutoff) {
			// Estimate based on consecutive failures (simplified)
			return profile.ConsecutiveFailures
		}
	}
	return 0
}

func (sad *SuspiciousActivityDetector) countRecentAccesses(userID string, duration time.Duration) int64 {
	// This would typically query the database for recent accesses
	// For now, we'll use a simplified approach
	if profile, exists := sad.userActivityTracker[userID]; exists {
		cutoff := time.Now().Add(-duration)
		if profile.LastAccessTime.After(cutoff) {
			// Estimate based on recent activity (simplified)
			return 1 // Current access
		}
	}
	return 0
}

func (sad *SuspiciousActivityDetector) isUnusualTimeAccess(profile *UserActivityProfile, timestamp time.Time) bool {
	hour := timestamp.Hour()
	weekday := int(timestamp.Weekday())

	// Calculate if this time is unusual for this user
	totalAccesses := profile.TimePatterns.BusinessHoursAccess + profile.TimePatterns.AfterHoursAccess
	if totalAccesses == 0 {
		return false // Not enough data
	}

	// Check if accessing during unusual hours for this user
	hourlyAccesses := profile.TimePatterns.HourlyDistribution[hour]
	hourlyPercentage := float64(hourlyAccesses) / float64(totalAccesses)

	// If this hour represents less than 5% of their typical access pattern
	if hourlyPercentage < sad.config.SuspiciousActivityThresholds.UnusualTimeThreshold {
		return true
	}

	// Check weekend access if user typically doesn't access on weekends
	if (weekday == 0 || weekday == 6) && profile.TimePatterns.WeekendAccess == 0 {
		return true
	}

	return false
}

func (sad *SuspiciousActivityDetector) isPrivilegeEscalationAttempt(event *AccessAttemptEvent) bool {
	// Check if user is trying to access resources above their role level
	userRole := event.UserRole
	resourceType := event.ResourceType

	// Define role hierarchy levels (simplified)
	roleLevels := map[string]int{
		"patient":           1,
		"mbbs_student":      2,
		"md_student":        3,
		"receptionist":      3,
		"lab_technician":    4,
		"nurse":             4,
		"clinical_staff":    5,
		"consulting_doctor": 6,
		"administrator":     7,
	}

	// Define resource access levels (simplified)
	resourceLevels := map[string]int{
		"patient_ehr":     3,
		"cpoe_order":      4,
		"lab_result":      4,
		"admin_function":  7,
		"system_config":   7,
	}

	userLevel, userExists := roleLevels[userRole]
	resourceLevel, resourceExists := resourceLevels[resourceType]

	if userExists && resourceExists {
		// If user is trying to access resource above their level
		if userLevel < resourceLevel {
			return true
		}
	}

	return false
}

func (sad *SuspiciousActivityDetector) isUnauthorizedResourceAccess(event *AccessAttemptEvent) bool {
	// Check if user is accessing resources they shouldn't based on their role
	userRole := event.UserRole
	action := event.Action
	resourceType := event.ResourceType

	// Define unauthorized combinations (simplified)
	unauthorizedCombinations := map[string]map[string][]string{
		"patient": {
			"patient_ehr": {"create", "update", "delete"},
			"cpoe_order":  {"create", "update", "delete", "approve"},
			"lab_result":  {"create", "update", "delete"},
		},
		"mbbs_student": {
			"cpoe_order":     {"create", "approve", "sign"},
			"admin_function": {"create", "read", "update", "delete"},
		},
		"receptionist": {
			"cpoe_order":     {"create", "approve", "sign"},
			"lab_result":     {"create", "update", "delete"},
			"admin_function": {"create", "read", "update", "delete"},
		},
	}

	if roleRestrictions, exists := unauthorizedCombinations[userRole]; exists {
		if resourceActions, exists := roleRestrictions[resourceType]; exists {
			for _, unauthorizedAction := range resourceActions {
				if action == unauthorizedAction {
					return true
				}
			}
		}
	}

	return false
}

func (sad *SuspiciousActivityDetector) calculateUserRiskScore(profile *UserActivityProfile) float64 {
	score := 0.0

	// Factor in failure rate
	if profile.AccessCount > 0 {
		failureRate := float64(profile.FailureCount) / float64(profile.AccessCount)
		score += failureRate * 30.0 // Max 30 points for failure rate
	}

	// Factor in consecutive failures
	score += float64(profile.ConsecutiveFailures) * 5.0 // 5 points per consecutive failure

	// Factor in number of unique IPs (more IPs = higher risk)
	if len(profile.IPAddresses) > 3 {
		score += float64(len(profile.IPAddresses)-3) * 2.0 // 2 points per additional IP
	}

	// Factor in after-hours access
	if profile.TimePatterns.BusinessHoursAccess > 0 {
		afterHoursRatio := float64(profile.TimePatterns.AfterHoursAccess) / float64(profile.TimePatterns.BusinessHoursAccess)
		if afterHoursRatio > 0.5 { // More than 50% after hours
			score += afterHoursRatio * 15.0 // Max 15 points
		}
	}

	// Factor in weekend access
	totalAccesses := profile.TimePatterns.BusinessHoursAccess + profile.TimePatterns.AfterHoursAccess
	if totalAccesses > 0 {
		weekendRatio := float64(profile.TimePatterns.WeekendAccess) / float64(totalAccesses)
		if weekendRatio > 0.2 { // More than 20% on weekends
			score += weekendRatio * 10.0 // Max 10 points
		}
	}

	// Cap the score at 100
	if score > 100.0 {
		score = 100.0
	}

	return score
}

func (sad *SuspiciousActivityDetector) calculateIPRiskScore(profile *IPActivityProfile) float64 {
	score := 0.0

	// Factor in failure rate
	if profile.AccessCount > 0 {
		failureRate := float64(profile.FailureCount) / float64(profile.AccessCount)
		score += failureRate * 40.0 // Max 40 points for failure rate
	}

	// Factor in number of users (more users from same IP = higher risk)
	if profile.UserCount > 5 {
		score += float64(profile.UserCount-5) * 3.0 // 3 points per additional user
	}

	// Factor in access frequency
	if !profile.FirstSeen.IsZero() {
		duration := time.Since(profile.FirstSeen)
		if duration > 0 {
			accessRate := float64(profile.AccessCount) / duration.Hours()
			if accessRate > 10 { // More than 10 accesses per hour
				score += (accessRate - 10) * 2.0 // 2 points per additional access per hour
			}
		}
	}

	// Cap the score at 100
	if score > 100.0 {
		score = 100.0
	}

	return score
}

func (sad *SuspiciousActivityDetector) calculateResourceRiskScore(profile *ResourceAccessProfile) float64 {
	score := 0.0

	// Factor in failure rate
	if profile.AccessCount > 0 {
		failureRate := float64(profile.FailureCount) / float64(profile.AccessCount)
		score += failureRate * 50.0 // Max 50 points for failure rate
	}

	// Factor in number of unique users accessing the resource
	if len(profile.UserAccess) > 10 {
		score += float64(len(profile.UserAccess)-10) * 2.0 // 2 points per additional user
	}

	// Factor in number of unique IPs accessing the resource
	if len(profile.IPAccess) > 5 {
		score += float64(len(profile.IPAccess)-5) * 3.0 // 3 points per additional IP
	}

	// Cap the score at 100
	if score > 100.0 {
		score = 100.0
	}

	return score
}

func (sad *SuspiciousActivityDetector) cleanupRoutine(ctx context.Context) {
	for {
		select {
		case <-sad.cleanupTicker.C:
			sad.cleanupOldProfiles()
		case <-ctx.Done():
			return
		case <-sad.stopChan:
			return
		}
	}
}

func (sad *SuspiciousActivityDetector) cleanupOldProfiles() {
	sad.mutex.Lock()
	defer sad.mutex.Unlock()

	cutoff := time.Now().Add(-sad.config.SuspiciousActivityThresholds.ProfileRetentionDuration)

	// Clean up old user profiles
	for userID, profile := range sad.userActivityTracker {
		if profile.LastAccessTime.Before(cutoff) {
			delete(sad.userActivityTracker, userID)
		}
	}

	// Clean up old IP profiles (but keep blacklisted ones)
	for ipAddress, profile := range sad.ipActivityTracker {
		if !profile.IsBlacklisted && profile.LastSeen.Before(cutoff) {
			delete(sad.ipActivityTracker, ipAddress)
		}
	}

	// Clean up old resource profiles
	for resourceID, profile := range sad.resourceAccessTracker {
		if profile.LastAccessTime.Before(cutoff) {
			delete(sad.resourceAccessTracker, resourceID)
		}
	}

	sad.logger.Debug("Cleaned up old activity profiles",
		"user_profiles", len(sad.userActivityTracker),
		"ip_profiles", len(sad.ipActivityTracker),
		"resource_profiles", len(sad.resourceAccessTracker),
	)
}