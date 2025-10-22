package rbac

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
)

// PerformanceMonitor implements RBAC performance monitoring and optimization
type PerformanceMonitor struct {
	db                    *sql.DB
	logger                *logrus.Logger
	config                *Config
	decisionMetrics       *DecisionMetrics
	cacheMetrics          *CachePerformanceMetrics
	optimizationEngine    *OptimizationEngine
	performanceBuffer     chan *PerformanceEvent
	stopChan              chan struct{}
	wg                    sync.WaitGroup
	mutex                 sync.RWMutex
	startTime             time.Time
}

// DecisionMetrics tracks RBAC decision performance metrics
type DecisionMetrics struct {
	TotalDecisions        int64         `json:"total_decisions"`
	AverageLatency        time.Duration `json:"average_latency"`
	P50Latency            time.Duration `json:"p50_latency"`
	P95Latency            time.Duration `json:"p95_latency"`
	P99Latency            time.Duration `json:"p99_latency"`
	MaxLatency            time.Duration `json:"max_latency"`
	MinLatency            time.Duration `json:"min_latency"`
	SlowDecisions         int64         `json:"slow_decisions"`
	FastDecisions         int64         `json:"fast_decisions"`
	DecisionsByRole       map[string]*RoleMetrics `json:"decisions_by_role"`
	DecisionsByResource   map[string]*ResourceMetrics `json:"decisions_by_resource"`
	LatencyTrend          []LatencyDataPoint `json:"latency_trend"`
	LastUpdated           time.Time     `json:"last_updated"`
}

// RoleMetrics tracks performance metrics by role
type RoleMetrics struct {
	Role            string        `json:"role"`
	TotalDecisions  int64         `json:"total_decisions"`
	AverageLatency  time.Duration `json:"average_latency"`
	CacheHitRate    float64       `json:"cache_hit_rate"`
	SlowDecisions   int64         `json:"slow_decisions"`
	LastAccess      time.Time     `json:"last_access"`
}

// ResourceMetrics tracks performance metrics by resource type
type ResourceMetrics struct {
	ResourceType    string        `json:"resource_type"`
	TotalDecisions  int64         `json:"total_decisions"`
	AverageLatency  time.Duration `json:"average_latency"`
	CacheHitRate    float64       `json:"cache_hit_rate"`
	ComplexDecisions int64        `json:"complex_decisions"`
	LastAccess      time.Time     `json:"last_access"`
}

// CachePerformanceMetrics tracks cache performance and efficiency
type CachePerformanceMetrics struct {
	PolicyCacheStats    *CacheStats `json:"policy_cache_stats"`
	DecisionCacheStats  *CacheStats `json:"decision_cache_stats"`
	RolePermCacheStats  *CacheStats `json:"role_perm_cache_stats"`
	AttributeCacheStats *CacheStats `json:"attribute_cache_stats"`
	OverallHitRate      float64     `json:"overall_hit_rate"`
	CacheEfficiency     float64     `json:"cache_efficiency"`
	MemoryUsage         int64       `json:"memory_usage_bytes"`
	EvictionRate        float64     `json:"eviction_rate"`
	LastOptimized       time.Time   `json:"last_optimized"`
}

// CacheStats tracks individual cache performance
type CacheStats struct {
	CacheType       string        `json:"cache_type"`
	TotalRequests   int64         `json:"total_requests"`
	CacheHits       int64         `json:"cache_hits"`
	CacheMisses     int64         `json:"cache_misses"`
	HitRate         float64       `json:"hit_rate"`
	AverageHitTime  time.Duration `json:"average_hit_time"`
	AverageMissTime time.Duration `json:"average_miss_time"`
	CacheSize       int           `json:"cache_size"`
	MaxSize         int           `json:"max_size"`
	Evictions       int64         `json:"evictions"`
	LastEviction    time.Time     `json:"last_eviction"`
}

// PerformanceEvent represents a performance measurement event
type PerformanceEvent struct {
	ID              string                 `json:"id"`
	EventType       string                 `json:"event_type"` // "decision", "cache_hit", "cache_miss"
	UserID          string                 `json:"user_id"`
	UserRole        string                 `json:"user_role"`
	ResourceID      string                 `json:"resource_id"`
	ResourceType    string                 `json:"resource_type"`
	Action          string                 `json:"action"`
	Latency         time.Duration          `json:"latency"`
	CacheHit        bool                   `json:"cache_hit"`
	DecisionResult  bool                   `json:"decision_result"`
	Timestamp       time.Time              `json:"timestamp"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// LatencyDataPoint represents a point in latency trend analysis
type LatencyDataPoint struct {
	Timestamp       time.Time     `json:"timestamp"`
	AverageLatency  time.Duration `json:"average_latency"`
	P95Latency      time.Duration `json:"p95_latency"`
	RequestCount    int64         `json:"request_count"`
}

// OptimizationEngine provides performance optimization recommendations
type OptimizationEngine struct {
	logger                *logrus.Logger
	recommendations       []*OptimizationRecommendation
	lastAnalysis          time.Time
	performanceThresholds *PerformanceThresholds
	mutex                 sync.RWMutex
}

// OptimizationRecommendation represents a performance optimization suggestion
type OptimizationRecommendation struct {
	ID              string                 `json:"id"`
	Type            string                 `json:"type"` // "cache_tuning", "policy_optimization", "resource_allocation"
	Priority        string                 `json:"priority"` // "high", "medium", "low"
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Impact          string                 `json:"impact"`
	Implementation  string                 `json:"implementation"`
	EstimatedGain   string                 `json:"estimated_gain"`
	Complexity      string                 `json:"complexity"`
	CreatedAt       time.Time              `json:"created_at"`
	Status          string                 `json:"status"` // "new", "in_progress", "completed", "dismissed"
	Metadata        map[string]interface{} `json:"metadata"`
}

// PerformanceThresholds defines performance thresholds for optimization
type PerformanceThresholds struct {
	SlowDecisionThreshold    time.Duration `json:"slow_decision_threshold"`
	CacheHitRateThreshold    float64       `json:"cache_hit_rate_threshold"`
	HighLatencyThreshold     time.Duration `json:"high_latency_threshold"`
	CacheEvictionThreshold   float64       `json:"cache_eviction_threshold"`
	MemoryUsageThreshold     int64         `json:"memory_usage_threshold"`
	OptimizationInterval     time.Duration `json:"optimization_interval"`
}

// NewPerformanceMonitor creates a new performance monitor instance
func NewPerformanceMonitor(config *Config, logger *logrus.Logger) (*PerformanceMonitor, error) {
	db, err := sql.Open("postgres", config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	monitor := &PerformanceMonitor{
		db:                db,
		logger:            logger,
		config:            config,
		performanceBuffer: make(chan *PerformanceEvent, config.PerformanceBufferSize),
		stopChan:          make(chan struct{}),
		startTime:         time.Now(),
		decisionMetrics: &DecisionMetrics{
			DecisionsByRole:     make(map[string]*RoleMetrics),
			DecisionsByResource: make(map[string]*ResourceMetrics),
			LatencyTrend:        make([]LatencyDataPoint, 0),
			LastUpdated:         time.Now(),
		},
		cacheMetrics: &CachePerformanceMetrics{
			PolicyCacheStats:    &CacheStats{CacheType: "policy"},
			DecisionCacheStats:  &CacheStats{CacheType: "decision"},
			RolePermCacheStats:  &CacheStats{CacheType: "role_permission"},
			AttributeCacheStats: &CacheStats{CacheType: "attribute"},
		},
	}

	// Initialize optimization engine
	monitor.optimizationEngine = NewOptimizationEngine(logger)

	// Initialize database tables
	if err := monitor.initializeTables(); err != nil {
		return nil, fmt.Errorf("failed to initialize performance monitoring tables: %w", err)
	}

	return monitor, nil
}

// Start starts the performance monitoring service
func (pm *PerformanceMonitor) Start(ctx context.Context) error {
	pm.logger.Info("Starting RBAC performance monitoring service")

	// Start performance event processor
	pm.wg.Add(1)
	go pm.processPerformanceEvents(ctx)

	// Start metrics aggregator
	pm.wg.Add(1)
	go pm.aggregateMetrics(ctx)

	// Start optimization analyzer
	pm.wg.Add(1)
	go pm.runOptimizationAnalysis(ctx)

	pm.logger.Info("RBAC performance monitoring service started successfully")
	return nil
}

// Stop stops the performance monitoring service
func (pm *PerformanceMonitor) Stop() error {
	pm.logger.Info("Stopping RBAC performance monitoring service")

	close(pm.stopChan)
	pm.wg.Wait()

	// Close database connection
	if err := pm.db.Close(); err != nil {
		pm.logger.WithError(err).Warn("Error closing database connection")
	}

	pm.logger.Info("RBAC performance monitoring service stopped")
	return nil
}

// RecordDecisionLatency records RBAC decision latency for monitoring
func (pm *PerformanceMonitor) RecordDecisionLatency(ctx context.Context, req *rbac.AccessRequest, decision *rbac.AccessDecision, latency time.Duration, cacheHit bool) error {
	event := &PerformanceEvent{
		ID:             uuid.New().String(),
		EventType:      "decision",
		UserID:         req.UserID,
		ResourceID:     req.ResourceID,
		Action:         req.Action,
		Latency:        latency,
		CacheHit:       cacheHit,
		DecisionResult: decision.Allowed,
		Timestamp:      time.Now(),
		Metadata:       make(map[string]interface{}),
	}

	// Extract additional context
	if userRole, ok := req.Attributes["role"]; ok {
		event.UserRole = userRole
	}
	if resourceType, ok := req.Attributes["resource_type"]; ok {
		event.ResourceType = resourceType
	}

	// Add decision metadata
	event.Metadata["decision_reason"] = decision.Reason
	event.Metadata["decision_ttl"] = decision.TTL.String()
	if len(decision.Conditions) > 0 {
		event.Metadata["decision_conditions"] = decision.Conditions
	}

	// Send to processing buffer (non-blocking)
	select {
	case pm.performanceBuffer <- event:
		// Successfully queued
	default:
		// Buffer full, log warning and process synchronously
		pm.logger.Warn("Performance buffer full, processing synchronously")
		return pm.processPerformanceEventSync(event)
	}

	return nil
}

// RecordCachePerformance records cache performance metrics
func (pm *PerformanceMonitor) RecordCachePerformance(cacheType string, hit bool, latency time.Duration) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	var stats *CacheStats
	switch cacheType {
	case "policy":
		stats = pm.cacheMetrics.PolicyCacheStats
	case "decision":
		stats = pm.cacheMetrics.DecisionCacheStats
	case "role_permission":
		stats = pm.cacheMetrics.RolePermCacheStats
	case "attribute":
		stats = pm.cacheMetrics.AttributeCacheStats
	default:
		pm.logger.Warn("Unknown cache type", "cache_type", cacheType)
		return
	}

	stats.TotalRequests++
	if hit {
		stats.CacheHits++
		// Update average hit time
		if stats.CacheHits == 1 {
			stats.AverageHitTime = latency
		} else {
			totalTime := stats.AverageHitTime * time.Duration(stats.CacheHits-1)
			stats.AverageHitTime = (totalTime + latency) / time.Duration(stats.CacheHits)
		}
	} else {
		stats.CacheMisses++
		// Update average miss time
		if stats.CacheMisses == 1 {
			stats.AverageMissTime = latency
		} else {
			totalTime := stats.AverageMissTime * time.Duration(stats.CacheMisses-1)
			stats.AverageMissTime = (totalTime + latency) / time.Duration(stats.CacheMisses)
		}
	}

	// Update hit rate
	if stats.TotalRequests > 0 {
		stats.HitRate = float64(stats.CacheHits) / float64(stats.TotalRequests) * 100
	}

	// Update overall cache metrics
	pm.updateOverallCacheMetrics()
}

// GetDecisionMetrics returns current decision performance metrics
func (pm *PerformanceMonitor) GetDecisionMetrics() *DecisionMetrics {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	// Create a deep copy to avoid race conditions
	metrics := &DecisionMetrics{
		TotalDecisions:      pm.decisionMetrics.TotalDecisions,
		AverageLatency:      pm.decisionMetrics.AverageLatency,
		P50Latency:          pm.decisionMetrics.P50Latency,
		P95Latency:          pm.decisionMetrics.P95Latency,
		P99Latency:          pm.decisionMetrics.P99Latency,
		MaxLatency:          pm.decisionMetrics.MaxLatency,
		MinLatency:          pm.decisionMetrics.MinLatency,
		SlowDecisions:       pm.decisionMetrics.SlowDecisions,
		FastDecisions:       pm.decisionMetrics.FastDecisions,
		DecisionsByRole:     make(map[string]*RoleMetrics),
		DecisionsByResource: make(map[string]*ResourceMetrics),
		LatencyTrend:        make([]LatencyDataPoint, len(pm.decisionMetrics.LatencyTrend)),
		LastUpdated:         pm.decisionMetrics.LastUpdated,
	}

	// Copy role metrics
	for role, roleMetrics := range pm.decisionMetrics.DecisionsByRole {
		metrics.DecisionsByRole[role] = &RoleMetrics{
			Role:           roleMetrics.Role,
			TotalDecisions: roleMetrics.TotalDecisions,
			AverageLatency: roleMetrics.AverageLatency,
			CacheHitRate:   roleMetrics.CacheHitRate,
			SlowDecisions:  roleMetrics.SlowDecisions,
			LastAccess:     roleMetrics.LastAccess,
		}
	}

	// Copy resource metrics
	for resource, resourceMetrics := range pm.decisionMetrics.DecisionsByResource {
		metrics.DecisionsByResource[resource] = &ResourceMetrics{
			ResourceType:     resourceMetrics.ResourceType,
			TotalDecisions:   resourceMetrics.TotalDecisions,
			AverageLatency:   resourceMetrics.AverageLatency,
			CacheHitRate:     resourceMetrics.CacheHitRate,
			ComplexDecisions: resourceMetrics.ComplexDecisions,
			LastAccess:       resourceMetrics.LastAccess,
		}
	}

	// Copy latency trend
	copy(metrics.LatencyTrend, pm.decisionMetrics.LatencyTrend)

	return metrics
}

// GetCacheMetrics returns current cache performance metrics
func (pm *PerformanceMonitor) GetCacheMetrics() *CachePerformanceMetrics {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	// Create a deep copy
	return &CachePerformanceMetrics{
		PolicyCacheStats:    pm.copyCacheStats(pm.cacheMetrics.PolicyCacheStats),
		DecisionCacheStats:  pm.copyCacheStats(pm.cacheMetrics.DecisionCacheStats),
		RolePermCacheStats:  pm.copyCacheStats(pm.cacheMetrics.RolePermCacheStats),
		AttributeCacheStats: pm.copyCacheStats(pm.cacheMetrics.AttributeCacheStats),
		OverallHitRate:      pm.cacheMetrics.OverallHitRate,
		CacheEfficiency:     pm.cacheMetrics.CacheEfficiency,
		MemoryUsage:         pm.cacheMetrics.MemoryUsage,
		EvictionRate:        pm.cacheMetrics.EvictionRate,
		LastOptimized:       pm.cacheMetrics.LastOptimized,
	}
}

// GetOptimizationRecommendations returns current optimization recommendations
func (pm *PerformanceMonitor) GetOptimizationRecommendations() []*OptimizationRecommendation {
	return pm.optimizationEngine.GetRecommendations()
}

// UpdateCacheSize updates cache size metrics
func (pm *PerformanceMonitor) UpdateCacheSize(cacheType string, currentSize, maxSize int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	var stats *CacheStats
	switch cacheType {
	case "policy":
		stats = pm.cacheMetrics.PolicyCacheStats
	case "decision":
		stats = pm.cacheMetrics.DecisionCacheStats
	case "role_permission":
		stats = pm.cacheMetrics.RolePermCacheStats
	case "attribute":
		stats = pm.cacheMetrics.AttributeCacheStats
	default:
		return
	}

	stats.CacheSize = currentSize
	stats.MaxSize = maxSize
}

// RecordCacheEviction records cache eviction events
func (pm *PerformanceMonitor) RecordCacheEviction(cacheType string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	var stats *CacheStats
	switch cacheType {
	case "policy":
		stats = pm.cacheMetrics.PolicyCacheStats
	case "decision":
		stats = pm.cacheMetrics.DecisionCacheStats
	case "role_permission":
		stats = pm.cacheMetrics.RolePermCacheStats
	case "attribute":
		stats = pm.cacheMetrics.AttributeCacheStats
	default:
		return
	}

	stats.Evictions++
	stats.LastEviction = time.Now()

	// Update overall eviction rate
	pm.updateOverallCacheMetrics()
}

// Helper methods

func (pm *PerformanceMonitor) initializeTables() error {
	// Create performance events table
	performanceEventsSQL := `
		CREATE TABLE IF NOT EXISTS rbac_performance_events (
			id VARCHAR(36) PRIMARY KEY,
			event_type VARCHAR(50) NOT NULL,
			user_id VARCHAR(100) NOT NULL,
			user_role VARCHAR(50),
			resource_id VARCHAR(100),
			resource_type VARCHAR(50),
			action VARCHAR(50) NOT NULL,
			latency_ms BIGINT NOT NULL,
			cache_hit BOOLEAN NOT NULL,
			decision_result BOOLEAN NOT NULL,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			metadata JSONB,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
		
		CREATE INDEX IF NOT EXISTS idx_performance_events_timestamp ON rbac_performance_events(timestamp);
		CREATE INDEX IF NOT EXISTS idx_performance_events_user_role ON rbac_performance_events(user_role);
		CREATE INDEX IF NOT EXISTS idx_performance_events_resource_type ON rbac_performance_events(resource_type);
		CREATE INDEX IF NOT EXISTS idx_performance_events_latency ON rbac_performance_events(latency_ms);
		CREATE INDEX IF NOT EXISTS idx_performance_events_cache_hit ON rbac_performance_events(cache_hit);
	`

	// Create optimization recommendations table
	optimizationSQL := `
		CREATE TABLE IF NOT EXISTS rbac_optimization_recommendations (
			id VARCHAR(36) PRIMARY KEY,
			type VARCHAR(50) NOT NULL,
			priority VARCHAR(20) NOT NULL,
			title VARCHAR(200) NOT NULL,
			description TEXT,
			impact TEXT,
			implementation TEXT,
			estimated_gain VARCHAR(100),
			complexity VARCHAR(20),
			status VARCHAR(20) DEFAULT 'new',
			metadata JSONB,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
		
		CREATE INDEX IF NOT EXISTS idx_optimization_recommendations_type ON rbac_optimization_recommendations(type);
		CREATE INDEX IF NOT EXISTS idx_optimization_recommendations_priority ON rbac_optimization_recommendations(priority);
		CREATE INDEX IF NOT EXISTS idx_optimization_recommendations_status ON rbac_optimization_recommendations(status);
	`

	if _, err := pm.db.Exec(performanceEventsSQL); err != nil {
		return fmt.Errorf("failed to create performance events table: %w", err)
	}

	if _, err := pm.db.Exec(optimizationSQL); err != nil {
		return fmt.Errorf("failed to create optimization recommendations table: %w", err)
	}

	return nil
}

func (pm *PerformanceMonitor) processPerformanceEvents(ctx context.Context) {
	defer pm.wg.Done()

	for {
		select {
		case event := <-pm.performanceBuffer:
			if err := pm.processPerformanceEventSync(event); err != nil {
				pm.logger.WithError(err).Error("Failed to process performance event")
			}
		case <-ctx.Done():
			pm.logger.Info("Performance event processor stopping")
			return
		case <-pm.stopChan:
			pm.logger.Info("Performance event processor stopping")
			return
		}
	}
}

func (pm *PerformanceMonitor) processPerformanceEventSync(event *PerformanceEvent) error {
	// Store event in database
	if err := pm.insertPerformanceEvent(event); err != nil {
		return fmt.Errorf("failed to insert performance event: %w", err)
	}

	// Update real-time metrics
	pm.updateDecisionMetrics(event)

	return nil
}

func (pm *PerformanceMonitor) updateDecisionMetrics(event *PerformanceEvent) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Update overall metrics
	pm.decisionMetrics.TotalDecisions++
	
	// Update latency statistics
	if pm.decisionMetrics.TotalDecisions == 1 {
		pm.decisionMetrics.AverageLatency = event.Latency
		pm.decisionMetrics.MinLatency = event.Latency
		pm.decisionMetrics.MaxLatency = event.Latency
	} else {
		// Update average latency
		totalTime := pm.decisionMetrics.AverageLatency * time.Duration(pm.decisionMetrics.TotalDecisions-1)
		pm.decisionMetrics.AverageLatency = (totalTime + event.Latency) / time.Duration(pm.decisionMetrics.TotalDecisions)
		
		// Update min/max latency
		if event.Latency < pm.decisionMetrics.MinLatency {
			pm.decisionMetrics.MinLatency = event.Latency
		}
		if event.Latency > pm.decisionMetrics.MaxLatency {
			pm.decisionMetrics.MaxLatency = event.Latency
		}
	}

	// Classify as slow or fast decision
	slowThreshold := 100 * time.Millisecond // Configurable threshold
	if event.Latency > slowThreshold {
		pm.decisionMetrics.SlowDecisions++
	} else {
		pm.decisionMetrics.FastDecisions++
	}

	// Update role-specific metrics
	if event.UserRole != "" {
		roleMetrics, exists := pm.decisionMetrics.DecisionsByRole[event.UserRole]
		if !exists {
			roleMetrics = &RoleMetrics{
				Role: event.UserRole,
			}
			pm.decisionMetrics.DecisionsByRole[event.UserRole] = roleMetrics
		}
		pm.updateRoleMetrics(roleMetrics, event)
	}

	// Update resource-specific metrics
	if event.ResourceType != "" {
		resourceMetrics, exists := pm.decisionMetrics.DecisionsByResource[event.ResourceType]
		if !exists {
			resourceMetrics = &ResourceMetrics{
				ResourceType: event.ResourceType,
			}
			pm.decisionMetrics.DecisionsByResource[event.ResourceType] = resourceMetrics
		}
		pm.updateResourceMetrics(resourceMetrics, event)
	}

	pm.decisionMetrics.LastUpdated = time.Now()
}

func (pm *PerformanceMonitor) updateRoleMetrics(roleMetrics *RoleMetrics, event *PerformanceEvent) {
	roleMetrics.TotalDecisions++
	roleMetrics.LastAccess = event.Timestamp

	// Update average latency
	if roleMetrics.TotalDecisions == 1 {
		roleMetrics.AverageLatency = event.Latency
	} else {
		totalTime := roleMetrics.AverageLatency * time.Duration(roleMetrics.TotalDecisions-1)
		roleMetrics.AverageLatency = (totalTime + event.Latency) / time.Duration(roleMetrics.TotalDecisions)
	}

	// Update cache hit rate (simplified calculation)
	if event.CacheHit {
		roleMetrics.CacheHitRate = (roleMetrics.CacheHitRate*float64(roleMetrics.TotalDecisions-1) + 100) / float64(roleMetrics.TotalDecisions)
	} else {
		roleMetrics.CacheHitRate = (roleMetrics.CacheHitRate * float64(roleMetrics.TotalDecisions-1)) / float64(roleMetrics.TotalDecisions)
	}

	// Count slow decisions
	if event.Latency > 100*time.Millisecond {
		roleMetrics.SlowDecisions++
	}
}

func (pm *PerformanceMonitor) updateResourceMetrics(resourceMetrics *ResourceMetrics, event *PerformanceEvent) {
	resourceMetrics.TotalDecisions++
	resourceMetrics.LastAccess = event.Timestamp

	// Update average latency
	if resourceMetrics.TotalDecisions == 1 {
		resourceMetrics.AverageLatency = event.Latency
	} else {
		totalTime := resourceMetrics.AverageLatency * time.Duration(resourceMetrics.TotalDecisions-1)
		resourceMetrics.AverageLatency = (totalTime + event.Latency) / time.Duration(resourceMetrics.TotalDecisions)
	}

	// Update cache hit rate
	if event.CacheHit {
		resourceMetrics.CacheHitRate = (resourceMetrics.CacheHitRate*float64(resourceMetrics.TotalDecisions-1) + 100) / float64(resourceMetrics.TotalDecisions)
	} else {
		resourceMetrics.CacheHitRate = (resourceMetrics.CacheHitRate * float64(resourceMetrics.TotalDecisions-1)) / float64(resourceMetrics.TotalDecisions)
	}

	// Count complex decisions (those with multiple conditions or attributes)
	if conditions, ok := event.Metadata["decision_conditions"].([]string); ok && len(conditions) > 1 {
		resourceMetrics.ComplexDecisions++
	}
}

func (pm *PerformanceMonitor) updateOverallCacheMetrics() {
	// Calculate overall hit rate
	totalRequests := pm.cacheMetrics.PolicyCacheStats.TotalRequests +
		pm.cacheMetrics.DecisionCacheStats.TotalRequests +
		pm.cacheMetrics.RolePermCacheStats.TotalRequests +
		pm.cacheMetrics.AttributeCacheStats.TotalRequests

	totalHits := pm.cacheMetrics.PolicyCacheStats.CacheHits +
		pm.cacheMetrics.DecisionCacheStats.CacheHits +
		pm.cacheMetrics.RolePermCacheStats.CacheHits +
		pm.cacheMetrics.AttributeCacheStats.CacheHits

	if totalRequests > 0 {
		pm.cacheMetrics.OverallHitRate = float64(totalHits) / float64(totalRequests) * 100
	}

	// Calculate cache efficiency (hit rate weighted by cache size utilization)
	totalSize := pm.cacheMetrics.PolicyCacheStats.CacheSize +
		pm.cacheMetrics.DecisionCacheStats.CacheSize +
		pm.cacheMetrics.RolePermCacheStats.CacheSize +
		pm.cacheMetrics.AttributeCacheStats.CacheSize

	totalMaxSize := pm.cacheMetrics.PolicyCacheStats.MaxSize +
		pm.cacheMetrics.DecisionCacheStats.MaxSize +
		pm.cacheMetrics.RolePermCacheStats.MaxSize +
		pm.cacheMetrics.AttributeCacheStats.MaxSize

	if totalMaxSize > 0 {
		utilizationRate := float64(totalSize) / float64(totalMaxSize) * 100
		pm.cacheMetrics.CacheEfficiency = pm.cacheMetrics.OverallHitRate * (utilizationRate / 100)
	}

	// Calculate eviction rate
	totalEvictions := pm.cacheMetrics.PolicyCacheStats.Evictions +
		pm.cacheMetrics.DecisionCacheStats.Evictions +
		pm.cacheMetrics.RolePermCacheStats.Evictions +
		pm.cacheMetrics.AttributeCacheStats.Evictions

	if totalRequests > 0 {
		pm.cacheMetrics.EvictionRate = float64(totalEvictions) / float64(totalRequests) * 100
	}
}

func (pm *PerformanceMonitor) aggregateMetrics(ctx context.Context) {
	defer pm.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.calculatePercentileLatencies()
			pm.updateLatencyTrend()
		case <-ctx.Done():
			pm.logger.Info("Metrics aggregator stopping")
			return
		case <-pm.stopChan:
			pm.logger.Info("Metrics aggregator stopping")
			return
		}
	}
}

func (pm *PerformanceMonitor) calculatePercentileLatencies() {
	// This would typically query recent performance events from the database
	// and calculate percentiles. For now, we'll use a simplified approach.
	
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// In a real implementation, you would:
	// 1. Query recent performance events from the database
	// 2. Sort latencies
	// 3. Calculate actual percentiles
	
	// Simplified calculation based on current metrics
	if pm.decisionMetrics.TotalDecisions > 0 {
		// Estimate percentiles based on average and max latencies
		pm.decisionMetrics.P50Latency = pm.decisionMetrics.AverageLatency
		pm.decisionMetrics.P95Latency = time.Duration(float64(pm.decisionMetrics.AverageLatency) * 1.5)
		pm.decisionMetrics.P99Latency = time.Duration(float64(pm.decisionMetrics.MaxLatency) * 0.9)
	}
}

func (pm *PerformanceMonitor) updateLatencyTrend() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Add current metrics to trend
	dataPoint := LatencyDataPoint{
		Timestamp:      time.Now(),
		AverageLatency: pm.decisionMetrics.AverageLatency,
		P95Latency:     pm.decisionMetrics.P95Latency,
		RequestCount:   pm.decisionMetrics.TotalDecisions,
	}

	pm.decisionMetrics.LatencyTrend = append(pm.decisionMetrics.LatencyTrend, dataPoint)

	// Keep only last 24 hours of data points (assuming 1-minute intervals)
	maxDataPoints := 24 * 60
	if len(pm.decisionMetrics.LatencyTrend) > maxDataPoints {
		pm.decisionMetrics.LatencyTrend = pm.decisionMetrics.LatencyTrend[len(pm.decisionMetrics.LatencyTrend)-maxDataPoints:]
	}
}

func (pm *PerformanceMonitor) runOptimizationAnalysis(ctx context.Context) {
	defer pm.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.optimizationEngine.AnalyzePerformance(pm.GetDecisionMetrics(), pm.GetCacheMetrics())
		case <-ctx.Done():
			pm.logger.Info("Optimization analyzer stopping")
			return
		case <-pm.stopChan:
			pm.logger.Info("Optimization analyzer stopping")
			return
		}
	}
}

func (pm *PerformanceMonitor) insertPerformanceEvent(event *PerformanceEvent) error {
	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO rbac_performance_events 
		(id, event_type, user_id, user_role, resource_id, resource_type, action, 
		 latency_ms, cache_hit, decision_result, timestamp, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err = pm.db.Exec(query,
		event.ID,
		event.EventType,
		event.UserID,
		pm.nullString(event.UserRole),
		pm.nullString(event.ResourceID),
		pm.nullString(event.ResourceType),
		event.Action,
		event.Latency.Milliseconds(),
		event.CacheHit,
		event.DecisionResult,
		event.Timestamp,
		metadataJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to insert performance event: %w", err)
	}

	return nil
}

func (pm *PerformanceMonitor) copyCacheStats(original *CacheStats) *CacheStats {
	return &CacheStats{
		CacheType:       original.CacheType,
		TotalRequests:   original.TotalRequests,
		CacheHits:       original.CacheHits,
		CacheMisses:     original.CacheMisses,
		HitRate:         original.HitRate,
		AverageHitTime:  original.AverageHitTime,
		AverageMissTime: original.AverageMissTime,
		CacheSize:       original.CacheSize,
		MaxSize:         original.MaxSize,
		Evictions:       original.Evictions,
		LastEviction:    original.LastEviction,
	}
}

func (pm *PerformanceMonitor) nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}