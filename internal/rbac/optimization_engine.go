package rbac

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// NewOptimizationEngine creates a new optimization engine
func NewOptimizationEngine(logger *logrus.Logger) *OptimizationEngine {
	return &OptimizationEngine{
		logger:          logger,
		recommendations: make([]*OptimizationRecommendation, 0),
		lastAnalysis:    time.Now(),
		performanceThresholds: &PerformanceThresholds{
			SlowDecisionThreshold:  100 * time.Millisecond,
			CacheHitRateThreshold:  80.0, // 80%
			HighLatencyThreshold:   500 * time.Millisecond,
			CacheEvictionThreshold: 10.0, // 10%
			MemoryUsageThreshold:   1024 * 1024 * 1024, // 1GB
			OptimizationInterval:   5 * time.Minute,
		},
	}
}

// AnalyzePerformance analyzes current performance metrics and generates optimization recommendations
func (oe *OptimizationEngine) AnalyzePerformance(decisionMetrics *DecisionMetrics, cacheMetrics *CachePerformanceMetrics) {
	oe.mutex.Lock()
	defer oe.mutex.Unlock()

	oe.logger.Info("Starting performance analysis for optimization recommendations")

	// Clear old recommendations
	oe.recommendations = make([]*OptimizationRecommendation, 0)

	// Analyze decision latency performance
	oe.analyzeDecisionLatency(decisionMetrics)

	// Analyze cache performance
	oe.analyzeCachePerformance(cacheMetrics)

	// Analyze role-specific performance
	oe.analyzeRolePerformance(decisionMetrics)

	// Analyze resource-specific performance
	oe.analyzeResourcePerformance(decisionMetrics)

	// Analyze system-wide patterns
	oe.analyzeSystemPatterns(decisionMetrics, cacheMetrics)

	// Sort recommendations by priority
	oe.sortRecommendationsByPriority()

	oe.lastAnalysis = time.Now()
	oe.logger.Info("Performance analysis completed", "recommendations_count", len(oe.recommendations))
}

// GetRecommendations returns current optimization recommendations
func (oe *OptimizationEngine) GetRecommendations() []*OptimizationRecommendation {
	oe.mutex.RLock()
	defer oe.mutex.RUnlock()

	// Return a copy to avoid race conditions
	recommendations := make([]*OptimizationRecommendation, len(oe.recommendations))
	copy(recommendations, oe.recommendations)
	return recommendations
}

// GetRecommendationsByType returns recommendations filtered by type
func (oe *OptimizationEngine) GetRecommendationsByType(recommendationType string) []*OptimizationRecommendation {
	oe.mutex.RLock()
	defer oe.mutex.RUnlock()

	var filtered []*OptimizationRecommendation
	for _, rec := range oe.recommendations {
		if rec.Type == recommendationType {
			filtered = append(filtered, rec)
		}
	}
	return filtered
}

// MarkRecommendationCompleted marks a recommendation as completed
func (oe *OptimizationEngine) MarkRecommendationCompleted(recommendationID string) error {
	oe.mutex.Lock()
	defer oe.mutex.Unlock()

	for _, rec := range oe.recommendations {
		if rec.ID == recommendationID {
			rec.Status = "completed"
			oe.logger.Info("Recommendation marked as completed", "recommendation_id", recommendationID)
			return nil
		}
	}

	return fmt.Errorf("recommendation not found: %s", recommendationID)
}

// DismissRecommendation dismisses a recommendation
func (oe *OptimizationEngine) DismissRecommendation(recommendationID string) error {
	oe.mutex.Lock()
	defer oe.mutex.Unlock()

	for _, rec := range oe.recommendations {
		if rec.ID == recommendationID {
			rec.Status = "dismissed"
			oe.logger.Info("Recommendation dismissed", "recommendation_id", recommendationID)
			return nil
		}
	}

	return fmt.Errorf("recommendation not found: %s", recommendationID)
}

// Private analysis methods

func (oe *OptimizationEngine) analyzeDecisionLatency(metrics *DecisionMetrics) {
	if metrics.TotalDecisions == 0 {
		return
	}

	// Check for high average latency
	if metrics.AverageLatency > oe.performanceThresholds.HighLatencyThreshold {
		oe.addRecommendation(&OptimizationRecommendation{
			Type:        "performance_tuning",
			Priority:    "high",
			Title:       "High Average Decision Latency Detected",
			Description: fmt.Sprintf("Average RBAC decision latency is %v, which exceeds the threshold of %v", metrics.AverageLatency, oe.performanceThresholds.HighLatencyThreshold),
			Impact:      "High latency affects user experience and system responsiveness",
			Implementation: "Consider optimizing role hierarchy depth, reducing policy complexity, or implementing more aggressive caching",
			EstimatedGain: fmt.Sprintf("Potential %d%% latency reduction", calculateLatencyReductionPotential(metrics.AverageLatency)),
			Complexity:  "medium",
			Metadata: map[string]interface{}{
				"current_latency": metrics.AverageLatency.String(),
				"threshold":       oe.performanceThresholds.HighLatencyThreshold.String(),
				"p95_latency":     metrics.P95Latency.String(),
			},
		})
	}

	// Check for high percentage of slow decisions
	if metrics.TotalDecisions > 0 {
		slowPercentage := float64(metrics.SlowDecisions) / float64(metrics.TotalDecisions) * 100
		if slowPercentage > 20.0 { // More than 20% slow decisions
			oe.addRecommendation(&OptimizationRecommendation{
				Type:        "policy_optimization",
				Priority:    "medium",
				Title:       "High Percentage of Slow Decisions",
				Description: fmt.Sprintf("%.1f%% of RBAC decisions are classified as slow (>%v)", slowPercentage, oe.performanceThresholds.SlowDecisionThreshold),
				Impact:      "Slow decisions impact overall system performance and user experience",
				Implementation: "Review and optimize complex policies, consider policy simplification or pre-computation",
				EstimatedGain: fmt.Sprintf("Potential %d%% improvement in decision speed", int(slowPercentage/2)),
				Complexity:  "medium",
				Metadata: map[string]interface{}{
					"slow_percentage":    slowPercentage,
					"slow_decisions":     metrics.SlowDecisions,
					"total_decisions":    metrics.TotalDecisions,
					"slow_threshold":     oe.performanceThresholds.SlowDecisionThreshold.String(),
				},
			})
		}
	}

	// Check P95 latency
	if metrics.P95Latency > 2*oe.performanceThresholds.HighLatencyThreshold {
		oe.addRecommendation(&OptimizationRecommendation{
			Type:        "performance_tuning",
			Priority:    "high",
			Title:       "High P95 Latency Indicates Performance Outliers",
			Description: fmt.Sprintf("P95 latency is %v, indicating significant performance outliers", metrics.P95Latency),
			Impact:      "Performance outliers can severely impact user experience for some requests",
			Implementation: "Investigate and optimize worst-case scenarios, consider request prioritization or circuit breakers",
			EstimatedGain: "Improved consistency and reduced worst-case latency",
			Complexity:  "high",
			Metadata: map[string]interface{}{
				"p95_latency":     metrics.P95Latency.String(),
				"average_latency": metrics.AverageLatency.String(),
				"max_latency":     metrics.MaxLatency.String(),
			},
		})
	}
}

func (oe *OptimizationEngine) analyzeCachePerformance(metrics *CachePerformanceMetrics) {
	// Analyze overall cache hit rate
	if metrics.OverallHitRate < oe.performanceThresholds.CacheHitRateThreshold {
		oe.addRecommendation(&OptimizationRecommendation{
			Type:        "cache_tuning",
			Priority:    "high",
			Title:       "Low Overall Cache Hit Rate",
			Description: fmt.Sprintf("Overall cache hit rate is %.1f%%, below the target of %.1f%%", metrics.OverallHitRate, oe.performanceThresholds.CacheHitRateThreshold),
			Impact:      "Low cache hit rate leads to increased latency and higher resource utilization",
			Implementation: "Increase cache sizes, optimize cache eviction policies, or improve cache key strategies",
			EstimatedGain: fmt.Sprintf("Potential %d%% latency reduction with improved caching", int((oe.performanceThresholds.CacheHitRateThreshold-metrics.OverallHitRate)/2)),
			Complexity:  "low",
			Metadata: map[string]interface{}{
				"current_hit_rate": metrics.OverallHitRate,
				"target_hit_rate":  oe.performanceThresholds.CacheHitRateThreshold,
				"cache_efficiency": metrics.CacheEfficiency,
			},
		})
	}

	// Analyze individual cache performance
	caches := []*CacheStats{
		metrics.PolicyCacheStats,
		metrics.DecisionCacheStats,
		metrics.RolePermCacheStats,
		metrics.AttributeCacheStats,
	}

	for _, cache := range caches {
		if cache.TotalRequests > 0 && cache.HitRate < oe.performanceThresholds.CacheHitRateThreshold {
			oe.addRecommendation(&OptimizationRecommendation{
				Type:        "cache_tuning",
				Priority:    "medium",
				Title:       fmt.Sprintf("Low %s Cache Hit Rate", cache.CacheType),
				Description: fmt.Sprintf("%s cache hit rate is %.1f%%, below optimal performance", cache.CacheType, cache.HitRate),
				Impact:      fmt.Sprintf("Poor %s cache performance affects related operations", cache.CacheType),
				Implementation: fmt.Sprintf("Optimize %s cache size, TTL settings, or key generation strategy", cache.CacheType),
				EstimatedGain: fmt.Sprintf("Improved %s cache performance", cache.CacheType),
				Complexity:  "low",
				Metadata: map[string]interface{}{
					"cache_type":    cache.CacheType,
					"hit_rate":      cache.HitRate,
					"cache_size":    cache.CacheSize,
					"max_size":      cache.MaxSize,
					"evictions":     cache.Evictions,
				},
			})
		}
	}

	// Check for high eviction rate
	if metrics.EvictionRate > oe.performanceThresholds.CacheEvictionThreshold {
		oe.addRecommendation(&OptimizationRecommendation{
			Type:        "resource_allocation",
			Priority:    "medium",
			Title:       "High Cache Eviction Rate",
			Description: fmt.Sprintf("Cache eviction rate is %.1f%%, indicating insufficient cache capacity", metrics.EvictionRate),
			Impact:      "High eviction rate reduces cache effectiveness and increases latency",
			Implementation: "Increase cache sizes or optimize cache eviction policies to reduce unnecessary evictions",
			EstimatedGain: "Improved cache stability and reduced latency variance",
			Complexity:  "low",
			Metadata: map[string]interface{}{
				"eviction_rate":     metrics.EvictionRate,
				"eviction_threshold": oe.performanceThresholds.CacheEvictionThreshold,
				"memory_usage":      metrics.MemoryUsage,
			},
		})
	}

	// Check cache efficiency
	if metrics.CacheEfficiency < 60.0 { // Less than 60% efficiency
		oe.addRecommendation(&OptimizationRecommendation{
			Type:        "cache_tuning",
			Priority:    "medium",
			Title:       "Low Cache Efficiency",
			Description: fmt.Sprintf("Cache efficiency is %.1f%%, indicating suboptimal cache utilization", metrics.CacheEfficiency),
			Impact:      "Low cache efficiency means caches are not providing optimal performance benefits",
			Implementation: "Review cache sizing, improve cache key strategies, or implement smarter eviction policies",
			EstimatedGain: "Better resource utilization and improved performance",
			Complexity:  "medium",
			Metadata: map[string]interface{}{
				"cache_efficiency": metrics.CacheEfficiency,
				"overall_hit_rate": metrics.OverallHitRate,
				"memory_usage":     metrics.MemoryUsage,
			},
		})
	}
}

func (oe *OptimizationEngine) analyzeRolePerformance(metrics *DecisionMetrics) {
	// Find roles with poor performance
	var rolePerformanceIssues []string

	for role, roleMetrics := range metrics.DecisionsByRole {
		// Check for high latency roles
		if roleMetrics.AverageLatency > oe.performanceThresholds.HighLatencyThreshold {
			rolePerformanceIssues = append(rolePerformanceIssues, role)
		}

		// Check for low cache hit rate
		if roleMetrics.CacheHitRate < oe.performanceThresholds.CacheHitRateThreshold {
			oe.addRecommendation(&OptimizationRecommendation{
				Type:        "role_optimization",
				Priority:    "medium",
				Title:       fmt.Sprintf("Poor Cache Performance for %s Role", role),
				Description: fmt.Sprintf("Role %s has a cache hit rate of %.1f%%, below optimal performance", role, roleMetrics.CacheHitRate),
				Impact:      fmt.Sprintf("Poor cache performance affects all users with %s role", role),
				Implementation: fmt.Sprintf("Optimize caching strategy for %s role permissions and policies", role),
				EstimatedGain: fmt.Sprintf("Improved performance for %s role users", role),
				Complexity:  "medium",
				Metadata: map[string]interface{}{
					"role":              role,
					"cache_hit_rate":    roleMetrics.CacheHitRate,
					"average_latency":   roleMetrics.AverageLatency.String(),
					"total_decisions":   roleMetrics.TotalDecisions,
				},
			})
		}

		// Check for high percentage of slow decisions
		if roleMetrics.TotalDecisions > 0 {
			slowPercentage := float64(roleMetrics.SlowDecisions) / float64(roleMetrics.TotalDecisions) * 100
			if slowPercentage > 30.0 { // More than 30% slow for this role
				oe.addRecommendation(&OptimizationRecommendation{
					Type:        "role_optimization",
					Priority:    "high",
					Title:       fmt.Sprintf("High Slow Decision Rate for %s Role", role),
					Description: fmt.Sprintf("Role %s has %.1f%% slow decisions, indicating complex permission evaluation", role, slowPercentage),
					Impact:      fmt.Sprintf("Slow decisions significantly impact %s role user experience", role),
					Implementation: fmt.Sprintf("Simplify permission structure for %s role or implement role-specific optimizations", role),
					EstimatedGain: fmt.Sprintf("Faster access decisions for %s role users", role),
					Complexity:  "high",
					Metadata: map[string]interface{}{
						"role":             role,
						"slow_percentage":  slowPercentage,
						"slow_decisions":   roleMetrics.SlowDecisions,
						"total_decisions":  roleMetrics.TotalDecisions,
					},
				})
			}
		}
	}

	// Recommend role hierarchy optimization if multiple roles have issues
	if len(rolePerformanceIssues) > 2 {
		oe.addRecommendation(&OptimizationRecommendation{
			Type:        "policy_optimization",
			Priority:    "high",
			Title:       "Multiple Roles Show Performance Issues",
			Description: fmt.Sprintf("Multiple roles (%s) show performance issues, indicating systemic problems", rolePerformanceIssues),
			Impact:      "Systemic performance issues affect multiple user groups",
			Implementation: "Review and optimize role hierarchy, consider flattening complex inheritance chains",
			EstimatedGain: "System-wide performance improvement",
			Complexity:  "high",
			Metadata: map[string]interface{}{
				"affected_roles": rolePerformanceIssues,
				"issue_count":    len(rolePerformanceIssues),
			},
		})
	}
}

func (oe *OptimizationEngine) analyzeResourcePerformance(metrics *DecisionMetrics) {
	// Find resources with poor performance
	for resourceType, resourceMetrics := range metrics.DecisionsByResource {
		// Check for high latency resources
		if resourceMetrics.AverageLatency > oe.performanceThresholds.HighLatencyThreshold {
			oe.addRecommendation(&OptimizationRecommendation{
				Type:        "resource_optimization",
				Priority:    "medium",
				Title:       fmt.Sprintf("High Latency for %s Resources", resourceType),
				Description: fmt.Sprintf("Resource type %s has average latency of %v, above optimal performance", resourceType, resourceMetrics.AverageLatency),
				Impact:      fmt.Sprintf("High latency affects all access to %s resources", resourceType),
				Implementation: fmt.Sprintf("Optimize access policies for %s resources or implement resource-specific caching", resourceType),
				EstimatedGain: fmt.Sprintf("Faster access to %s resources", resourceType),
				Complexity:  "medium",
				Metadata: map[string]interface{}{
					"resource_type":     resourceType,
					"average_latency":   resourceMetrics.AverageLatency.String(),
					"total_decisions":   resourceMetrics.TotalDecisions,
					"cache_hit_rate":    resourceMetrics.CacheHitRate,
				},
			})
		}

		// Check for high complexity resources
		if resourceMetrics.TotalDecisions > 0 {
			complexityPercentage := float64(resourceMetrics.ComplexDecisions) / float64(resourceMetrics.TotalDecisions) * 100
			if complexityPercentage > 50.0 { // More than 50% complex decisions
				oe.addRecommendation(&OptimizationRecommendation{
					Type:        "policy_optimization",
					Priority:    "medium",
					Title:       fmt.Sprintf("High Complexity for %s Resource Access", resourceType),
					Description: fmt.Sprintf("Resource type %s has %.1f%% complex access decisions", resourceType, complexityPercentage),
					Impact:      fmt.Sprintf("Complex decisions slow down access to %s resources", resourceType),
					Implementation: fmt.Sprintf("Simplify access policies for %s resources or pre-compute common access patterns", resourceType),
					EstimatedGain: fmt.Sprintf("Simplified and faster access to %s resources", resourceType),
					Complexity:  "medium",
					Metadata: map[string]interface{}{
						"resource_type":        resourceType,
						"complexity_percentage": complexityPercentage,
						"complex_decisions":    resourceMetrics.ComplexDecisions,
						"total_decisions":      resourceMetrics.TotalDecisions,
					},
				})
			}
		}
	}
}

func (oe *OptimizationEngine) analyzeSystemPatterns(decisionMetrics *DecisionMetrics, cacheMetrics *CachePerformanceMetrics) {
	// Analyze latency trends
	if len(decisionMetrics.LatencyTrend) > 10 {
		// Check if latency is trending upward
		recentTrend := decisionMetrics.LatencyTrend[len(decisionMetrics.LatencyTrend)-10:]
		if oe.isLatencyTrendingUp(recentTrend) {
			oe.addRecommendation(&OptimizationRecommendation{
				Type:        "performance_tuning",
				Priority:    "high",
				Title:       "Latency Trending Upward",
				Description: "RBAC decision latency shows an upward trend over recent time periods",
				Impact:      "Increasing latency indicates potential performance degradation",
				Implementation: "Investigate recent changes, monitor resource usage, and consider system scaling",
				EstimatedGain: "Prevent further performance degradation",
				Complexity:  "high",
				Metadata: map[string]interface{}{
					"trend_analysis": "upward",
					"data_points":    len(recentTrend),
				},
			})
		}
	}

	// Check for memory usage concerns
	if cacheMetrics.MemoryUsage > oe.performanceThresholds.MemoryUsageThreshold {
		oe.addRecommendation(&OptimizationRecommendation{
			Type:        "resource_allocation",
			Priority:    "high",
			Title:       "High Memory Usage",
			Description: fmt.Sprintf("RBAC system memory usage is %d bytes, exceeding threshold", cacheMetrics.MemoryUsage),
			Impact:      "High memory usage can lead to system instability and performance issues",
			Implementation: "Optimize cache sizes, implement memory-efficient data structures, or increase system memory",
			EstimatedGain: "Improved system stability and performance",
			Complexity:  "medium",
			Metadata: map[string]interface{}{
				"memory_usage":  cacheMetrics.MemoryUsage,
				"threshold":     oe.performanceThresholds.MemoryUsageThreshold,
			},
		})
	}

	// Check for system load patterns
	if decisionMetrics.TotalDecisions > 0 {
		decisionsPerMinute := float64(decisionMetrics.TotalDecisions) / time.Since(time.Now().Add(-24*time.Hour)).Minutes()
		if decisionsPerMinute > 1000 { // High load threshold
			oe.addRecommendation(&OptimizationRecommendation{
				Type:        "resource_allocation",
				Priority:    "medium",
				Title:       "High System Load Detected",
				Description: fmt.Sprintf("System is processing %.1f RBAC decisions per minute", decisionsPerMinute),
				Impact:      "High load may require system scaling or optimization",
				Implementation: "Consider horizontal scaling, load balancing, or performance optimizations",
				EstimatedGain: "Better handling of high load scenarios",
				Complexity:  "high",
				Metadata: map[string]interface{}{
					"decisions_per_minute": decisionsPerMinute,
					"total_decisions":      decisionMetrics.TotalDecisions,
				},
			})
		}
	}
}

func (oe *OptimizationEngine) addRecommendation(rec *OptimizationRecommendation) {
	rec.ID = uuid.New().String()
	rec.CreatedAt = time.Now()
	rec.Status = "new"
	oe.recommendations = append(oe.recommendations, rec)
}

func (oe *OptimizationEngine) sortRecommendationsByPriority() {
	priorityOrder := map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
	}

	sort.Slice(oe.recommendations, func(i, j int) bool {
		return priorityOrder[oe.recommendations[i].Priority] < priorityOrder[oe.recommendations[j].Priority]
	})
}

func (oe *OptimizationEngine) isLatencyTrendingUp(trend []LatencyDataPoint) bool {
	if len(trend) < 5 {
		return false
	}

	// Simple trend analysis: compare first half with second half
	midPoint := len(trend) / 2
	firstHalfAvg := oe.calculateAverageLatency(trend[:midPoint])
	secondHalfAvg := oe.calculateAverageLatency(trend[midPoint:])

	// Consider trending up if second half is 20% higher than first half
	return secondHalfAvg > time.Duration(float64(firstHalfAvg)*1.2)
}

func (oe *OptimizationEngine) calculateAverageLatency(trend []LatencyDataPoint) time.Duration {
	if len(trend) == 0 {
		return 0
	}

	var total time.Duration
	for _, point := range trend {
		total += point.AverageLatency
	}
	return total / time.Duration(len(trend))
}

// Helper function to calculate latency reduction potential
func calculateLatencyReductionPotential(currentLatency time.Duration) int {
	// Simple heuristic: higher latency has more reduction potential
	if currentLatency > 1*time.Second {
		return 50
	} else if currentLatency > 500*time.Millisecond {
		return 30
	} else if currentLatency > 200*time.Millisecond {
		return 20
	}
	return 10
}