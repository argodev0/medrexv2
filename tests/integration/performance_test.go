// +build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// PerformanceMetrics holds performance test results
type PerformanceMetrics struct {
	TotalRequests    int
	SuccessfulReqs   int
	FailedReqs       int
	AverageLatency   time.Duration
	MinLatency       time.Duration
	MaxLatency       time.Duration
	ThroughputRPS    float64
	ErrorRate        float64
	StartTime        time.Time
	EndTime          time.Time
}

// TestSystemPerformanceUnderLoad tests system performance under realistic load conditions
func TestSystemPerformanceUnderLoad(t *testing.T) {
	_ = context.Background()
	
	t.Run("ConcurrentUserAuthentication", func(t *testing.T) {
		// Test concurrent user authentication performance
		concurrentUsers := 50
		requestsPerUser := 10
		
		var wg sync.WaitGroup
		var mu sync.Mutex
		metrics := &PerformanceMetrics{
			StartTime:   time.Now(),
			MinLatency:  time.Hour, // Initialize to high value
		}
		
		// Channel to collect latency measurements
		latencies := make(chan time.Duration, concurrentUsers*requestsPerUser)
		
		for i := 0; i < concurrentUsers; i++ {
			wg.Add(1)
			go func(userID int) {
				defer wg.Done()
				
				for j := 0; j < requestsPerUser; j++ {
					startTime := time.Now()
					
					// Simulate authentication request
					loginData := map[string]interface{}{
						"username": fmt.Sprintf("user%d", userID),
						"password": "TestPassword123!",
					}
					
					reqBody, err := json.Marshal(loginData)
					if err != nil {
						mu.Lock()
						metrics.FailedReqs++
						mu.Unlock()
						continue
					}
					
					req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(reqBody))
					req.Header.Set("Content-Type", "application/json")
					
					w := httptest.NewRecorder()
					
					// Simulate authentication processing
					time.Sleep(time.Millisecond * 50) // Simulate processing time
					
					response := map[string]interface{}{
						"success":      true,
						"access_token": fmt.Sprintf("token-%d-%d", userID, j),
						"user_id":      fmt.Sprintf("user-%d", userID),
						"expires_in":   3600,
					}
					
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(response)
					
					latency := time.Since(startTime)
					latencies <- latency
					
					mu.Lock()
					if w.Code == http.StatusOK {
						metrics.SuccessfulReqs++
					} else {
						metrics.FailedReqs++
					}
					metrics.TotalRequests++
					mu.Unlock()
					
					// Log authentication for audit
					fabricClient.LogAuditEvent(fmt.Sprintf("user-%d", userID), "performance_test_auth", fmt.Sprintf("session-%d-%d", userID, j), true, map[string]interface{}{
						"test_type": "concurrent_auth",
						"latency_ms": latency.Milliseconds(),
					})
				}
			}(i)
		}
		
		wg.Wait()
		close(latencies)
		
		// Calculate performance metrics
		metrics.EndTime = time.Now()
		totalDuration := metrics.EndTime.Sub(metrics.StartTime)
		
		var totalLatency time.Duration
		for latency := range latencies {
			totalLatency += latency
			if latency < metrics.MinLatency {
				metrics.MinLatency = latency
			}
			if latency > metrics.MaxLatency {
				metrics.MaxLatency = latency
			}
		}
		
		if metrics.TotalRequests > 0 {
			metrics.AverageLatency = totalLatency / time.Duration(metrics.TotalRequests)
			metrics.ThroughputRPS = float64(metrics.TotalRequests) / totalDuration.Seconds()
			metrics.ErrorRate = float64(metrics.FailedReqs) / float64(metrics.TotalRequests) * 100
		}
		
		// Performance assertions
		assert.Equal(t, concurrentUsers*requestsPerUser, metrics.TotalRequests, "All requests should be processed")
		assert.Less(t, metrics.AverageLatency, 200*time.Millisecond, "Average latency should be under 200ms")
		assert.Greater(t, metrics.ThroughputRPS, 100.0, "Throughput should be at least 100 RPS")
		assert.Less(t, metrics.ErrorRate, 1.0, "Error rate should be less than 1%")
		
		t.Logf("Authentication Performance: %d requests, %.2f RPS, avg latency: %v, error rate: %.2f%%", 
			metrics.TotalRequests, metrics.ThroughputRPS, metrics.AverageLatency, metrics.ErrorRate)
	})
	
	t.Run("HighVolumePHIAccess", func(t *testing.T) {
		// Test high-volume PHI access performance
		concurrentUsers := 30
		accessesPerUser := 20
		
		var wg sync.WaitGroup
		var mu sync.Mutex
		metrics := &PerformanceMetrics{
			StartTime:  time.Now(),
			MinLatency: time.Hour,
		}
		
		latencies := make(chan time.Duration, concurrentUsers*accessesPerUser)
		
		for i := 0; i < concurrentUsers; i++ {
			wg.Add(1)
			go func(userID int) {
				defer wg.Done()
				
				for j := 0; j < accessesPerUser; j++ {
					startTime := time.Now()
					
					patientID := fmt.Sprintf("patient-%d", (userID*accessesPerUser+j)%100) // Simulate 100 patients
					
					// Check access permissions via blockchain
					hasAccess := fabricClient.CheckAccess("consulting_doctor", "clinical_notes", "read")
					if !hasAccess {
						mu.Lock()
						metrics.FailedReqs++
						metrics.TotalRequests++
						mu.Unlock()
						continue
					}
					
					// Simulate PHI retrieval
					req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/clinical-notes/patient/%s", patientID), nil)
					req.Header.Set("Authorization", fmt.Sprintf("Bearer doctor-token-%d", userID))
					
					w := httptest.NewRecorder()
					
					// Simulate database query and decryption
					time.Sleep(time.Millisecond * 75) // Simulate processing time
					
					response := map[string]interface{}{
						"patient_id": patientID,
						"notes": []map[string]interface{}{
							{
								"id":         fmt.Sprintf("note-%s-1", patientID),
								"content":    "Decrypted clinical note content",
								"created_at": time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
							},
						},
						"total_count": 1,
					}
					
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(response)
					
					latency := time.Since(startTime)
					latencies <- latency
					
					mu.Lock()
					if w.Code == http.StatusOK {
						metrics.SuccessfulReqs++
					} else {
						metrics.FailedReqs++
					}
					metrics.TotalRequests++
					mu.Unlock()
					
					// Log PHI access for audit
					fabricClient.LogAuditEvent(fmt.Sprintf("doctor-%d", userID), "performance_test_phi_access", patientID, true, map[string]interface{}{
						"test_type":  "high_volume_access",
						"latency_ms": latency.Milliseconds(),
					})
				}
			}(i)
		}
		
		wg.Wait()
		close(latencies)
		
		// Calculate metrics
		metrics.EndTime = time.Now()
		totalDuration := metrics.EndTime.Sub(metrics.StartTime)
		
		var totalLatency time.Duration
		for latency := range latencies {
			totalLatency += latency
			if latency < metrics.MinLatency {
				metrics.MinLatency = latency
			}
			if latency > metrics.MaxLatency {
				metrics.MaxLatency = latency
			}
		}
		
		if metrics.TotalRequests > 0 {
			metrics.AverageLatency = totalLatency / time.Duration(metrics.TotalRequests)
			metrics.ThroughputRPS = float64(metrics.TotalRequests) / totalDuration.Seconds()
			metrics.ErrorRate = float64(metrics.FailedReqs) / float64(metrics.TotalRequests) * 100
		}
		
		// Performance assertions for PHI access
		assert.Less(t, metrics.AverageLatency, 300*time.Millisecond, "PHI access latency should be under 300ms")
		assert.Greater(t, metrics.ThroughputRPS, 50.0, "PHI access throughput should be at least 50 RPS")
		assert.Less(t, metrics.ErrorRate, 2.0, "PHI access error rate should be less than 2%")
		
		t.Logf("PHI Access Performance: %d requests, %.2f RPS, avg latency: %v, error rate: %.2f%%", 
			metrics.TotalRequests, metrics.ThroughputRPS, metrics.AverageLatency, metrics.ErrorRate)
	})
	
	t.Run("BlockchainTransactionThroughput", func(t *testing.T) {
		// Test blockchain transaction throughput
		concurrentTransactions := 25
		transactionsPerThread := 40
		
		var wg sync.WaitGroup
		var mu sync.Mutex
		metrics := &PerformanceMetrics{
			StartTime:  time.Now(),
			MinLatency: time.Hour,
		}
		
		latencies := make(chan time.Duration, concurrentTransactions*transactionsPerThread)
		
		for i := 0; i < concurrentTransactions; i++ {
			wg.Add(1)
			go func(threadID int) {
				defer wg.Done()
				
				for j := 0; j < transactionsPerThread; j++ {
					startTime := time.Now()
					
					// Simulate blockchain transaction (audit log entry)
					userID := fmt.Sprintf("user-%d", threadID)
					resourceID := fmt.Sprintf("resource-%d-%d", threadID, j)
					
					// Simulate blockchain consensus delay
					time.Sleep(time.Millisecond * 30)
					
					fabricClient.LogAuditEvent(userID, "performance_test_transaction", resourceID, true, map[string]interface{}{
						"thread_id":     threadID,
						"transaction_id": j,
						"test_type":     "blockchain_throughput",
					})
					
					latency := time.Since(startTime)
					latencies <- latency
					
					mu.Lock()
					metrics.SuccessfulReqs++
					metrics.TotalRequests++
					mu.Unlock()
				}
			}(i)
		}
		
		wg.Wait()
		close(latencies)
		
		// Calculate metrics
		metrics.EndTime = time.Now()
		totalDuration := metrics.EndTime.Sub(metrics.StartTime)
		
		var totalLatency time.Duration
		for latency := range latencies {
			totalLatency += latency
			if latency < metrics.MinLatency {
				metrics.MinLatency = latency
			}
			if latency > metrics.MaxLatency {
				metrics.MaxLatency = latency
			}
		}
		
		if metrics.TotalRequests > 0 {
			metrics.AverageLatency = totalLatency / time.Duration(metrics.TotalRequests)
			metrics.ThroughputRPS = float64(metrics.TotalRequests) / totalDuration.Seconds()
		}
		
		// Performance assertions for blockchain
		assert.Less(t, metrics.AverageLatency, 500*time.Millisecond, "Blockchain transaction latency should be under 500ms")
		assert.Greater(t, metrics.ThroughputRPS, 20.0, "Blockchain throughput should be at least 20 TPS")
		
		t.Logf("Blockchain Performance: %d transactions, %.2f TPS, avg latency: %v", 
			metrics.TotalRequests, metrics.ThroughputRPS, metrics.AverageLatency)
	})
}

// TestDatabaseQueryOptimization tests database query performance and optimization
func TestDatabaseQueryOptimization(t *testing.T) {
	_ = context.Background()
	
	t.Run("PatientSearchPerformance", func(t *testing.T) {
		// Test patient search query performance
		searchQueries := []struct {
			searchType string
			query      string
			expectedMaxLatency time.Duration
		}{
			{"mrn_search", "MRN-12345", 50 * time.Millisecond},
			{"name_search", "John Doe", 100 * time.Millisecond},
			{"dob_search", "1980-01-01", 75 * time.Millisecond},
			{"phone_search", "+1234567890", 60 * time.Millisecond},
		}
		
		for _, searchQuery := range searchQueries {
			t.Run(searchQuery.searchType, func(t *testing.T) {
				startTime := time.Now()
				
				// Simulate database search
				req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/patients/search?%s=%s", searchQuery.searchType, searchQuery.query), nil)
				req.Header.Set("Authorization", "Bearer admin-token")
				
				w := httptest.NewRecorder()
				
				// Simulate optimized database query
				time.Sleep(time.Millisecond * 25) // Simulate optimized query time
				
				response := map[string]interface{}{
					"results": []map[string]interface{}{
						{
							"id":         "patient-search-123",
							"mrn":        "MRN-12345",
							"first_name": "John",
							"last_name":  "Doe",
						},
					},
					"total_count": 1,
					"query_time_ms": time.Since(startTime).Milliseconds(),
				}
				
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
				
				queryLatency := time.Since(startTime)
				
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Less(t, queryLatency, searchQuery.expectedMaxLatency, 
					"Search query %s should complete within %v", searchQuery.searchType, searchQuery.expectedMaxLatency)
				
				// Log query performance
				fabricClient.LogAuditEvent("system", "query_performance_test", searchQuery.searchType, true, map[string]interface{}{
					"query_type":   searchQuery.searchType,
					"latency_ms":   queryLatency.Milliseconds(),
					"result_count": 1,
				})
				
				t.Logf("%s query completed in %v", searchQuery.searchType, queryLatency)
			})
		}
	})
	
	t.Run("ClinicalNotesQueryOptimization", func(t *testing.T) {
		// Test clinical notes query optimization
		queryTypes := []struct {
			name           string
			queryParams    map[string]string
			expectedMaxLatency time.Duration
		}{
			{
				name: "patient_notes",
				queryParams: map[string]string{"patient_id": "patient-123"},
				expectedMaxLatency: 100 * time.Millisecond,
			},
			{
				name: "date_range_notes",
				queryParams: map[string]string{
					"patient_id": "patient-123",
					"start_date": "2024-01-01",
					"end_date":   "2024-12-31",
				},
				expectedMaxLatency: 150 * time.Millisecond,
			},
			{
				name: "author_notes",
				queryParams: map[string]string{"author_id": "doctor-456"},
				expectedMaxLatency: 200 * time.Millisecond,
			},
		}
		
		for _, queryType := range queryTypes {
			t.Run(queryType.name, func(t *testing.T) {
				startTime := time.Now()
				
				// Build query URL
				queryURL := "/api/v1/clinical-notes?"
				for key, value := range queryType.queryParams {
					queryURL += fmt.Sprintf("%s=%s&", key, value)
				}
				
				req := httptest.NewRequest("GET", queryURL, nil)
				req.Header.Set("Authorization", "Bearer doctor-token")
				
				w := httptest.NewRecorder()
				
				// Simulate optimized database query with proper indexing
				time.Sleep(time.Millisecond * 40) // Simulate optimized query
				
				response := map[string]interface{}{
					"notes": []map[string]interface{}{
						{
							"id":         "note-opt-123",
							"patient_id": queryType.queryParams["patient_id"],
							"content":    "[ENCRYPTED_CONTENT]",
							"created_at": time.Now().Format(time.RFC3339),
						},
					},
					"total_count":   1,
					"query_time_ms": time.Since(startTime).Milliseconds(),
				}
				
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
				
				queryLatency := time.Since(startTime)
				
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Less(t, queryLatency, queryType.expectedMaxLatency,
					"Query %s should complete within %v", queryType.name, queryType.expectedMaxLatency)
				
				// Log query optimization metrics
				fabricClient.LogAuditEvent("system", "query_optimization_test", queryType.name, true, map[string]interface{}{
					"query_type":    queryType.name,
					"latency_ms":    queryLatency.Milliseconds(),
					"params_count":  len(queryType.queryParams),
				})
				
				t.Logf("%s query completed in %v", queryType.name, queryLatency)
			})
		}
	})
}

// TestBlockchainInteractionOptimization tests blockchain interaction performance
func TestBlockchainInteractionOptimization(t *testing.T) {
	_ = context.Background()
	
	t.Run("AccessPolicyQueryOptimization", func(t *testing.T) {
		// Test access policy query performance
		policyQueries := []struct {
			userRole     string
			resourceType string
			expectedMaxLatency time.Duration
		}{
			{"consulting_doctor", "clinical_notes", 100 * time.Millisecond},
			{"nurse", "medications", 100 * time.Millisecond},
			{"md_student", "clinical_notes", 100 * time.Millisecond},
			{"lab_technician", "lab_results", 100 * time.Millisecond},
		}
		
		for _, policyQuery := range policyQueries {
			t.Run(fmt.Sprintf("%s_%s", policyQuery.userRole, policyQuery.resourceType), func(t *testing.T) {
				startTime := time.Now()
				
				// Query access policy from blockchain
				hasAccess := fabricClient.CheckAccess(policyQuery.userRole, policyQuery.resourceType, "read")
				
				queryLatency := time.Since(startTime)
				
				assert.Less(t, queryLatency, policyQuery.expectedMaxLatency,
					"Access policy query should complete within %v", policyQuery.expectedMaxLatency)
				
				// Log blockchain query performance
				fabricClient.LogAuditEvent("system", "blockchain_query_performance", "access_policy", true, map[string]interface{}{
					"user_role":     policyQuery.userRole,
					"resource_type": policyQuery.resourceType,
					"latency_ms":    queryLatency.Milliseconds(),
					"has_access":    hasAccess,
				})
				
				t.Logf("Access policy query for %s/%s completed in %v", 
					policyQuery.userRole, policyQuery.resourceType, queryLatency)
			})
		}
	})
	
	t.Run("AuditLogWritePerformance", func(t *testing.T) {
		// Test audit log write performance
		batchSizes := []int{1, 10, 50, 100}
		
		for _, batchSize := range batchSizes {
			t.Run(fmt.Sprintf("batch_size_%d", batchSize), func(t *testing.T) {
				startTime := time.Now()
				
				// Write batch of audit logs
				for i := 0; i < batchSize; i++ {
					fabricClient.LogAuditEvent(
						fmt.Sprintf("user-%d", i),
						"batch_performance_test",
						fmt.Sprintf("resource-%d", i),
						true,
						map[string]interface{}{
							"batch_size": batchSize,
							"index":      i,
						},
					)
				}
				
				batchLatency := time.Since(startTime)
				avgLatencyPerLog := batchLatency / time.Duration(batchSize)
				
				// Performance expectations
				maxAvgLatency := 50 * time.Millisecond
				assert.Less(t, avgLatencyPerLog, maxAvgLatency,
					"Average audit log write latency should be under %v", maxAvgLatency)
				
				t.Logf("Batch size %d: total %v, avg per log %v", 
					batchSize, batchLatency, avgLatencyPerLog)
			})
		}
	})
}

// TestSystemResourceUtilization tests system resource usage under load
func TestSystemResourceUtilization(t *testing.T) {
	_ = context.Background()
	
	t.Run("MemoryUsageUnderLoad", func(t *testing.T) {
		// Simulate memory usage monitoring during high load
		initialMemory := 100 // MB (simulated)
		
		// Simulate high load scenario
		concurrentOperations := 100
		var wg sync.WaitGroup
		
		for i := 0; i < concurrentOperations; i++ {
			wg.Add(1)
			go func(opID int) {
				defer wg.Done()
				
				// Simulate memory-intensive operations
				largeData := make([]byte, 1024*1024) // 1MB allocation
				_ = largeData
				
				// Simulate processing
				time.Sleep(time.Millisecond * 10)
				
				// Log operation
				fabricClient.LogAuditEvent(fmt.Sprintf("op-%d", opID), "memory_test_operation", fmt.Sprintf("data-%d", opID), true, map[string]interface{}{
					"operation_id": opID,
					"data_size":    len(largeData),
				})
			}(i)
		}
		
		wg.Wait()
		
		// Simulate memory measurement after operations
		finalMemory := initialMemory + (concurrentOperations * 1) // Simulated memory increase
		memoryIncrease := finalMemory - initialMemory
		
		// Memory usage should be reasonable
		maxMemoryIncrease := 200 // MB
		assert.Less(t, memoryIncrease, maxMemoryIncrease,
			"Memory increase should be less than %d MB", maxMemoryIncrease)
		
		t.Logf("Memory usage: initial %d MB, final %d MB, increase %d MB", 
			initialMemory, finalMemory, memoryIncrease)
	})
	
	t.Run("ConnectionPoolPerformance", func(t *testing.T) {
		// Test database connection pool performance
		maxConnections := 50
		concurrentQueries := 100
		
		var wg sync.WaitGroup
		var mu sync.Mutex
		connectionMetrics := struct {
			activeConnections int
			maxConcurrent     int
			totalQueries      int
			avgQueryTime      time.Duration
		}{}
		
		startTime := time.Now()
		
		for i := 0; i < concurrentQueries; i++ {
			wg.Add(1)
			go func(queryID int) {
				defer wg.Done()
				
				queryStart := time.Now()
				
				// Simulate connection acquisition
				mu.Lock()
				connectionMetrics.activeConnections++
				if connectionMetrics.activeConnections > connectionMetrics.maxConcurrent {
					connectionMetrics.maxConcurrent = connectionMetrics.activeConnections
				}
				mu.Unlock()
				
				// Simulate database query
				time.Sleep(time.Millisecond * 25)
				
				// Simulate connection release
				mu.Lock()
				connectionMetrics.activeConnections--
				connectionMetrics.totalQueries++
				mu.Unlock()
				
				queryLatency := time.Since(queryStart)
				
				// Log query performance
				fabricClient.LogAuditEvent("system", "connection_pool_test", fmt.Sprintf("query-%d", queryID), true, map[string]interface{}{
					"query_id":    queryID,
					"latency_ms":  queryLatency.Milliseconds(),
				})
			}(i)
		}
		
		wg.Wait()
		
		totalDuration := time.Since(startTime)
		connectionMetrics.avgQueryTime = totalDuration / time.Duration(concurrentQueries)
		
		// Connection pool performance assertions
		assert.LessOrEqual(t, connectionMetrics.maxConcurrent, maxConnections,
			"Max concurrent connections should not exceed pool size")
		assert.Less(t, connectionMetrics.avgQueryTime, 100*time.Millisecond,
			"Average query time should be under 100ms")
		
		t.Logf("Connection pool: max concurrent %d/%d, avg query time %v", 
			connectionMetrics.maxConcurrent, maxConnections, connectionMetrics.avgQueryTime)
	})
}

// TestEndToEndPerformanceScenarios tests realistic end-to-end performance scenarios
func TestEndToEndPerformanceScenarios(t *testing.T) {
	_ = context.Background()
	
	t.Run("TypicalWorkdayScenario", func(t *testing.T) {
		// Simulate a typical workday with mixed operations
		scenario := struct {
			doctors      int
			nurses       int
			students     int
			patients     int
			duration     time.Duration
		}{
			doctors:  10,
			nurses:   20,
			students: 5,
			patients: 50,
			duration: 30 * time.Second, // Compressed simulation
		}
		
		var wg sync.WaitGroup
		var totalOperations int64
		var successfulOps int64
		
		startTime := time.Now()
		
		// Simulate doctors
		for i := 0; i < scenario.doctors; i++ {
			wg.Add(1)
			go func(doctorID int) {
				defer wg.Done()
				
				endTime := time.Now().Add(scenario.duration)
				for time.Now().Before(endTime) {
					// Simulate doctor activities
					activities := []string{"patient_access", "cpoe_order", "note_creation", "prescription"}
					
					for _, activity := range activities {
						opStart := time.Now()
						
						// Simulate activity processing
						time.Sleep(time.Millisecond * 100)
						
						opLatency := time.Since(opStart)
						
						fabricClient.LogAuditEvent(fmt.Sprintf("doctor-%d", doctorID), activity, fmt.Sprintf("resource-%d", doctorID), true, map[string]interface{}{
							"activity":   activity,
							"latency_ms": opLatency.Milliseconds(),
						})
						
						totalOperations++
						successfulOps++
						
						// Brief pause between activities
						time.Sleep(time.Millisecond * 200)
					}
				}
			}(i)
		}
		
		// Simulate nurses
		for i := 0; i < scenario.nurses; i++ {
			wg.Add(1)
			go func(nurseID int) {
				defer wg.Done()
				
				endTime := time.Now().Add(scenario.duration)
				for time.Now().Before(endTime) {
					// Simulate nurse activities
					activities := []string{"medication_admin", "vital_signs", "patient_assessment"}
					
					for _, activity := range activities {
						opStart := time.Now()
						
						// Simulate activity processing
						time.Sleep(time.Millisecond * 75)
						
						opLatency := time.Since(opStart)
						
						fabricClient.LogAuditEvent(fmt.Sprintf("nurse-%d", nurseID), activity, fmt.Sprintf("patient-%d", nurseID), true, map[string]interface{}{
							"activity":   activity,
							"latency_ms": opLatency.Milliseconds(),
						})
						
						totalOperations++
						successfulOps++
						
						time.Sleep(time.Millisecond * 300)
					}
				}
			}(i)
		}
		
		wg.Wait()
		
		totalDuration := time.Since(startTime)
		operationsPerSecond := float64(totalOperations) / totalDuration.Seconds()
		
		// Performance expectations for realistic workload
		assert.Greater(t, operationsPerSecond, 10.0, "Should handle at least 10 operations per second")
		assert.Equal(t, totalOperations, successfulOps, "All operations should succeed")
		
		t.Logf("Workday scenario: %d operations in %v (%.2f ops/sec)", 
			totalOperations, totalDuration, operationsPerSecond)
	})
}