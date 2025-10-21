package gateway

import (
	"sync"
	"time"
)

// RateLimiter implements rate limiting using token bucket algorithm
type RateLimiter struct {
	buckets    map[string]*tokenBucket
	bucketsMux sync.RWMutex
	limit      int
	period     time.Duration
}

// tokenBucket represents a token bucket for rate limiting
type tokenBucket struct {
	tokens     int
	lastRefill time.Time
	mutex      sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, period time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*tokenBucket),
		limit:   limit,
		period:  period,
	}
}

// Allow checks if a request is allowed for the given user
func (rl *RateLimiter) Allow(userID string) (bool, error) {
	bucket := rl.getBucket(userID)
	
	bucket.mutex.Lock()
	defer bucket.mutex.Unlock()

	// Refill tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	
	if elapsed >= rl.period {
		// Refill bucket completely
		bucket.tokens = rl.limit
		bucket.lastRefill = now
	} else {
		// Partial refill based on elapsed time
		tokensToAdd := int(elapsed.Nanoseconds() * int64(rl.limit) / rl.period.Nanoseconds())
		bucket.tokens = min(bucket.tokens+tokensToAdd, rl.limit)
		if tokensToAdd > 0 {
			bucket.lastRefill = now
		}
	}

	// Check if request is allowed
	if bucket.tokens > 0 {
		bucket.tokens--
		return true, nil
	}

	return false, nil
}

// Reset resets the rate limit for a user
func (rl *RateLimiter) Reset(userID string) error {
	rl.bucketsMux.Lock()
	defer rl.bucketsMux.Unlock()

	if bucket, exists := rl.buckets[userID]; exists {
		bucket.mutex.Lock()
		bucket.tokens = rl.limit
		bucket.lastRefill = time.Now()
		bucket.mutex.Unlock()
	}

	return nil
}

// GetLimits returns current token count and limit for a user
func (rl *RateLimiter) GetLimits(userID string) (int, int, error) {
	bucket := rl.getBucket(userID)
	
	bucket.mutex.Lock()
	defer bucket.mutex.Unlock()

	return bucket.tokens, rl.limit, nil
}

// getBucket gets or creates a token bucket for a user
func (rl *RateLimiter) getBucket(userID string) *tokenBucket {
	rl.bucketsMux.RLock()
	bucket, exists := rl.buckets[userID]
	rl.bucketsMux.RUnlock()

	if exists {
		return bucket
	}

	// Create new bucket
	rl.bucketsMux.Lock()
	defer rl.bucketsMux.Unlock()

	// Double-check after acquiring write lock
	if bucket, exists := rl.buckets[userID]; exists {
		return bucket
	}

	bucket = &tokenBucket{
		tokens:     rl.limit,
		lastRefill: time.Now(),
	}
	rl.buckets[userID] = bucket

	return bucket
}

// cleanup removes old buckets (should be called periodically)
func (rl *RateLimiter) cleanup() {
	rl.bucketsMux.Lock()
	defer rl.bucketsMux.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour) // Remove buckets older than 24 hours

	for userID, bucket := range rl.buckets {
		bucket.mutex.Lock()
		if bucket.lastRefill.Before(cutoff) {
			delete(rl.buckets, userID)
		}
		bucket.mutex.Unlock()
	}
}

// StartCleanup starts periodic cleanup of old buckets
func (rl *RateLimiter) StartCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			rl.cleanup()
		}
	}()
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}