package adapter

import (
	"strings"
	"sync"
	"time"
)

// Default rate-limit constants for network-facing adapter backends (INT-001/002/003).
// Serve applies these when ext-logs or otel-export is enabled with a non-noop
// backend and the operator has not already set Config.RateCapacity. Capacity 0
// remains unlimited (noop / no network).
const (
	// DefaultNetworkAdapterRateCapacity is the default token-bucket capacity
	// (burst) for network-facing adapters when none is configured.
	DefaultNetworkAdapterRateCapacity = 10
	// DefaultNetworkAdapterRateRefillPerS is tokens refilled per second for that default.
	DefaultNetworkAdapterRateRefillPerS = 1.0
)

// DefaultRateLimitForExtLogsBackend returns registry RateCapacity / RateRefillPerS
// defaults for serve wiring. noop (or empty) → (0, 0) unlimited; mock, http, and
// any other non-noop backend → modest defaults so operator-pinned HTTP backends
// are not unbounded by default.
func DefaultRateLimitForExtLogsBackend(backend ExtLogsBackendName) (capacity, refillPerS float64) {
	b := ExtLogsBackendName(strings.ToLower(strings.TrimSpace(string(backend))))
	switch b {
	case ExtLogsBackendNoop, "":
		return 0, 0
	default:
		return DefaultNetworkAdapterRateCapacity, DefaultNetworkAdapterRateRefillPerS
	}
}

// DefaultRateLimitForOtelExportBackend returns registry RateCapacity / RateRefillPerS
// defaults for otel-export serve wiring. Same posture as ext-logs: noop unlimited;
// mock/http get modest defaults (10 / 1/s).
func DefaultRateLimitForOtelExportBackend(backend OtelExportBackendName) (capacity, refillPerS float64) {
	b := OtelExportBackendName(strings.ToLower(strings.TrimSpace(string(backend))))
	switch b {
	case OtelExportBackendNoop, "":
		return 0, 0
	default:
		return DefaultNetworkAdapterRateCapacity, DefaultNetworkAdapterRateRefillPerS
	}
}

// TokenBucket is a simple per-adapter rate limiter (INT-001 optional budget hook).
// Zero-value is unusable; construct with NewTokenBucket.
type TokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	refillRate float64 // tokens per second
	last       time.Time
	now        func() time.Time
}

// NewTokenBucket creates a token bucket with the given capacity and refill rate
// (tokens per second). Capacity and rate must be positive.
func NewTokenBucket(capacity float64, refillPerSec float64) *TokenBucket {
	if capacity <= 0 {
		capacity = 1
	}
	if refillPerSec <= 0 {
		refillPerSec = 1
	}
	return &TokenBucket{
		tokens:     capacity,
		capacity:   capacity,
		refillRate: refillPerSec,
		last:       time.Now(),
		now:        time.Now,
	}
}

// Allow reports whether n tokens may be taken now. n defaults to 1 when ≤0.
func (b *TokenBucket) Allow(n float64) bool {
	if b == nil {
		return true
	}
	if n <= 0 {
		n = 1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if !b.last.IsZero() {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * b.refillRate
			if b.tokens > b.capacity {
				b.tokens = b.capacity
			}
		}
	}
	b.last = now
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// SetNow injects a clock for tests.
func (b *TokenBucket) SetNow(now func() time.Time) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if now != nil {
		b.now = now
	}
}
