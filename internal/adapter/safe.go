package adapter

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"
)

// recoverToHealth runs fn and converts panics into unhealthy Health + error.
// Used so adapter Start/Stop/Health/Call cannot crash the core process.
func recoverToHealth(entry *Entry, op string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("adapter %q panic in %s: %v", entry.ID, op, r)
			// Include a short stack for operators; never include secrets from the adapter.
			_ = debug.Stack()
			entry.markPanic(msg)
			err = fmt.Errorf("%s", msg)
		}
	}()
	return fn()
}

// safeStart starts the adapter with panic recovery.
func safeStart(ctx context.Context, entry *Entry) error {
	entry.setHealth(Health{Status: HealthStarting, Message: "starting", CheckedAt: time.Now().UTC()})
	err := recoverToHealth(entry, "Start", func() error {
		return entry.Adapter.Start(ctx)
	})
	if err != nil {
		// Keep unhealthy if panic already set it; otherwise record start failure.
		if entry.snapshotHealth().Status != HealthUnhealthy {
			entry.setHealth(Health{
				Status:    HealthUnhealthy,
				Message:   err.Error(),
				CheckedAt: time.Now().UTC(),
			})
		}
		return err
	}
	entry.mu.Lock()
	entry.started = true
	entry.mu.Unlock()
	entry.setHealth(Health{Status: HealthHealthy, Message: "started", CheckedAt: time.Now().UTC()})
	return nil
}

// safeStop stops the adapter with panic recovery.
func safeStop(ctx context.Context, entry *Entry) error {
	err := recoverToHealth(entry, "Stop", func() error {
		return entry.Adapter.Stop(ctx)
	})
	entry.mu.Lock()
	entry.stopped = true
	entry.started = false
	entry.mu.Unlock()
	if err != nil {
		if entry.snapshotHealth().Status != HealthUnhealthy {
			entry.setHealth(Health{Status: HealthUnhealthy, Message: err.Error(), CheckedAt: time.Now().UTC()})
		}
		return err
	}
	// Do not overwrite panic unhealthy with stopped.
	h := entry.snapshotHealth()
	if h.Status != HealthUnhealthy {
		entry.setHealth(Health{Status: HealthStopped, Message: "stopped", CheckedAt: time.Now().UTC()})
	}
	return nil
}

// safeHealth queries Health with panic recovery; panics → unhealthy.
func safeHealth(ctx context.Context, entry *Entry) Health {
	var h Health
	err := recoverToHealth(entry, "Health", func() error {
		h = entry.Adapter.Health(ctx)
		return nil
	})
	if err != nil {
		return entry.snapshotHealth()
	}
	// If a prior panic marked unhealthy, prefer that over a lying healthy report.
	entry.mu.Lock()
	panicked := entry.panicked
	entry.mu.Unlock()
	if panicked {
		return entry.snapshotHealth()
	}
	if h.CheckedAt.IsZero() {
		// leave zero; caller may fill
	}
	entry.setHealth(h)
	return h
}

// Call runs fn under rate limit + panic recovery for ad-hoc adapter work.
// Returns CodeThrottled-style error when the bucket denies.
func Call(entry *Entry, fn func() error) error {
	if entry == nil || entry.Adapter == nil {
		return fmt.Errorf("adapter: nil entry")
	}
	if entry.RateLimit != nil && !entry.RateLimit.Allow(1) {
		return fmt.Errorf("adapter %q rate limited", entry.ID)
	}
	return recoverToHealth(entry, "Call", fn)
}
