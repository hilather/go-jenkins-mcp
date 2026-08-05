package cachecontrol

import (
	"sync"
	"sync/atomic"
)

// Telemetry dimensions are low-cardinality only (type id, layer, outcome).
// Never attach job names, paths, URLs, subjects, or free-form error text.

// Outcome codes for cache data-path events.
const (
	OutcomeHit           = "hit"
	OutcomeMiss          = "miss"
	OutcomeBypass        = "bypass"
	OutcomeFillOK        = "fill_ok"
	OutcomeFillDiscarded = "fill_discarded"
	OutcomeFillError     = "fill_error"
	OutcomeAuthDeny      = "auth_deny"
	OutcomeStale         = "stale"
)

// Layer codes.
const (
	LayerL0   = "l0"
	LayerDisk = "disk"
	LayerNone = "none"
)

// TelemetryEvent is a single low-cardinality event.
type TelemetryEvent struct {
	TypeID  TypeID
	Layer   string
	Outcome string
	// Reason is a stable machine code only (empty ok).
	Reason string
	Bytes  int64
}

// TelemetryRecorder aggregates counters in-process (rollups durable layer residual).
type TelemetryRecorder struct {
	mu sync.Mutex
	// key: type|layer|outcome|reason → count
	counts map[string]*atomic.Int64
	bytes  map[string]*atomic.Int64
}

// NewTelemetryRecorder creates an empty recorder.
func NewTelemetryRecorder() *TelemetryRecorder {
	return &TelemetryRecorder{
		counts: make(map[string]*atomic.Int64),
		bytes:  make(map[string]*atomic.Int64),
	}
}

func telKey(e TelemetryEvent) string {
	return string(e.TypeID) + "|" + e.Layer + "|" + e.Outcome + "|" + e.Reason
}

// Record increments counters for e. Ignores empty TypeID.
func (r *TelemetryRecorder) Record(e TelemetryEvent) {
	if r == nil || e.TypeID == "" {
		return
	}
	// Reject high-cardinality misuse: reason must be short stable code.
	if len(e.Reason) > 64 {
		e.Reason = "reason_truncated"
	}
	k := telKey(e)
	r.mu.Lock()
	c, ok := r.counts[k]
	if !ok {
		c = &atomic.Int64{}
		r.counts[k] = c
		r.bytes[k] = &atomic.Int64{}
	}
	b := r.bytes[k]
	r.mu.Unlock()
	c.Add(1)
	if e.Bytes > 0 {
		b.Add(e.Bytes)
	}
}

// Snapshot returns a secret-free rollup map suitable for admin metrics.
func (r *TelemetryRecorder) Snapshot() []TelemetryRollup {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TelemetryRollup, 0, len(r.counts))
	for k, c := range r.counts {
		// parse key
		parts := split4(k)
		out = append(out, TelemetryRollup{
			TypeID:  TypeID(parts[0]),
			Layer:   parts[1],
			Outcome: parts[2],
			Reason:  parts[3],
			Count:   c.Load(),
			Bytes:   r.bytes[k].Load(),
		})
	}
	return out
}

// TelemetryRollup is one aggregated counter row.
type TelemetryRollup struct {
	TypeID  TypeID `json:"typeId"`
	Layer   string `json:"layer"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
	Count   int64  `json:"count"`
	Bytes   int64  `json:"bytes,omitempty"`
}

func split4(k string) [4]string {
	var out [4]string
	start := 0
	idx := 0
	for i := 0; i < len(k) && idx < 3; i++ {
		if k[i] == '|' {
			out[idx] = k[start:i]
			idx++
			start = i + 1
		}
	}
	out[idx] = k[start:]
	return out
}
