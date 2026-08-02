package adapter

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Config configures a Registry.
//
// Deny by default:
//   - EnabledIDs empty → no adapters registered/started.
//   - Unknown IDs fail registration (CodeInvalidArgument).
//   - Non-builtin IDs require Allowlist membership.
//   - Builtin IDs (noop, clock, otel-correlate, otel-export, ext-logs, work-items)
//     may be enabled without an allowlist file when AllowBuiltins is true (default).
//   - External/future adapters always require Allowlist (AllowBuiltins does not
//     apply to unknown/non-builtin IDs).
type Config struct {
	// EnabledIDs are adapter IDs requested via --enable-adapter (explicit enable).
	EnabledIDs []string
	// Allowlist is the approved set (from file or policy). Empty denies non-builtins.
	Allowlist Allowlist
	// AllowBuiltins permits enabling in-tree builtins without Allowlist membership.
	// Default true when zero-value is used via NewRegistry (see NewRegistry).
	// Set false to require allowlist even for builtins (strict mode).
	AllowBuiltins *bool
	// Catalog maps ID → factory. Nil uses DefaultCatalog().
	Catalog map[string]Factory
	// Host is passed to factories (no Jenkins client).
	Host Host
	// RateLimitPerAdapter optional default bucket config; zero ⇒ no limit.
	// When RateCapacity > 0, each registered adapter gets a token bucket.
	RateCapacity   float64
	RateRefillPerS float64
}

func (c Config) allowBuiltins() bool {
	if c.AllowBuiltins == nil {
		return true
	}
	return *c.AllowBuiltins
}

// Registry holds explicitly enabled, approved adapters for one process.
type Registry struct {
	cfg     Config
	catalog map[string]Factory

	mu      sync.Mutex
	entries map[string]*Entry
	// started is true after StartAll succeeds (or partially; see StartAll).
	started bool
}

// NewRegistry builds a registry. It does not start adapters; call RegisterEnabled then StartAll.
// With empty EnabledIDs the registry remains empty (default production posture).
func NewRegistry(cfg Config) *Registry {
	cat := cfg.Catalog
	if cat == nil {
		cat = DefaultCatalog()
	}
	return &Registry{
		cfg:     cfg,
		catalog: cat,
		entries: make(map[string]*Entry),
	}
}

// RegisterEnabled constructs and registers every EnabledID that is approved.
// Unknown IDs fail. Disabled-by-default: empty EnabledIDs is a no-op success.
// Does not Start adapters. All-or-nothing: on any error, no new entries are kept.
func (r *Registry) RegisterEnabled() error {
	if r == nil {
		return apperr.New(apperr.CodeInternal, "adapter registry is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	pending := make(map[string]*Entry)
	seen := map[string]struct{}{}
	for _, raw := range r.cfg.EnabledIDs {
		id := normalizeID(raw)
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}

		if err := r.approveLocked(id); err != nil {
			return err
		}
		factory, ok := r.catalog[id]
		if !ok {
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("unknown adapter id %q (not in catalog)", id))
		}
		a, err := factory(r.cfg.Host)
		if err != nil {
			return apperr.Wrap(apperr.CodeInternal, fmt.Sprintf("adapter %q factory", id), err)
		}
		if a == nil {
			return apperr.New(apperr.CodeInternal, fmt.Sprintf("adapter %q factory returned nil", id))
		}
		// Enforce ID consistency.
		if normalizeID(a.ID()) != id {
			return apperr.New(apperr.CodeInternal,
				fmt.Sprintf("adapter factory id mismatch: want %q got %q", id, a.ID()))
		}
		entry := &Entry{
			ID:           id,
			Capabilities: append([]Capability(nil), a.Capabilities()...),
			Adapter:      a,
			health:       Health{Status: HealthUnknown, Message: "registered"},
		}
		if r.cfg.RateCapacity > 0 {
			entry.RateLimit = NewTokenBucket(r.cfg.RateCapacity, r.cfg.RateRefillPerS)
		}
		pending[id] = entry
	}
	for id, entry := range pending {
		r.entries[id] = entry
	}
	return nil
}

func (r *Registry) approveLocked(id string) error {
	if r.cfg.Allowlist.Contains(id) {
		return nil
	}
	if IsBuiltin(id) && r.cfg.allowBuiltins() {
		return nil
	}
	if IsBuiltin(id) {
		return apperr.New(apperr.CodePolicyDenial,
			fmt.Sprintf("adapter %q is not on the allowlist (builtins require allowlist in strict mode)", id))
	}
	// Non-builtin always needs allowlist; if unknown factory, still fail as not approved.
	return apperr.New(apperr.CodePolicyDenial,
		fmt.Sprintf("adapter %q is not approved (allowlist deny by default)", id))
}

// RegisterInstance registers a pre-built adapter (tests). Still enforces
// allowlist/builtin policy and rejects unknown IDs when requireCatalog is true.
func (r *Registry) RegisterInstance(a Adapter, requireCatalog bool) error {
	if r == nil || a == nil {
		return apperr.New(apperr.CodeInvalidArgument, "adapter instance required")
	}
	id := normalizeID(a.ID())
	if id == "" {
		return apperr.New(apperr.CodeInvalidArgument, "adapter id is empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.approveLocked(id); err != nil {
		return err
	}
	if requireCatalog {
		if _, ok := r.catalog[id]; !ok {
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("unknown adapter id %q (not in catalog)", id))
		}
	}
	r.entries[id] = &Entry{
		ID:           id,
		Capabilities: append([]Capability(nil), a.Capabilities()...),
		Adapter:      a,
		health:       Health{Status: HealthUnknown, Message: "registered"},
	}
	return nil
}

// StartAll starts every registered adapter with panic isolation.
// A single adapter failure marks it unhealthy but does not prevent other adapters
// from starting; the returned error joins failures. Core process continues.
func (r *Registry) StartAll(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	r.mu.Unlock()

	var errs []string
	for _, id := range ids {
		r.mu.Lock()
		entry := r.entries[id]
		r.mu.Unlock()
		if entry == nil {
			continue
		}
		if err := safeStart(ctx, entry); err != nil {
			errs = append(errs, err.Error())
			r.cfg.Host.logf("adapter %s start failed: %v", id, err)
		}
	}
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	if len(errs) > 0 {
		return apperr.New(apperr.CodeInternal, "adapter start failures: "+strings.Join(errs, "; "))
	}
	return nil
}

// StopAll stops every registered adapter with panic isolation.
func (r *Registry) StopAll(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	r.mu.Unlock()

	var errs []string
	for _, id := range ids {
		r.mu.Lock()
		entry := r.entries[id]
		r.mu.Unlock()
		if entry == nil {
			continue
		}
		if err := safeStop(ctx, entry); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return apperr.New(apperr.CodeInternal, "adapter stop failures: "+strings.Join(errs, "; "))
	}
	return nil
}

// Get returns a registered entry or nil.
func (r *Registry) Get(id string) *Entry {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entries[normalizeID(id)]
}

// Health returns health for one adapter (panic-safe).
func (r *Registry) Health(ctx context.Context, id string) Health {
	e := r.Get(id)
	if e == nil {
		return Health{Status: HealthDisabled, Message: "not registered"}
	}
	return safeHealth(ctx, e)
}

// HealthAll returns health for all registered adapters.
func (r *Registry) HealthAll(ctx context.Context) map[string]Health {
	out := make(map[string]Health)
	if r == nil {
		return out
	}
	r.mu.Lock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	for _, id := range ids {
		out[id] = r.Health(ctx, id)
	}
	return out
}

// IDs returns sorted registered adapter IDs.
func (r *Registry) IDs() []string {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Len returns the number of registered adapters.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// EnabledRequested reports whether any --enable-adapter IDs were configured.
func (r *Registry) EnabledRequested() bool {
	if r == nil {
		return false
	}
	for _, id := range r.cfg.EnabledIDs {
		if normalizeID(id) != "" {
			return true
		}
	}
	return false
}
