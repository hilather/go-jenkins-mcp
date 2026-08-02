package audit

import (
	"os"
	"sort"
	"strings"
)

// KnownEventTypes returns every stable AUD-001 type string the product emits.
//
// Agent non-negotiable (AGENTS.md): when adding a new audit type, append it here
// in the same change as event.go constants, DefaultTypeFilter, emit sites,
// admin …/audit/settings (auto via this list), SPA AUDIT_TYPE_OPTIONS/HINTS
// fallback, and docs/observability.md. Unknown types are fail-closed at the
// File ReloadingFilterSink (AllowUnknown false).
//
// Order is stable for API/UI display. Admin/MCP-OPS write types are first-class
// catalog members so ReloadingFilterSink persists them by default.
func KnownEventTypes() []string {
	// Keep in sync with Type* constants and mutation Manager emit types.
	out := []string{
		TypeLoginSuccess,
		TypeLoginFail,
		TypeServeStart,
		TypeToolDeny,
		TypeToolError,
		TypeToolSuccess,
		TypeAuthFail,
		TypeAuditSettings,
		TypePolicyValidate,
		TypePolicyApply,
		TypeAdminCacheEvict,
		TypeAdminSupportBundle,
		TypeAdminSubjectInvalid,
		TypeAdminConsentPurge,
		TypeAdminFleetCachePurge,
		// Mutation manager (internal/mutation) uses these type strings.
		"mutation_preview",
		"mutation_confirm",
		"mutation_deny",
	}
	return append([]string(nil), out...)
}

// IsKnownEventType reports whether t is in KnownEventTypes (exact match).
func IsKnownEventType(t string) bool {
	t = strings.TrimSpace(t)
	if t == "" {
		return false
	}
	for _, k := range KnownEventTypes() {
		if k == t {
			return true
		}
	}
	return false
}

// TypeFilter decides which event types are persisted by a FilterSink.
// Unknown types: default deny (fail closed) unless AllowUnknown is true.
type TypeFilter struct {
	// Enabled maps type → whether Emit should persist. Missing key = default.
	Enabled map[string]bool
	// DefaultOn is used when a known type is absent from Enabled.
	// Production defaults: true for most types; tool_success often false.
	DefaultOn bool
	// AllowUnknown when true persists types not in KnownEventTypes (not recommended).
	AllowUnknown bool
}

// DefaultTypeFilter enables all known types except tool_success unless
// JENKINS_MCP_AUDIT_TOOL_OK is truthy (parity with historical opt-in).
func DefaultTypeFilter() TypeFilter {
	f := TypeFilter{
		Enabled:   make(map[string]bool, len(KnownEventTypes())),
		DefaultOn: true,
	}
	for _, t := range KnownEventTypes() {
		f.Enabled[t] = true
	}
	// tool_success remains opt-in unless env enables it.
	f.Enabled[TypeToolSuccess] = envTruthy(os.Getenv("JENKINS_MCP_AUDIT_TOOL_OK"))
	return f
}

// Allows reports whether type t should be emitted to the underlying sink.
func (f TypeFilter) Allows(t string) bool {
	t = strings.TrimSpace(t)
	if t == "" {
		return false
	}
	if f.Enabled != nil {
		if on, ok := f.Enabled[t]; ok {
			return on
		}
	}
	if IsKnownEventType(t) {
		return f.DefaultOn
	}
	return f.AllowUnknown
}

// EnabledMap returns a full map for every known type (for admin API/UI).
func (f TypeFilter) EnabledMap() map[string]bool {
	out := make(map[string]bool, len(KnownEventTypes()))
	for _, t := range KnownEventTypes() {
		out[t] = f.Allows(t)
	}
	return out
}

// NormalizeEnabled merges client-supplied enabled flags with defaults.
// Only known types are accepted; unknown keys are ignored (fail closed).
// Returns a filter with DefaultOn=true and explicit Enabled for all known types.
func NormalizeEnabled(enabled map[string]bool) TypeFilter {
	base := DefaultTypeFilter()
	if enabled == nil {
		return base
	}
	for _, t := range KnownEventTypes() {
		if v, ok := enabled[t]; ok {
			base.Enabled[t] = v
		}
	}
	return base
}

// SortedEnabledKeys returns known types sorted for stable JSON.
func SortedEnabledKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
