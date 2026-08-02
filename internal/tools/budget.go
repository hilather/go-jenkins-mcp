package tools

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// MCP-001 / ADR 0010: central structured result budgets.
const (
	// DefaultTargetBytes is the soft structured-result target (64 KiB).
	DefaultTargetBytes = 64 * 1024
	// DefaultHardMaxBytes is the hard stop for any tool result (1 MiB).
	DefaultHardMaxBytes = 1024 * 1024
	// AbsoluteMaxHardMaxBytes is the process absolute fail-closed ceiling for the
	// serve bootstrap hard max (Wave 38). Operators may raise --hard-max-bytes /
	// JENKINS_MCP_HARD_MAX_BYTES above DefaultHardMaxBytes, but never above this
	// bound — multi-GB values are rejected (not a soft target). Overlay
	// max_result_bytes may only lower within the resolved bootstrap ceiling.
	AbsoluteMaxHardMaxBytes = 64 << 20 // 64 MiB
	// AbsoluteMaxTargetBytes is the process absolute fail-closed ceiling for the
	// soft TargetBytes knob (Wave 47 Track B / Wave 51 Track C / ADR 0010).
	// Equals AbsoluteMaxHardMaxBytes (64 MiB): operators may raise --target-bytes /
	// JENKINS_MCP_TARGET_BYTES above DefaultTargetBytes up to this bound (aligned
	// with the hard-max absolute so raising --hard-max-bytes can be paired with a
	// matching soft target). Values above AbsoluteMaxTargetBytes fail closed at
	// resolve. At enforce time TargetBytes is still clamped to the live hard max
	// (Normalize / effectiveBudget); resolve may yield target > bootstrap hard max
	// when the operator only raised --target-bytes — serve clamps after Normalize.
	AbsoluteMaxTargetBytes = AbsoluteMaxHardMaxBytes
	// DefaultMaxListItems is a coarse safety cap for ClampListLen helpers.
	// List tools (get_jobs, list_jobs, list_builds) use opaque page_token
	// pagination with per-tool hard maxes; this is a last-resort array clamp.
	DefaultMaxListItems = 500

	// EnvHardMaxBytes is the serve env for the bootstrap result hard-max ceiling
	// (Wave 37). CLI --hard-max-bytes overrides when set. Empty/0 → DefaultHardMaxBytes.
	// Invalid values and values above AbsoluteMaxHardMaxBytes fail closed at serve
	// start. Overlay max_result_bytes may only lower within this ceiling; raising
	// the serve-bootstrap ceiling (within AbsoluteMaxHardMaxBytes) requires re-serve.
	EnvHardMaxBytes = "JENKINS_MCP_HARD_MAX_BYTES"
	// EnvTargetBytes is the serve env for the soft structured-result target
	// (Wave 47 Track B). CLI --target-bytes overrides when set. Empty/0 →
	// DefaultTargetBytes. Invalid values and values above AbsoluteMaxTargetBytes
	// fail closed at serve start. Soft target never silently exceeds hard max at
	// enforce time (Normalize / effectiveBudget clamp).
	EnvTargetBytes = "JENKINS_MCP_TARGET_BYTES"
)

// Budgets holds result-size limits applied by addTool / EnforceBudget.
// Value type stays immutable for call sites; live hard-max mid-serve uses LiveHardMax.
type Budgets struct {
	// TargetBytes is the soft target; exceeding it is recorded in metadata when
	// the payload is otherwise accepted under HardMaxBytes.
	TargetBytes int
	// HardMaxBytes is the absolute maximum serialized JSON size for a tool result.
	HardMaxBytes int
	// MaxListItems caps array lengths for ClampListLen (0 = DefaultMaxListItems).
	// Opaque page tokens on list tools are separate (per-tool max page size).
	MaxListItems int
}

// LiveHardMax is a thread-safe hard max shared by registered tool handlers.
//
// Wave 25: policy reload may LowerTo(max_result_bytes) (only lower).
// Wave 31: a serve-bootstrap ceiling is fixed at NewLiveHardMax; SetWithinCeiling
// may raise or lower the live value mid-serve but never above that ceiling
// (never invent higher than process serve-start hard max).
// Wave 37: the bootstrap ceiling is ResolveHardMaxBytes (default → env → flag);
// overlay LowerHardMax may only lower the live value. Raising the serve-bootstrap
// ceiling still requires process restart with a higher --hard-max-bytes /
// JENKINS_MCP_HARD_MAX_BYTES (overlay alone never raises the ceiling).
// Wave 38: ResolveHardMaxBytes also enforces AbsoluteMaxHardMaxBytes (64 MiB).
type LiveHardMax struct {
	v       atomic.Int64
	ceiling int64 // immutable after NewLiveHardMax; process serve-start hard max
}

// NewLiveHardMax returns a holder initialized to n with ceiling = n after
// normalize (non-positive → DefaultHardMaxBytes). Ceiling never changes.
// Pass the Wave 37 bootstrap ceiling (before overlay lower); then LowerTo /
// SetWithinCeiling for the effective live value.
func NewLiveHardMax(n int) *LiveHardMax {
	if n <= 0 {
		n = DefaultHardMaxBytes
	}
	h := &LiveHardMax{ceiling: int64(n)}
	h.v.Store(int64(n))
	return h
}

// ResolveHardMaxBytes resolves the serve bootstrap result hard-max ceiling.
//
// Precedence (later wins): DefaultHardMaxBytes → envVal → flagVal.
// Empty / whitespace means unset at that layer. Positive integers are accepted.
// Zero (explicit "0") at the winning layer means DefaultHardMaxBytes.
// Negative or non-integer values fail closed (error); never clamp silently.
// After resolve, n must be ≤ AbsoluteMaxHardMaxBytes (Wave 38 process absolute
// fail-closed ceiling); oversize values error with a hard-max / maximum /
// bound message (no secrets).
//
// Overlay max_result_bytes is applied separately via LowerHardMax / LiveHardMax
// and must never raise above this bootstrap ceiling.
func ResolveHardMaxBytes(flagVal, envVal string) (int, error) {
	n := DefaultHardMaxBytes
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseHardMaxBytesValue(raw, "env "+EnvHardMaxBytes)
		if err != nil {
			return 0, err
		}
		n = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseHardMaxBytesValue(raw, "flag --hard-max-bytes")
		if err != nil {
			return 0, err
		}
		n = v
	}
	if n > AbsoluteMaxHardMaxBytes {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"hard max bytes exceeds absolute maximum bound ("+
				strconv.Itoa(AbsoluteMaxHardMaxBytes)+" bytes)")
	}
	return n, nil
}

func parseHardMaxBytesValue(raw, source string) (int, error) {
	v, err := strconv.ParseInt(raw, 10, 0)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid hard max bytes from "+source+" (positive integer bytes, or 0 for default): "+raw)
	}
	if v < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"hard max bytes from "+source+" must not be negative")
	}
	if v == 0 {
		return DefaultHardMaxBytes, nil
	}
	return int(v), nil
}

// ResolveTargetBytes resolves the serve soft structured-result target (Wave 47).
//
// Precedence (later wins): DefaultTargetBytes → envVal → flagVal.
// Empty / whitespace means unset at that layer. Positive integers are accepted.
// Zero (explicit "0") at the winning layer means DefaultTargetBytes.
// Negative or non-integer values fail closed (error); never clamp silently.
// After resolve, n must be ≤ AbsoluteMaxTargetBytes (= AbsoluteMaxHardMaxBytes /
// 64 MiB process absolute fail-closed ceiling for the soft knob); oversize
// values error with a target / maximum / bound message (no secrets).
//
// Soft target is clamped to the live hard max at enforce time (Normalize /
// effectiveBudget); this resolver does not accept a hard-max argument. When
// resolve yields target > bootstrap hard max, serve clamps after Normalize.
func ResolveTargetBytes(flagVal, envVal string) (int, error) {
	n := DefaultTargetBytes
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseTargetBytesValue(raw, "env "+EnvTargetBytes)
		if err != nil {
			return 0, err
		}
		n = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseTargetBytesValue(raw, "flag --target-bytes")
		if err != nil {
			return 0, err
		}
		n = v
	}
	if n > AbsoluteMaxTargetBytes {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"target bytes exceeds absolute maximum bound ("+
				strconv.Itoa(AbsoluteMaxTargetBytes)+" bytes)")
	}
	return n, nil
}

func parseTargetBytesValue(raw, source string) (int, error) {
	v, err := strconv.ParseInt(raw, 10, 0)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid target bytes from "+source+" (positive integer bytes, or 0 for default): "+raw)
	}
	if v < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"target bytes from "+source+" must not be negative")
	}
	if v == 0 {
		return DefaultTargetBytes, nil
	}
	return int(v), nil
}

// Get returns the current hard max in bytes.
func (h *LiveHardMax) Get() int {
	if h == nil {
		return 0
	}
	n := h.v.Load()
	if n <= 0 {
		return 0
	}
	return int(n)
}

// Ceiling returns the serve-bootstrap hard-max ceiling (immutable). Nil ⇒ 0.
func (h *LiveHardMax) Ceiling() int {
	if h == nil {
		return 0
	}
	if h.ceiling <= 0 {
		return 0
	}
	return int(h.ceiling)
}

// LowerTo reduces the hard max to n when n is positive and smaller than the
// current value. Returns true when the stored value changed. Never raises.
// Prefer SetWithinCeiling on policy reload when the overlay may raise or lower.
func (h *LiveHardMax) LowerTo(n int) bool {
	if h == nil || n <= 0 {
		return false
	}
	want := int64(n)
	for {
		cur := h.v.Load()
		if want >= cur {
			return false
		}
		if h.v.CompareAndSwap(cur, want) {
			return true
		}
	}
}

// SetWithinCeiling sets the live hard max to min(n, ceiling) when n is positive.
// Can raise or lower relative to the current value, but never exceeds the
// serve-bootstrap ceiling. Returns true when the stored value changed.
// n <= 0 is a no-op (false) so an omitted overlay max_result_bytes keeps the
// last live value rather than auto-restoring to ceiling.
func (h *LiveHardMax) SetWithinCeiling(n int) bool {
	if h == nil || n <= 0 {
		return false
	}
	want := int64(n)
	if want > h.ceiling {
		want = h.ceiling
	}
	// Defense: non-positive ceiling must not clear the live value.
	if want <= 0 {
		return false
	}
	for {
		cur := h.v.Load()
		if want == cur {
			return false
		}
		if h.v.CompareAndSwap(cur, want) {
			return true
		}
	}
}

// DefaultBudgets returns architecture defaults (64 KiB target / 1 MiB hard).
func DefaultBudgets() Budgets {
	return Budgets{
		TargetBytes:  DefaultTargetBytes,
		HardMaxBytes: DefaultHardMaxBytes,
		MaxListItems: DefaultMaxListItems,
	}
}

// SoftTargetClampApplied reports whether a resolved soft target exceeded the
// hard max before a Normalize-style clamp (Wave 53 Track C / MCP-001 residual
// honesty). True iff hardMax > 0 && resolvedTarget > hardMax. Used by serve to
// log non-secret target_bytes_clamped when resolve yields target above the
// bootstrap/live hard max; AbsoluteMaxTargetBytes / resolve fail-closed
// ceilings are unchanged.
func SoftTargetClampApplied(resolvedTarget, hardMax int) bool {
	return hardMax > 0 && resolvedTarget > hardMax
}

// Normalize fills zero fields with defaults and rejects non-positive hard max
// by substituting the default hard max (fail closed toward a finite bound).
func (b Budgets) Normalize() Budgets {
	if b.TargetBytes <= 0 {
		b.TargetBytes = DefaultTargetBytes
	}
	if b.HardMaxBytes <= 0 {
		b.HardMaxBytes = DefaultHardMaxBytes
	}
	if b.MaxListItems <= 0 {
		b.MaxListItems = DefaultMaxListItems
	}
	// Never allow target above hard max.
	if b.TargetBytes > b.HardMaxBytes {
		b.TargetBytes = b.HardMaxBytes
	}
	return b
}

// TruncationInfo is explicit truncation metadata (never silent drop).
type TruncationInfo struct {
	Truncated      bool   `json:"truncated"`
	OriginalBytes  int    `json:"original_bytes"`
	ReturnedBytes  int    `json:"returned_bytes"`
	HardMaxBytes   int    `json:"hard_max_bytes"`
	TargetBytes    int    `json:"target_bytes"`
	OverTarget     bool   `json:"over_target,omitempty"`
	Message        string `json:"message,omitempty"`
	ContentOmitted bool   `json:"content_omitted,omitempty"`
}

// TruncatedResult is returned when serialized output exceeds the hard max.
// It is intentionally small and secret-free.
type TruncatedResult struct {
	Truncation TruncationInfo `json:"truncation"`
}

// EnforceBudget marshals v and enforces the hard max (MCP-001).
//
// Behavior:
//   - nil / empty-safe: nil and trivially small values pass.
//   - under hard max: original value returned (even if over soft target).
//   - over hard max: a TruncatedResult summary is returned (content omitted)
//     so callers never emit multi-MiB MCP payloads. The summary always fits
//     under HardMaxBytes.
//
// The second return is non-nil truncation metadata when truncated or over target.
func EnforceBudget(v any, b Budgets) (any, *TruncationInfo, error) {
	b = b.Normalize()
	if isEmptyResult(v) {
		return v, nil, nil
	}

	data, err := json.Marshal(v)
	if err != nil {
		return nil, nil, apperr.Wrap(apperr.CodeInternal, "failed to marshal tool result", err)
	}
	n := len(data)

	if n <= b.HardMaxBytes {
		if n > b.TargetBytes {
			info := &TruncationInfo{
				Truncated:     false,
				OriginalBytes: n,
				ReturnedBytes: n,
				HardMaxBytes:  b.HardMaxBytes,
				TargetBytes:   b.TargetBytes,
				OverTarget:    true,
				Message:       "result exceeds soft target but is under hard maximum",
			}
			return v, info, nil
		}
		return v, nil, nil
	}

	// Hard cap exceeded: omit content; return explicit truncation summary.
	info := TruncationInfo{
		Truncated:      true,
		OriginalBytes:  n,
		HardMaxBytes:   b.HardMaxBytes,
		TargetBytes:    b.TargetBytes,
		OverTarget:     true,
		ContentOmitted: true,
		Message:        "structured result exceeded hard maximum; content omitted",
	}
	summary := TruncatedResult{Truncation: info}
	sumBytes, err := json.Marshal(summary)
	if err != nil {
		// Extremely unlikely; fall back to stable quota error without payload.
		return nil, nil, apperr.New(apperr.CodeQuota, "result exceeded hard maximum")
	}
	info.ReturnedBytes = len(sumBytes)
	summary.Truncation.ReturnedBytes = info.ReturnedBytes

	// Defense: summary itself must never exceed hard max.
	if info.ReturnedBytes > b.HardMaxBytes {
		return nil, nil, apperr.New(apperr.CodeQuota, "result exceeded hard maximum")
	}
	return summary, &info, nil
}

// EnforceBudgetOrError is like EnforceBudget but converts hard-cap truncation
// into a stable CodeQuota error when preferError is true.
func EnforceBudgetOrError(v any, b Budgets, preferError bool) (any, *TruncationInfo, error) {
	out, info, err := EnforceBudget(v, b)
	if err != nil {
		return nil, nil, err
	}
	if preferError && info != nil && info.Truncated {
		return nil, info, apperr.New(apperr.CodeQuota, "result exceeded hard maximum")
	}
	return out, info, nil
}

func isEmptyResult(v any) bool {
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case string:
		return x == ""
	case []byte:
		return len(x) == 0
	default:
		return false
	}
}

// ClampListLen returns items capped to MaxListItems (or DefaultMaxListItems).
// remaining is how many items were not returned (for future continuation).
func ClampListLen[T any](items []T, max int) (out []T, remaining int) {
	if max <= 0 {
		max = DefaultMaxListItems
	}
	if len(items) <= max {
		return items, 0
	}
	return items[:max], len(items) - max
}
