package fleetcache

import (
	"strings"
	"sync"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Object-class residuals (secret-free, low-cardinality) — FLC-082.
const (
	ObjectClassResidualAllowed          = "object_class_allowed"
	ObjectClassResidualUnknownDenied    = "object_class_unknown_denied"
	ObjectClassResidualDisabled         = "object_class_disabled"
	ObjectClassResidualExceedsSizeLimit = "object_class_exceeds_size_limit"
)

// ObjectClassPolicy is the explicit admission policy for one object kind.
// Unknown kinds are never present in the default registry (default deny).
type ObjectClassPolicy struct {
	// Kind is the wire/locator object_kind (e.g. console_log).
	Kind string
	// Enabled when false rejects the class even if registered.
	Enabled bool
	// MaxObjectRawBytes hard cap for peer storage of this class (0 = use default).
	MaxObjectRawBytes int64
	// ApprovalToken is a non-secret stable id for audit matrices (not a credential).
	ApprovalToken string
	// Residual is optional operator-facing note (secret-free).
	Residual string
}

// DefaultMaxObjectRawBytesConsoleLog is the v1 console_log peer size ceiling.
const DefaultMaxObjectRawBytesConsoleLog = 256 << 20 // 256 MiB

// DefaultObjectClassRegistry is the product default: console_log only, fail-closed elsewhere.
func DefaultObjectClassRegistry() map[string]ObjectClassPolicy {
	return map[string]ObjectClassPolicy{
		ObjectKindConsoleLog: {
			Kind:              ObjectKindConsoleLog,
			Enabled:           true,
			MaxObjectRawBytes: DefaultMaxObjectRawBytesConsoleLog,
			ApprovalToken:     "flc_v1_console_log_sealed",
			Residual:          "v1 sealed completed console logs only",
		},
	}
}

// ObjectClassAdmission decides whether a kind may enter peer storage/locator paths.
type ObjectClassAdmission struct {
	mu     sync.RWMutex
	byKind map[string]ObjectClassPolicy
}

// NewObjectClassAdmission builds an admission registry. Nil/empty registry still
// fail-closed (unknown denied). Prefer DefaultObjectClassRegistry().
func NewObjectClassAdmission(reg map[string]ObjectClassPolicy) *ObjectClassAdmission {
	a := &ObjectClassAdmission{byKind: make(map[string]ObjectClassPolicy)}
	for k, p := range reg {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		p.Kind = k
		if p.MaxObjectRawBytes < 0 {
			p.MaxObjectRawBytes = 0
		}
		a.byKind[k] = p
	}
	return a
}

// DefaultObjectClassAdmission is the process default (console_log only).
var DefaultObjectClassAdmission = NewObjectClassAdmission(DefaultObjectClassRegistry())

// ObjectClassAdmitResult is secret-free.
type ObjectClassAdmitResult struct {
	Allowed bool
	Kind    string
	// MaxObjectRawBytes effective when Allowed (0 if unlimited-by-policy residual).
	MaxObjectRawBytes int64
	ApprovalToken     string
	Residual          string
}

// AdmitObjectClass fail-closed: unknown or disabled classes cannot enter peer storage.
// rawBytes if >0 is checked against MaxObjectRawBytes when set.
func (a *ObjectClassAdmission) AdmitObjectClass(kind string, rawBytes int64) ObjectClassAdmitResult {
	kind = strings.ToLower(strings.TrimSpace(kind))
	out := ObjectClassAdmitResult{Kind: kind, Residual: ObjectClassResidualUnknownDenied}
	if kind == "" {
		return out
	}
	if a == nil {
		// Fail closed without registry.
		return out
	}
	a.mu.RLock()
	p, ok := a.byKind[kind]
	a.mu.RUnlock()
	if !ok {
		return out
	}
	if !p.Enabled {
		out.Residual = ObjectClassResidualDisabled
		out.ApprovalToken = p.ApprovalToken
		return out
	}
	maxB := p.MaxObjectRawBytes
	if maxB <= 0 && kind == ObjectKindConsoleLog {
		maxB = DefaultMaxObjectRawBytesConsoleLog
	}
	if rawBytes > 0 && maxB > 0 && rawBytes > maxB {
		out.Residual = ObjectClassResidualExceedsSizeLimit
		out.MaxObjectRawBytes = maxB
		out.ApprovalToken = p.ApprovalToken
		return out
	}
	out.Allowed = true
	out.MaxObjectRawBytes = maxB
	out.ApprovalToken = p.ApprovalToken
	out.Residual = ObjectClassResidualAllowed
	if p.Residual != "" {
		out.Residual = ObjectClassResidualAllowed // keep machine-stable residual
	}
	return out
}

// AdmitObjectClass uses DefaultObjectClassAdmission.
func AdmitObjectClass(kind string, rawBytes int64) ObjectClassAdmitResult {
	return DefaultObjectClassAdmission.AdmitObjectClass(kind, rawBytes)
}

// RequireObjectClass fails closed with apperr when not admitted (locator/publish gates).
func RequireObjectClass(kind string, rawBytes int64) error {
	res := AdmitObjectClass(kind, rawBytes)
	if res.Allowed {
		return nil
	}
	switch res.Residual {
	case ObjectClassResidualExceedsSizeLimit:
		return apperr.New(apperr.CodeQuota, "object class exceeds size limit")
	case ObjectClassResidualDisabled:
		return apperr.New(apperr.CodePolicyDenial, "object class disabled")
	default:
		return apperr.New(apperr.CodePolicyDenial, "object class not approved for peer storage")
	}
}

// ApprovedObjectKinds returns sorted-stable list of enabled kinds (observable residual).
func (a *ObjectClassAdmission) ApprovedObjectKinds() []string {
	if a == nil {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.byKind))
	for k, p := range a.byKind {
		if p.Enabled {
			out = append(out, k)
		}
	}
	// Stable order: console_log first then others.
	if len(out) > 1 {
		// simple insertion order not guaranteed; sort by name without importing sort if few
		for i := 0; i < len(out); i++ {
			for j := i + 1; j < len(out); j++ {
				if out[j] < out[i] {
					out[i], out[j] = out[j], out[i]
				}
			}
		}
	}
	return out
}

// ObjectClassStatusResidual is a secret-free operator string for StatusSummary.
func ObjectClassStatusResidual() string {
	kinds := DefaultObjectClassAdmission.ApprovedObjectKinds()
	if len(kinds) == 0 {
		return "object_classes:none; default_deny"
	}
	return "object_classes:" + strings.Join(kinds, ",") + "; unknown_default_deny"
}
