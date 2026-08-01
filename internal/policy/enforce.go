package policy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// Reason codes for multi-layer enforcement (POL-004). Stable and non-secret.
const (
	ReasonUnclassifiedRequest = "unclassified_request"
	ReasonStoreDenied         = "store_denied"
	ReasonContextCancelled    = "context_cancelled"
)

// ---------------------------------------------------------------------------
// Handler / registry middleware (PEP)
// ---------------------------------------------------------------------------

// CheckToolAccess is the reusable handler middleware (POL-004).
// Call before every tool body — including test-only force-registered mutations.
//
// Order: context → read-only (mutations) → deny-only MCP RBAC.
// Nil gate fails closed for mutations. Nil evaluator skips RBAC (RO still applies).
func CheckToolAccess(ctx context.Context, gate *ReadOnlyGate, ev PolicyEvaluator, subject Subject, toolName string, class EffectClass) error {
	return CheckToolAccessWithTarget(ctx, gate, ev, subject, toolName, class, Target{})
}

// CheckToolAccessWithTarget is CheckToolAccess plus optional job/target scope.
func CheckToolAccessWithTarget(ctx context.Context, gate *ReadOnlyGate, ev PolicyEvaluator, subject Subject, toolName string, class EffectClass, target Target) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "policy check cancelled", err)
	}
	name := strings.TrimSpace(toolName)
	if name == "" {
		return apperr.New(apperr.CodePolicyDenial, "tool name is required for policy evaluation")
	}
	if class == EffectMutate {
		if err := gate.DenyMutation(name); err != nil {
			return err
		}
	}
	if ev != nil {
		d := ev.Evaluate(subject, Action{ToolName: name, Class: class}, target)
		if err := d.Err(); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Jenkins request guard (network PEP)
// ---------------------------------------------------------------------------

// ReadOnlyMutationGuard implements jenkins.MutationGuard using a ReadOnlyGate
// and the Jenkins request classifier (POL-004).
//
// GET/HEAD/auth are allowed under RO. Mutate and unclassified write paths are
// denied when the gate is effective.
type ReadOnlyMutationGuard struct {
	Gate *ReadOnlyGate
}

// CheckRequest implements jenkins.MutationGuard.
func (g ReadOnlyMutationGuard) CheckRequest(ctx context.Context, class jenkins.RequestClass, method, path string) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "policy check cancelled", err)
	}
	if !jenkins.RequiresMutationPermission(class) {
		return nil
	}
	// Unclassified under RO: fail closed with a distinct reason code surface.
	if g.Gate == nil || g.Gate.Effective() {
		if class == jenkins.RequestUnclassified {
			msg := fmt.Sprintf("jenkins request denied: unclassified %s path under read-only", strings.ToUpper(strings.TrimSpace(method)))
			return apperr.New(apperr.CodePolicyDenial, msg)
		}
		return g.Gate.DenyMutation("jenkins:" + classifyLabel(class, method, path))
	}
	return nil
}

func classifyLabel(class jenkins.RequestClass, method, path string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "REQUEST"
	}
	// Short, non-secret label for denial messages (no query/body).
	p := strings.TrimSpace(path)
	if i := strings.Index(p, "?"); i >= 0 {
		p = p[:i]
	}
	if len(p) > 64 {
		p = p[:64]
	}
	if p == "" {
		return string(class)
	}
	return m + " " + p
}

// NewReadOnlyMutationGuard returns a guard for the given gate (nil ⇒ fail-closed RO).
func NewReadOnlyMutationGuard(gate *ReadOnlyGate) ReadOnlyMutationGuard {
	if gate == nil {
		gate = NewDefaultReadOnlyGate()
	}
	return ReadOnlyMutationGuard{Gate: gate}
}

// ---------------------------------------------------------------------------
// Cache / store read helper (storage PEP stub)
// ---------------------------------------------------------------------------

// StoreReadAction is the synthetic tool name used when evaluating store/cache
// reads against deny-only MCP policy (POL-004). LogStore/ArtifactStore callers
// should pass this (or a more specific future action) before serving bytes.
const StoreReadAction = "store_cached_read"

// CheckStoreRead evaluates MCP policy before a LogStore/ArtifactStore read
// when an evaluator is provided. Nil evaluator ⇒ allow (caller still has RO
// and Jenkins gates). Empty/anonymous subjects fail closed when ev is non-nil.
//
// resource is a non-secret label (job full name, generation id, etc.) for
// target scoping; it is never logged with secrets by this helper.
func CheckStoreRead(ctx context.Context, ev PolicyEvaluator, subject Subject, resource string) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "store policy check cancelled", err)
	}
	if ev == nil {
		return nil
	}
	target := Target{JobName: strings.TrimSpace(resource)}
	d := ev.Evaluate(subject, Action{ToolName: StoreReadAction, Class: EffectRead}, target)
	if d.Denied() {
		// Prefer evaluator explanation; ensure policy_denial code.
		if err := d.Err(); err != nil {
			return err
		}
		return apperr.New(apperr.CodePolicyDenial, "cached content denied by MCP policy")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Context-aware evaluate + overhead helper
// ---------------------------------------------------------------------------

// EvaluateWithContext runs Evaluate after a cancellation check (POL-004).
func EvaluateWithContext(ctx context.Context, ev PolicyEvaluator, subject Subject, action Action, target Target) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{
			Effect:      EffectDeny,
			ReasonCode:  ReasonContextCancelled,
			Explanation: "policy evaluation cancelled",
		}, apperr.Wrap(apperr.CodeCancelled, "policy evaluation cancelled", err)
	}
	if ev == nil {
		return Decision{
			Effect:      EffectDeny,
			ReasonCode:  ReasonNoEvaluator,
			Explanation: "MCP policy evaluator is not configured (fail closed)",
		}, nil
	}
	return ev.Evaluate(subject, action, target), nil
}

// MeasureEvaluate runs Evaluate n times and returns average duration.
// Used by conformance tests to bound overhead (POL-004/005).
func MeasureEvaluate(ev PolicyEvaluator, subject Subject, action Action, target Target, n int) time.Duration {
	if n <= 0 {
		n = 1
	}
	start := time.Now()
	for i := 0; i < n; i++ {
		_ = ev.Evaluate(subject, action, target)
	}
	return time.Since(start) / time.Duration(n)
}
