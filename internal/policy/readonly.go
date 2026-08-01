package policy

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Source identifiers for effective read-only (status/doctor; non-secret).
const (
	SourceBuiltinDefault  = "builtin_default"
	SourceCLIFlag         = "cli_flag"         // --read-only
	SourceEnv             = "env"              // JENKINS_MCP_READ_ONLY
	SourceProfile         = "profile"          // profile.read_only
	SourceEnterpriseForce = "enterprise_force" // signed force_read_only
	SourceAllowMutations  = "allow_mutations"  // --allow-mutations (test/pilot opt-in)
)

// EnvReadOnlyVar is the process environment key for read-only (POL-001).
const EnvReadOnlyVar = "JENKINS_MCP_READ_ONLY"

// EnterpriseForce is the signed enterprise policy stub (ADR 0004).
// When absent (nil) or ForceReadOnly returns ok=false, the source is ignored.
// When force=true, read-only cannot be disabled by --allow-mutations or profile.
// Implementations may be hot-updated (see DynamicForce) — ReadOnlyGate re-reads
// Force on every Effective() / DenyMutation call.
type EnterpriseForce interface {
	// ForceReadOnly reports whether enterprise policy forces read-only.
	// ok=false means no enterprise force is configured (ignore this source).
	ForceReadOnly() (force bool, ok bool)
}

// StaticForce is a test/stub EnterpriseForce with a fixed value.
type StaticForce struct {
	Force bool
	// Present when false makes ForceReadOnly return ok=false (ignore).
	Present bool
}

// ForceReadOnly implements EnterpriseForce.
func (s StaticForce) ForceReadOnly() (force bool, ok bool) {
	if !s.Present {
		return false, false
	}
	return s.Force, true
}

// DynamicForce is a thread-safe EnterpriseForce that can be hot-applied when a
// policy overlay reloads (Wave 25). Safe for concurrent ForceReadOnly / Set.
//
// Encoding (atomic uint32): bit0=present, bit1=force. present=false ⇒ ok=false
// (source ignored), matching StaticForce / OverlayForce semantics.
type DynamicForce struct {
	state atomic.Uint32
}

const (
	dynForcePresent uint32 = 1 << 0
	dynForceValue   uint32 = 1 << 1
)

// NewDynamicForce returns a DynamicForce with the given initial value.
// present=false means the enterprise force source is absent (ignored).
func NewDynamicForce(force, present bool) *DynamicForce {
	d := &DynamicForce{}
	d.Set(force, present)
	return d
}

// NewDynamicForceFromOverlay seeds force from a loaded overlay.
// Overlay nil ⇒ present=false (source ignored). Non-nil ⇒ present=true and
// force mirrors overlay.force_read_only (including explicit false).
func NewDynamicForceFromOverlay(o *Overlay) *DynamicForce {
	if o == nil {
		return NewDynamicForce(false, false)
	}
	return NewDynamicForce(o.ForceReadOnly, true)
}

// Set updates the force value atomically (Wave 25 policy reload OnSuccess).
// present=false clears the enterprise force contribution.
func (d *DynamicForce) Set(force, present bool) {
	if d == nil {
		return
	}
	var v uint32
	if present {
		v = dynForcePresent
		if force {
			v |= dynForceValue
		}
	}
	d.state.Store(v)
}

// SetFromOverlay updates from a loaded overlay (nil ⇒ present=false).
func (d *DynamicForce) SetFromOverlay(o *Overlay) {
	if d == nil {
		return
	}
	if o == nil {
		d.Set(false, false)
		return
	}
	d.Set(o.ForceReadOnly, true)
}

// ForceReadOnly implements EnterpriseForce.
func (d *DynamicForce) ForceReadOnly() (force bool, ok bool) {
	if d == nil {
		return false, false
	}
	v := d.state.Load()
	if v&dynForcePresent == 0 {
		return false, false
	}
	return v&dynForceValue != 0, true
}

// Inputs are the contributing sources for effective read-only computation.
// Most restrictive wins: any true source → read-only (ADR 0004 / architecture §7.1).
type Inputs struct {
	// FlagReadOnly is true when --read-only was set on the process.
	FlagReadOnly bool
	// EnvReadOnly is true when JENKINS_MCP_READ_ONLY is a truthy value.
	EnvReadOnly bool
	// ProfileReadOnly is non-nil when a profile sets the read_only field.
	// true contributes RO; false does not clear stronger sources.
	ProfileReadOnly *bool
	// Force is optional signed enterprise force_read_only.
	Force EnterpriseForce
	// AllowMutations is a test/pilot-only opt-in (--allow-mutations) that
	// removes the built-in default RO contribution. It cannot defeat
	// flag/env/profile/enterprise force sources.
	AllowMutations bool
	// SkipBuiltinDefault disables the pilot built-in default (normally false).
	// Prefer AllowMutations for opt-in writes; this exists for pure unit tests
	// of individual sources.
	SkipBuiltinDefault bool
}

// State is the computed effective read-only decision plus contributing sources.
type State struct {
	// Effective is true when the process must not expose or execute mutations.
	Effective bool
	// Sources lists non-secret identifiers that contributed true (or the
	// allow-mutations opt-in when Effective is false solely because of it).
	Sources []string
}

// ComputeEffectiveReadOnly applies most-restrictive-wins across Inputs.
// Pilot built-in default is read-only true unless AllowMutations (or
// SkipBuiltinDefault) removes that contribution.
func ComputeEffectiveReadOnly(in Inputs) State {
	var sources []string
	effective := false

	add := func(cond bool, src string) {
		if !cond {
			return
		}
		effective = true
		sources = append(sources, src)
	}

	// Built-in default: true for pilot when no explicit write opt-in.
	if !in.SkipBuiltinDefault && !in.AllowMutations {
		add(true, SourceBuiltinDefault)
	} else if in.AllowMutations {
		// Record opt-in for status/doctor (does not force RO).
		sources = append(sources, SourceAllowMutations)
	}

	add(in.FlagReadOnly, SourceCLIFlag)
	add(in.EnvReadOnly, SourceEnv)
	if in.ProfileReadOnly != nil && *in.ProfileReadOnly {
		add(true, SourceProfile)
	}
	if in.Force != nil {
		if force, ok := in.Force.ForceReadOnly(); ok && force {
			add(true, SourceEnterpriseForce)
		}
	}

	return State{Effective: effective, Sources: sources}
}

// ParseEnvReadOnly interprets JENKINS_MCP_READ_ONLY-style values.
// True for 1/true/yes/on (case-insensitive); false otherwise (including empty).
func ParseEnvReadOnly(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// EnvReadOnlyFromEnviron reads EnvReadOnlyVar from the process environment.
func EnvReadOnlyFromEnviron() bool {
	return ParseEnvReadOnly(os.Getenv(EnvReadOnlyVar))
}

// ReadOnlyGate is the process-wide gate used by tool registration and dispatch.
//
// Inputs are retained so EnterpriseForce can hot-apply mid-serve (Wave 25
// DynamicForce). CLI/env/profile flags stay fixed for the process; only Force
// is expected to change underfoot. Effective() / Sources() recompute on each
// call so DenyMutation and ListTools mutation visibility see live force.
//
// Wave 30: when AllowMutations opt-in is set, mutation tools are registered
// even if Effective() is currently true (e.g. enterprise force_read_only), so
// a later DynamicForce clear can re-expose them via ListTools without restart.
// DenyMutation + ListTools filter still hide/deny while Effective. Without
// AllowMutations (default pilot RO), mutations stay omitted at Register.
type ReadOnlyGate struct {
	inputs Inputs
}

// NewReadOnlyGate builds a gate from Inputs.
func NewReadOnlyGate(in Inputs) *ReadOnlyGate {
	return &ReadOnlyGate{inputs: in}
}

// NewDefaultReadOnlyGate returns the pilot default (read-only true).
func NewDefaultReadOnlyGate() *ReadOnlyGate {
	return NewReadOnlyGate(Inputs{})
}

// Effective reports whether mutations must be denied/omitted.
func (g *ReadOnlyGate) Effective() bool {
	if g == nil {
		// Fail closed: missing gate ⇒ read-only.
		return true
	}
	return ComputeEffectiveReadOnly(g.inputs).Effective
}

// Sources returns contributing source identifiers (non-secret).
func (g *ReadOnlyGate) Sources() []string {
	if g == nil {
		return []string{SourceBuiltinDefault}
	}
	st := ComputeEffectiveReadOnly(g.inputs)
	out := make([]string, len(st.Sources))
	copy(out, st.Sources)
	return out
}

// State returns a copy of the computed state.
func (g *ReadOnlyGate) State() State {
	if g == nil {
		return State{Effective: true, Sources: []string{SourceBuiltinDefault}}
	}
	st := ComputeEffectiveReadOnly(g.inputs)
	out := make([]string, len(st.Sources))
	copy(out, st.Sources)
	return State{Effective: st.Effective, Sources: out}
}

// StatusMap is a non-secret map suitable for status/doctor tool output.
func (g *ReadOnlyGate) StatusMap() map[string]any {
	st := g.State()
	return map[string]any{
		"read_only": st.Effective,
		"sources":   st.Sources,
	}
}

// DenyMutation returns a policy_denial error when read-only is effective.
// Call at the start of every mutation handler (defense in depth if a
// mutation tool is somehow registered or invoked).
func (g *ReadOnlyGate) DenyMutation(toolName string) error {
	if !g.Effective() {
		return nil
	}
	name := strings.TrimSpace(toolName)
	if name == "" {
		name = "mutation"
	}
	// Model-visible message: no secrets, no internal paths.
	msg := fmt.Sprintf("tool %q denied: global read-only is active", name)
	return apperr.New(apperr.CodePolicyDenial, msg)
}

// AllowMutationRegistration reports whether the process is fully write-enabled
// (Effective is false). Used by dispatch readiness checks and status; tools
// registration also consults AllowMutationsOptIn (Wave 30).
func (g *ReadOnlyGate) AllowMutationRegistration() bool {
	return !g.Effective()
}

// AllowMutationsOptIn reports whether Inputs.AllowMutations was set (--allow-mutations
// / pilot write opt-in), without consulting Effective(). When true, production
// Register may still attach mutation tools under current force RO so a later
// DynamicForce clear can re-list them (Wave 30). Nil gate ⇒ false (fail closed).
// Dispatch and ListTools still honor Effective via DenyMutation / filter.
func (g *ReadOnlyGate) AllowMutationsOptIn() bool {
	if g == nil {
		return false
	}
	return g.inputs.AllowMutations
}

// ShouldRegisterMutations reports whether mutation tools should be attached at
// Register. True when fully write-enabled (AllowMutationRegistration) or when
// AllowMutations opt-in is set even under current Effective RO (Wave 30).
// Nil gate ⇒ false (fail-closed default RO, omit mutations).
func (g *ReadOnlyGate) ShouldRegisterMutations() bool {
	if g == nil {
		return false
	}
	return g.AllowMutationRegistration() || g.AllowMutationsOptIn()
}
