package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
)

// Overlay schema / env (CFG-002 / MGR-001).
const (
	// CurrentOverlayVersion is the supported enterprise policy overlay schema.
	CurrentOverlayVersion = 1

	// EnvPolicyFileVar overrides the default overlay path.
	// Empty / unset → $XDG_CONFIG_HOME/jenkins-mcp/policy/overlay.json
	// May point at a plain overlay or a signed overlay.bundle.json envelope.
	EnvPolicyFileVar = "JENKINS_MCP_POLICY_FILE"

	// EnvPolicyRequiredVar when truthy (1/true/yes/on) fails closed if the
	// resolved policy file is missing. Invalid/unreadable present files always
	// fail closed regardless of this flag. Also rejects unsigned overlays when
	// set (production-style enforcement even without trusted keys staging —
	// RequiringSignatureVerifier field-presence check only).
	EnvPolicyRequiredVar = "JENKINS_MCP_POLICY_REQUIRED"

	// EnvRequireSignedPolicyVar when truthy (1/true/yes/on) requires a
	// cryptographically signed policy bundle with trusted public keys
	// (Ed25519). Stronger than POLICY_REQUIRED: fails closed if no trusted
	// keys are configured (staging stub is not accepted). Intended for
	// enterprise gateway hosts / force-off pin (MGR-001 residual lite).
	// Alias intent: refuse unsigned force-off residual paths at serve load.
	EnvRequireSignedPolicyVar = "JENKINS_MCP_REQUIRE_SIGNED_POLICY"
)

// PolicyMode controls default-allow vs default-deny for tools (POL-002).
type PolicyMode string

const (
	// ModePilot allows known read tools when no explicit deny matches.
	// Explicit deny_tools always deny. Default when mode is empty.
	ModePilot PolicyMode = "pilot"
	// ModeStrict denies unknown (unclassified) tools by default and still
	// applies explicit deny_tools. Used when enterprises require a closed set.
	ModeStrict PolicyMode = "strict"
)

// Overlay is the versioned enterprise policy document (CFG-002).
// It is secret-free JSON. Production deployments SHOULD use signed bundles
// (BundleEnvelope + Ed25519SignatureVerifier); see MGR-001.
//
// Example (plain pilot overlay):
//
//	{
//	  "version": 1,
//	  "force_read_only": true,
//	  "mode": "pilot",
//	  "deny_tools": ["jenkins_get_build_logs"],
//	  "deny_job_prefixes": ["secret-folder"],
//	  "deny_node_names": ["prod-agent-*"],
//	  "deny_view_names": ["secret-view"],
//	  "deny_artifact_paths": ["secrets/**", "*.pem"],
//	  "deny_branch_names": ["release/*", "main"],
//	  "max_result_bytes": 65536,
//	  "max_tools_per_minute": 15,
//	  "max_tools_burst": 5,
//	  "fleet_telemetry_force_off": true
//	}
type Overlay struct {
	// Version is the schema version (required; must equal CurrentOverlayVersion).
	Version int `json:"version"`

	// ForceReadOnly when true cannot be defeated by --allow-mutations, profile,
	// or weaker CLI flags (wired into ReadOnlyGate via EnterpriseForce).
	ForceReadOnly bool `json:"force_read_only"`

	// FleetTelemetryForceOff when true forces fleet health telemetry off for this
	// process regardless of JENKINS_MCP_TELEMETRY (MGR-002). Fail-closed lower-only
	// pin: never elevates enablement. Env cannot re-enable while true; clearing to
	// false on hot-reload re-allows env enable for a live collector that was
	// force-off'd mid-session. Secret-free boolean only.
	FleetTelemetryForceOff bool `json:"fleet_telemetry_force_off"`

	// Mode is "pilot" (default) or "strict". Unknown values fail closed at load.
	Mode PolicyMode `json:"mode,omitempty"`

	// DenyTools is an optional explicit deny list of MCP tool names.
	// Matching is exact on the registered tool name (case-sensitive).
	DenyTools []string `json:"deny_tools,omitempty"`

	// AllowMutationTools (MUT-017): when non-empty and mutations are enabled,
	// only these mutation tools register. Empty = all classified mutations.
	AllowMutationTools []string `json:"allow_mutation_tools,omitempty"`
	// AllowInterruptModes (MUT-017): when non-empty, only these interrupt modes
	// (stop|term|kill) are allowed for jenkins_interrupt_build.
	AllowInterruptModes []string `json:"allow_interrupt_modes,omitempty"`
	// AllowMutationJobPrefixes (MUT-017): when non-empty, mutation targets must
	// match at least one job full-name prefix.
	AllowMutationJobPrefixes []string `json:"allow_mutation_job_prefixes,omitempty"`

	// DenyJobPrefixes is an optional list of job full names / folder patterns
	// denied at call time when tool args include job_name (POL-004 lite).
	// Match: exact full name or folder children (prefix + "/"); optional trailing
	// /** (same as folder+descendants); single-segment *; mid-path **; limited
	// {a,b} braces (Wave 30). Not bare string prefix. Overly broad entries
	// (*, **, /**) and invalid braces fail Validate.
	// Empty list ⇒ no job-scoped MCP restriction from overlay. See MatchDenyJobPattern.
	DenyJobPrefixes []string `json:"deny_job_prefixes,omitempty"`

	// DenyNodeNames is an optional list of node/agent name patterns denied at
	// call time when tool args include node_name / NodeName (Wave 35).
	// Same ValidateDenyJobPattern / MatchDenyJobPattern language as jobs.
	// Empty list ⇒ no node-scoped MCP restriction from overlay.
	DenyNodeNames []string `json:"deny_node_names,omitempty"`

	// DenyViewNames is an optional list of view name patterns denied at call
	// time when tool args include view_name / ViewName or seed view / View
	// (Wave 35). Same pattern language as deny_job_prefixes.
	// Empty list ⇒ no view-scoped MCP restriction from overlay.
	DenyViewNames []string `json:"deny_view_names,omitempty"`

	// DenyArtifactPaths is an optional list of relative artifact path patterns
	// denied at call time when tool args include path / Path or artifact_path /
	// ArtifactPath (Wave 36; e.g. jenkins_get_artifact_text). Same pattern
	// language as deny_job_prefixes (ValidateDenyJobPattern / MatchDenyJobPattern).
	// Empty list ⇒ no artifact-path MCP restriction from overlay.
	DenyArtifactPaths []string `json:"deny_artifact_paths,omitempty"`

	// DenyBranchNames is an optional list of multibranch/matrix branch name
	// patterns denied at call time when tool args include branch_name /
	// BranchName (or seed branch / Branch when BranchName empty) (Wave 37).
	// Wave 38–39: also applied when BranchName is empty but job_name / JobName
	// is a multi-segment path — matches BranchDenyCandidates (leaf,
	// intermediate segs[1..], path suffixes, full JobName) so tools without a
	// branch_name arg still fail closed (incl. team/mb/release/1.2 vs
	// release/*). Slashy BranchName also matches leaf/suffix candidates.
	// Single-segment JobName alone does not apply branch deny. Same
	// ValidateDenyJobPattern / MatchDenyJobPattern language as jobs.
	// Empty list ⇒ no branch-scoped MCP restriction from overlay.
	DenyBranchNames []string `json:"deny_branch_names,omitempty"`

	// MaxResultBytes when set is an upper bound that can only lower the
	// process hard max (never raise server limits). nil means no overlay cap.
	MaxResultBytes *int `json:"max_result_bytes,omitempty"`

	// MaxToolsPerMinute when set is an upper bound that can only lower the
	// serve-bootstrap per-subject tool rate (HOST-006; gateway.SubjectRateLimiter.LowerRate).
	// Never raises rate. nil / omitted means no overlay rate cap (env/bootstrap unchanged).
	MaxToolsPerMinute *int `json:"max_tools_per_minute,omitempty"`

	// MaxToolsBurst when set can only lower per-subject token-bucket burst
	// (HOST-006 LowerRate). nil / omitted means no overlay burst cap.
	MaxToolsBurst *int `json:"max_tools_burst,omitempty"`

	// Signature is a legacy stub field on plain overlays (CFG-002 pilot).
	// Signed production bundles use BundleEnvelope.Signature instead; this
	// field is cleared on verified envelope overlays.
	Signature string `json:"signature,omitempty"`

	// Subjects holds optional per-user and per-group deny-only bindings (POL-006).
	// Global fields above always apply; matching bindings only add denials /
	// lower budgets. Never elevates force_read_only or Jenkins access.
	// Admin CRUD / SPA: UI-011 residual until operator UI ships.
	Subjects *SubjectBindings `json:"subjects,omitempty"`
}

// SignatureVerifier checks integrity of an enterprise policy overlay.
//
// Production deployments use Ed25519SignatureVerifier with trusted public keys
// (MGR-001). NopSignatureVerifier remains pilot-only when no trusted keys exist.
type SignatureVerifier interface {
	// Verify returns nil when the overlay is acceptable for the given raw bytes.
	// raw is the exact file content that was unmarshaled into overlay (or the
	// envelope that produced overlay).
	Verify(overlay *Overlay, raw []byte) error
}

// NopSignatureVerifier accepts any structurally valid overlay.
// Documented as pilot-only; production needs signed bundles.
type NopSignatureVerifier struct{}

// Verify implements SignatureVerifier (always succeeds when overlay non-nil).
func (NopSignatureVerifier) Verify(overlay *Overlay, raw []byte) error {
	if overlay == nil {
		return apperr.New(apperr.CodePolicyDenial, "policy overlay is nil")
	}
	_ = raw
	return nil
}

// RequiringSignatureVerifier fails closed when signature is empty.
// Still not real crypto — only enforces presence of the signature field for tests
// and staged rollouts until trusted keys are configured. Prefer
// Ed25519SignatureVerifier with RequireSigned when keys are present.
type RequiringSignatureVerifier struct{}

// Verify implements SignatureVerifier.
func (RequiringSignatureVerifier) Verify(overlay *Overlay, raw []byte) error {
	if overlay == nil {
		return apperr.New(apperr.CodePolicyDenial, "policy overlay is nil")
	}
	// Signed envelope path: detect and require non-empty envelope signature
	// (top-level signature or multi-sig signatures[] entry).
	if LooksLikeBundle(raw) {
		var env BundleEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return apperr.Wrap(apperr.CodePolicyDenial, "policy bundle JSON invalid", err)
		}
		if strings.TrimSpace(env.Signature) == "" && !env.HasMultiSignatures() {
			return apperr.New(apperr.CodePolicyDenial,
				"policy overlay signature required but missing (unsigned bundles rejected)")
		}
		return nil
	}
	if strings.TrimSpace(overlay.Signature) == "" {
		return apperr.New(apperr.CodePolicyDenial,
			"policy overlay signature required but missing (unsigned bundles rejected)")
	}
	_ = raw
	return nil
}

// LoadOptions configures overlay resolution (CFG-002 / MGR-001).
type LoadOptions struct {
	// Path is an explicit file path. Empty → env JENKINS_MCP_POLICY_FILE, then default XDG path.
	Path string
	// Required when true fails closed if the resolved path does not exist.
	// Also set from JENKINS_MCP_POLICY_REQUIRED when using LoadFromEnviron.
	Required bool
	// Verifier checks signatures. Nil ⇒ chosen by LoadFromEnviron or NopSignatureVerifier.
	Verifier SignatureVerifier
	// Paths supplies XDG locations. Nil ⇒ config.Resolve().
	Paths *config.Paths
	// SkipLastGood when true does not open or update the last-good cache
	// (CLI verify --no-cache, unit tests).
	SkipLastGood bool
	// LastGoodPath overrides the default last-good cache path when non-empty.
	LastGoodPath string
	// TrustedKeys injects a key set (tests / CLI --keys). Nil ⇒ load from environ
	// only inside LoadFromEnviron / DefaultVerifierFromEnviron.
	TrustedKeys TrustedKeySet
}

// LoadResult is the outcome of loading an overlay (absent is not an error).
type LoadResult struct {
	// Overlay is nil when no file was present and Required was false.
	Overlay *Overlay
	// Bundle is set when the loaded file was a signed envelope (may be nil for plain).
	Bundle *BundleEnvelope
	// Path is the resolved path that was inspected (may be empty if Resolve failed early).
	Path string
	// Present is true when a file existed at Path.
	Present bool
	// SignatureState is a non-secret status token for status/doctor output.
	// Values: absent, unverified_pilot, present_field, verified.
	SignatureState string
	// BundleSeq is the envelope sequence when verified (0 if plain/absent).
	BundleSeq int64
	// KeyID is the verifying key id when verified (empty otherwise; never key material).
	KeyID string
	// ContentHash is sha256 of signing payload when verified (empty otherwise).
	ContentHash string
}

// OverlayForce adapts a loaded Overlay to EnterpriseForce (CFG-002).
// The Overlay field ForceReadOnly cannot also be a method name, so this
// thin adapter wires force_read_only into ReadOnlyGate.Inputs.Force.
type OverlayForce struct {
	Overlay *Overlay
}

// ForceReadOnly implements EnterpriseForce.
// ok is true only when an overlay was loaded; force follows the field.
func (f OverlayForce) ForceReadOnly() (force bool, ok bool) {
	if f.Overlay == nil {
		return false, false
	}
	return f.Overlay.ForceReadOnly, true
}

// AsEnterpriseForce returns an EnterpriseForce for a loaded overlay (nil-safe).
func AsEnterpriseForce(o *Overlay) EnterpriseForce {
	if o == nil {
		return nil
	}
	return OverlayForce{Overlay: o}
}

// NormalizeMode returns ModePilot for empty mode after validation.
func (o *Overlay) NormalizeMode() PolicyMode {
	if o == nil || o.Mode == "" {
		return ModePilot
	}
	return o.Mode
}

// Validate checks structural constraints (no network, no secrets).
func (o *Overlay) Validate() error {
	if o == nil {
		return apperr.New(apperr.CodeInvalidArgument, "policy overlay is nil")
	}
	if o.Version != CurrentOverlayVersion {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported policy overlay version %d (want %d)", o.Version, CurrentOverlayVersion))
	}
	switch o.Mode {
	case "", ModePilot, ModeStrict:
		// ok
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported policy mode %q (use pilot or strict)", o.Mode))
	}
	for i, name := range o.DenyTools {
		name = strings.TrimSpace(name)
		if name == "" {
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("deny_tools[%d] is empty", i))
		}
		o.DenyTools[i] = name
	}
	for i, p := range o.DenyJobPrefixes {
		p = strings.TrimSpace(p)
		if err := validateDenyPatternIndex("deny_job_prefixes", i, p); err != nil {
			return err
		}
		o.DenyJobPrefixes[i] = p
	}
	for i, p := range o.DenyNodeNames {
		p = strings.TrimSpace(p)
		if err := validateDenyPatternIndex("deny_node_names", i, p); err != nil {
			return err
		}
		o.DenyNodeNames[i] = p
	}
	for i, p := range o.DenyViewNames {
		p = strings.TrimSpace(p)
		if err := validateDenyPatternIndex("deny_view_names", i, p); err != nil {
			return err
		}
		o.DenyViewNames[i] = p
	}
	for i, p := range o.DenyArtifactPaths {
		p = strings.TrimSpace(p)
		if err := validateDenyPatternIndex("deny_artifact_paths", i, p); err != nil {
			return err
		}
		o.DenyArtifactPaths[i] = p
	}
	for i, p := range o.DenyBranchNames {
		p = strings.TrimSpace(p)
		if err := validateDenyPatternIndex("deny_branch_names", i, p); err != nil {
			return err
		}
		o.DenyBranchNames[i] = p
	}
	if o.MaxResultBytes != nil {
		if *o.MaxResultBytes <= 0 {
			return apperr.New(apperr.CodeInvalidArgument, "max_result_bytes must be positive when set")
		}
	}
	if o.MaxToolsPerMinute != nil {
		if *o.MaxToolsPerMinute <= 0 {
			return apperr.New(apperr.CodeInvalidArgument, "max_tools_per_minute must be positive when set")
		}
	}
	if o.MaxToolsBurst != nil {
		if *o.MaxToolsBurst <= 0 {
			return apperr.New(apperr.CodeInvalidArgument, "max_tools_burst must be positive when set")
		}
	}
	if err := o.Subjects.Validate(); err != nil {
		return err
	}
	return nil
}

// ResolvePolicyPath returns the path to load given opts and environment.
// When no explicit/env path is set, prefers overlay.bundle.json if it exists,
// otherwise the plain overlay.json default.
func ResolvePolicyPath(opts LoadOptions) (string, error) {
	if p := strings.TrimSpace(opts.Path); p != "" {
		return p, nil
	}
	if p := strings.TrimSpace(os.Getenv(EnvPolicyFileVar)); p != "" {
		return p, nil
	}
	var paths config.Paths
	if opts.Paths != nil {
		paths = *opts.Paths
	} else {
		resolved, err := config.Resolve()
		if err != nil {
			return "", apperr.Wrap(apperr.CodeInternal, "resolve config paths for policy", err)
		}
		paths = resolved
	}
	bundlePath := paths.DefaultPolicyBundleFile()
	if st, err := os.Stat(bundlePath); err == nil && !st.IsDir() {
		return bundlePath, nil
	}
	return paths.DefaultPolicyFile(), nil
}

// LoadOverlay loads and validates an enterprise policy overlay or signed bundle.
//
// Fail-closed rules:
//   - File present but unreadable or invalid JSON/schema → error (never partial).
//   - SignatureVerifier rejects → error.
//   - File absent + Required → error.
//   - File absent + !Required → (nil overlay, nil error) with Present=false.
//   - Signed bundle: invalid/expired/untrusted/downgraded → error (MGR-001).
func LoadOverlay(opts LoadOptions) (LoadResult, error) {
	path, err := ResolvePolicyPath(opts)
	if err != nil {
		return LoadResult{}, err
	}
	res := LoadResult{Path: path, SignatureState: SigStateAbsent}

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if opts.Required || policyRequiredFromEnv() {
				return res, apperr.New(apperr.CodePolicyDenial,
					fmt.Sprintf("enterprise policy required but missing at %s", sanitizePath(path)))
			}
			return res, nil
		}
		// Unreadable (permissions, I/O): fail closed when the path was intended.
		return res, apperr.Wrap(apperr.CodePolicyDenial,
			fmt.Sprintf("enterprise policy unreadable at %s", sanitizePath(path)), err)
	}
	res.Present = true

	verifier := opts.Verifier
	if verifier == nil {
		verifier = NopSignatureVerifier{}
	}

	if LooksLikeBundle(raw) {
		// Signed envelopes always require Ed25519 verification — never accept via Nop.
		if _, ok := verifier.(Ed25519SignatureVerifier); !ok {
			return res, apperr.New(apperr.CodePolicyDenial,
				"signed policy bundle requires trusted public keys (configure JENKINS_MCP_POLICY_TRUSTED_KEYS or policy/trusted_keys/)")
		}
		var env BundleEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return res, apperr.Wrap(apperr.CodePolicyDenial,
				"enterprise policy bundle is invalid JSON (fail closed)", err)
		}
		// Validate overlay structure before crypto so bad mode/version still fail closed.
		env.Overlay.Signature = ""
		if err := env.Overlay.Validate(); err != nil {
			return res, apperr.Wrap(apperr.CodePolicyDenial,
				"enterprise policy overlay failed validation (fail closed)", err)
		}
		// Verifier performs full envelope validation + crypto + last-good.
		// Return verifier error as-is (already policy_denial with specific reason).
		if err := verifier.Verify(&env.Overlay, raw); err != nil {
			return res, err
		}
		res.SignatureState = SigStateVerified
		if h, err := ContentHash(&env); err == nil {
			res.ContentHash = h
		}
		res.BundleSeq = env.BundleSeq
		res.KeyID = env.KeyID
		env.Overlay.Signature = ""
		res.Overlay = &env.Overlay
		envCopy := env
		res.Bundle = &envCopy
		return res, nil
	}

	// Plain overlay document.
	var o Overlay
	if err := json.Unmarshal(raw, &o); err != nil {
		return res, apperr.Wrap(apperr.CodePolicyDenial,
			"enterprise policy overlay is invalid JSON (fail closed)", err)
	}
	if err := o.Validate(); err != nil {
		return res, apperr.Wrap(apperr.CodePolicyDenial,
			"enterprise policy overlay failed validation (fail closed)", err)
	}

	if err := verifier.Verify(&o, raw); err != nil {
		return res, err
	}

	if strings.TrimSpace(o.Signature) != "" {
		res.SignatureState = SigStatePresentField
	} else {
		res.SignatureState = SigStateUnverifiedPilot
	}
	res.Overlay = &o
	return res, nil
}

// DefaultVerifierFromEnviron builds the production/pilot verifier for LoadFromEnviron.
//
//	trusted keys present → Ed25519SignatureVerifier (RequireSigned=true)
//	REQUIRE_SIGNED_POLICY without keys → error (fail closed; no staging stub)
//	POLICY_REQUIRED without keys → RequiringSignatureVerifier (staging)
//	else → NopSignatureVerifier (pilot)
func DefaultVerifierFromEnviron(opts LoadOptions) (SignatureVerifier, error) {
	keys := opts.TrustedKeys
	if keys == nil {
		var err error
		keys, err = LoadTrustedKeysFromEnviron(opts.Paths)
		if err != nil {
			return nil, err
		}
	}
	requireSigned := requireSignedPolicyFromEnv()
	required := opts.Required || policyRequiredFromEnv() || requireSigned
	if requireSigned && keys.Len() == 0 {
		// MGR-001 residual lite: enterprise gateway hosts must pin real Ed25519
		// verification — field-presence staging is not force-off safe.
		return nil, apperr.New(apperr.CodePolicyDenial,
			"JENKINS_MCP_REQUIRE_SIGNED_POLICY=1 requires trusted public keys "+
				"(set JENKINS_MCP_POLICY_TRUSTED_KEYS or policy/trusted_keys/); "+
				"unsigned pilot overlays and staging stub signatures are rejected")
	}
	if keys.Len() > 0 {
		var cache *LastGoodCache
		if !opts.SkipLastGood {
			cachePath := strings.TrimSpace(opts.LastGoodPath)
			if cachePath == "" {
				p, err := DefaultLastGoodPath(opts.Paths)
				if err != nil {
					return nil, err
				}
				cachePath = p
			}
			c, err := OpenLastGoodCache(cachePath)
			if err != nil {
				return nil, err
			}
			cache = c
		}
		return BundleVerifier(keys, cache, true), nil
	}
	if required {
		return RequiringSignatureVerifier{}, nil
	}
	return NopSignatureVerifier{}, nil
}

// LoadFromEnviron is LoadOverlay with Required and Verifier from the environment.
// When trusted public keys are present, Ed25519 verification is enforced and
// unsigned plain overlays are rejected. When no keys are configured, pilot
// NopSignatureVerifier is used (signature_state=unverified_pilot).
// JENKINS_MCP_REQUIRE_SIGNED_POLICY=1 fails closed without trusted keys.
func LoadFromEnviron() (LoadResult, error) {
	opts := LoadOptions{Required: policyRequiredFromEnv() || requireSignedPolicyFromEnv()}
	v, err := DefaultVerifierFromEnviron(opts)
	if err != nil {
		return LoadResult{}, err
	}
	opts.Verifier = v
	return LoadOverlay(opts)
}

func policyRequiredFromEnv() bool {
	return ParseEnvReadOnly(os.Getenv(EnvPolicyRequiredVar)) // same truthy parser
}

func requireSignedPolicyFromEnv() bool {
	return ParseEnvReadOnly(os.Getenv(EnvRequireSignedPolicyVar))
}

// sanitizePath returns a base-only path for model-visible errors when possible.
// Full absolute paths may appear in process logs; keep error messages short.
func sanitizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "(unset)"
	}
	return filepath.Base(p)
}

// EffectiveMaxResultBytes returns the overlay cap when set and positive.
func (o *Overlay) EffectiveMaxResultBytes() (int, bool) {
	if o == nil || o.MaxResultBytes == nil || *o.MaxResultBytes <= 0 {
		return 0, false
	}
	return *o.MaxResultBytes, true
}

// EffectiveMaxToolsPerMinute returns the overlay per-subject tools/min cap when
// set and positive (HOST-006; serve applies via SubjectRateLimiter.LowerRate only).
func (o *Overlay) EffectiveMaxToolsPerMinute() (int, bool) {
	if o == nil || o.MaxToolsPerMinute == nil || *o.MaxToolsPerMinute <= 0 {
		return 0, false
	}
	return *o.MaxToolsPerMinute, true
}

// EffectiveMaxToolsBurst returns the overlay per-subject burst cap when set and
// positive (HOST-006 LowerRate only).
func (o *Overlay) EffectiveMaxToolsBurst() (int, bool) {
	if o == nil || o.MaxToolsBurst == nil || *o.MaxToolsBurst <= 0 {
		return 0, false
	}
	return *o.MaxToolsBurst, true
}

// DenyToolSet returns a set of denied tool names for O(1) lookup.
func (o *Overlay) DenyToolSet() map[string]struct{} {
	if o == nil || len(o.DenyTools) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(o.DenyTools))
	for _, n := range o.DenyTools {
		out[n] = struct{}{}
	}
	return out
}

// DenyJobPrefixList returns a copy of deny_job_prefixes (empty ⇒ nil).
func (o *Overlay) DenyJobPrefixList() []string {
	if o == nil || len(o.DenyJobPrefixes) == 0 {
		return nil
	}
	out := make([]string, len(o.DenyJobPrefixes))
	copy(out, o.DenyJobPrefixes)
	return out
}

// DenyNodeNameList returns a copy of deny_node_names (empty ⇒ nil).
func (o *Overlay) DenyNodeNameList() []string {
	if o == nil || len(o.DenyNodeNames) == 0 {
		return nil
	}
	out := make([]string, len(o.DenyNodeNames))
	copy(out, o.DenyNodeNames)
	return out
}

// DenyViewNameList returns a copy of deny_view_names (empty ⇒ nil).
func (o *Overlay) DenyViewNameList() []string {
	if o == nil || len(o.DenyViewNames) == 0 {
		return nil
	}
	out := make([]string, len(o.DenyViewNames))
	copy(out, o.DenyViewNames)
	return out
}

// DenyArtifactPathList returns a copy of deny_artifact_paths (empty ⇒ nil).
func (o *Overlay) DenyArtifactPathList() []string {
	if o == nil || len(o.DenyArtifactPaths) == 0 {
		return nil
	}
	out := make([]string, len(o.DenyArtifactPaths))
	copy(out, o.DenyArtifactPaths)
	return out
}

// DenyBranchNameList returns a copy of deny_branch_names (empty ⇒ nil).
func (o *Overlay) DenyBranchNameList() []string {
	if o == nil || len(o.DenyBranchNames) == 0 {
		return nil
	}
	out := make([]string, len(o.DenyBranchNames))
	copy(out, o.DenyBranchNames)
	return out
}

// StatusMap is a non-secret map for status/doctor (CFG-002 / MGR-001 provenance).
func (r LoadResult) StatusMap() map[string]any {
	m := map[string]any{
		"policy_present":   r.Present,
		"policy_path_base": sanitizePath(r.Path),
		"signature_state":  r.SignatureState,
	}
	if r.Overlay != nil {
		m["policy_version"] = r.Overlay.Version
		m["force_read_only"] = r.Overlay.ForceReadOnly
		m["fleet_telemetry_force_off"] = r.Overlay.FleetTelemetryForceOff
		m["mode"] = string(r.Overlay.NormalizeMode())
		m["deny_tools_count"] = len(r.Overlay.DenyTools)
		m["deny_job_prefixes_count"] = len(r.Overlay.DenyJobPrefixes)
		m["deny_node_names_count"] = len(r.Overlay.DenyNodeNames)
		m["deny_view_names_count"] = len(r.Overlay.DenyViewNames)
		m["deny_artifact_paths_count"] = len(r.Overlay.DenyArtifactPaths)
		m["deny_branch_names_count"] = len(r.Overlay.DenyBranchNames)
		if n, ok := r.Overlay.EffectiveMaxResultBytes(); ok {
			m["max_result_bytes"] = n
		}
		if n, ok := r.Overlay.EffectiveMaxToolsPerMinute(); ok {
			m["max_tools_per_minute"] = n
		}
		if n, ok := r.Overlay.EffectiveMaxToolsBurst(); ok {
			m["max_tools_burst"] = n
		}
	}
	if r.BundleSeq > 0 {
		m["bundle_seq"] = r.BundleSeq
	}
	if r.KeyID != "" {
		m["key_id"] = r.KeyID
	}
	if r.ContentHash != "" {
		m["content_hash"] = r.ContentHash
	}
	return m
}

// EffectivePolicyExplain is a secret-free explanation of loaded policy for CLI
// show-effective (MGR-001). Never includes signature bytes or key material.
type EffectivePolicyExplain struct {
	ProfileID              string         `json:"profile_id,omitempty"`
	PolicyPresent          bool           `json:"policy_present"`
	PolicyPathBase         string         `json:"policy_path_base,omitempty"`
	SignatureState         string         `json:"signature_state"`
	ForceReadOnly          bool           `json:"force_read_only"`
	FleetTelemetryForceOff bool           `json:"fleet_telemetry_force_off"`
	Mode                   string         `json:"mode,omitempty"`
	DenyTools              []string       `json:"deny_tools,omitempty"`
	DenyJobPrefixes        []string       `json:"deny_job_prefixes,omitempty"`
	DenyNodeNames          []string       `json:"deny_node_names,omitempty"`
	DenyViewNames          []string       `json:"deny_view_names,omitempty"`
	DenyArtifactPaths      []string       `json:"deny_artifact_paths,omitempty"`
	DenyBranchNames        []string       `json:"deny_branch_names,omitempty"`
	MaxResultBytes         *int           `json:"max_result_bytes,omitempty"`
	MaxToolsPerMinute      *int           `json:"max_tools_per_minute,omitempty"`
	MaxToolsBurst          *int           `json:"max_tools_burst,omitempty"`
	BundleSeq              int64          `json:"bundle_seq,omitempty"`
	KeyID                  string         `json:"key_id,omitempty"`
	ContentHash            string         `json:"content_hash,omitempty"`
	ReadOnly               map[string]any `json:"read_only,omitempty"`
	Notes                  []string       `json:"notes,omitempty"`
}

// ExplainEffective builds EffectivePolicyExplain from a load result + RO gate inputs.
func ExplainEffective(profileID string, res LoadResult, ro Inputs) EffectivePolicyExplain {
	ex := EffectivePolicyExplain{
		ProfileID:      profileID,
		PolicyPresent:  res.Present,
		PolicyPathBase: sanitizePath(res.Path),
		SignatureState: res.SignatureState,
		BundleSeq:      res.BundleSeq,
		KeyID:          res.KeyID,
		ContentHash:    res.ContentHash,
	}
	if res.Overlay != nil {
		ex.ForceReadOnly = res.Overlay.ForceReadOnly
		ex.FleetTelemetryForceOff = res.Overlay.FleetTelemetryForceOff
		ex.Mode = string(res.Overlay.NormalizeMode())
		if len(res.Overlay.DenyTools) > 0 {
			ex.DenyTools = append([]string(nil), res.Overlay.DenyTools...)
		}
		if len(res.Overlay.DenyJobPrefixes) > 0 {
			ex.DenyJobPrefixes = append([]string(nil), res.Overlay.DenyJobPrefixes...)
		}
		if len(res.Overlay.DenyNodeNames) > 0 {
			ex.DenyNodeNames = append([]string(nil), res.Overlay.DenyNodeNames...)
		}
		if len(res.Overlay.DenyViewNames) > 0 {
			ex.DenyViewNames = append([]string(nil), res.Overlay.DenyViewNames...)
		}
		if len(res.Overlay.DenyArtifactPaths) > 0 {
			ex.DenyArtifactPaths = append([]string(nil), res.Overlay.DenyArtifactPaths...)
		}
		if len(res.Overlay.DenyBranchNames) > 0 {
			ex.DenyBranchNames = append([]string(nil), res.Overlay.DenyBranchNames...)
		}
		if n, ok := res.Overlay.EffectiveMaxResultBytes(); ok {
			ex.MaxResultBytes = &n
		}
		if n, ok := res.Overlay.EffectiveMaxToolsPerMinute(); ok {
			ex.MaxToolsPerMinute = &n
		}
		if n, ok := res.Overlay.EffectiveMaxToolsBurst(); ok {
			ex.MaxToolsBurst = &n
		}
	}
	st := ComputeEffectiveReadOnly(ro)
	ex.ReadOnly = map[string]any{
		"effective": st.Effective,
		"sources":   st.Sources,
	}
	switch res.SignatureState {
	case SigStateUnverifiedPilot:
		ex.Notes = append(ex.Notes, "pilot: unsigned overlay accepted; configure trusted keys for production")
	case SigStateVerified:
		ex.Notes = append(ex.Notes, "signed enterprise policy bundle verified")
	case SigStateAbsent:
		ex.Notes = append(ex.Notes, "no enterprise policy file loaded")
	}
	return ex
}
