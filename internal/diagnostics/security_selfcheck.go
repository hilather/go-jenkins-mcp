package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/mcpserver"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// Security self-check (QA-005 MVP): offline canaries and control status.
// Does NOT claim an external penetration test is complete.

// SelfCheckStatus is ok | warn | fail | skip | info.
type SelfCheckStatus string

const (
	SelfCheckOK   SelfCheckStatus = "ok"
	SelfCheckWarn SelfCheckStatus = "warn"
	SelfCheckFail SelfCheckStatus = "fail"
	SelfCheckSkip SelfCheckStatus = "skip"
	SelfCheckInfo SelfCheckStatus = "info"
)

// SelfCheckItem is one offline canary or control status row (secret-free).
type SelfCheckItem struct {
	// Name is a stable id (e.g. redaction_canary).
	Name string `json:"name"`
	// Status is ok|warn|fail|skip|info.
	Status SelfCheckStatus `json:"status"`
	// Message is operator-visible and must never contain secrets.
	Message string `json:"message"`
	// Details is optional non-secret structured data.
	Details map[string]any `json:"details,omitempty"`
	// Control maps to the security-review checklist id when applicable.
	Control string `json:"control,omitempty"`
}

// SelfCheckReport is the full security self-check result (QA-005).
type SelfCheckReport struct {
	// Overall is fail if any item failed; warn if any warn and no fail; else ok.
	Overall SelfCheckStatus `json:"overall"`
	// Version/Commit of the binary when provided.
	Version string `json:"version,omitempty"`
	Commit  string `json:"commit,omitempty"`
	// ProfileID when a profile was supplied (optional).
	ProfileID string `json:"profile_id,omitempty"`
	// Items are canary / control checks.
	Items []SelfCheckItem `json:"items"`
	// Residuals document what this self-check does not cover.
	Residuals []string `json:"residuals"`
	// IndependentReviewRequired is always true for MVP self-assessment.
	IndependentReviewRequired bool `json:"independent_review_required"`
	// GeneratedAt is RFC3339 UTC.
	GeneratedAt string `json:"generated_at"`
}

// SelfCheckOptions configures an offline security self-check.
type SelfCheckOptions struct {
	// Profile optional; enables OIDC structural checks when present.
	Profile *profile.Profile
	// Paths optional XDG paths.
	Paths *config.Paths
	// PolicyResult optional preloaded policy load; when nil, LoadFromEnviron.
	PolicyResult *policy.LoadResult
	// Version / Commit for report metadata.
	Version string
	Commit  string
	// Now optional clock.
	Now func() time.Time
	// SkipSupportBundleCanary skips the cheap bundle category plan check.
	SkipSupportBundleCanary bool
	// Getenv optional env reader for gateway Mode B residual (OAUTH-009).
	// nil → os.Getenv (via gatewayModeBResidual).
	Getenv func(string) string
}

// hardMaxResolveCanary is installed by internal/tools init (MCP-001 / Wave 38).
// Registration avoids a diagnostics → tools import cycle (tools already imports
// diagnostics for doctor/diagnose). Nil means tools package not linked.
var hardMaxResolveCanary func() SelfCheckItem

// RegisterHardMaxResolveCanary installs the offline hard-max absolute-cap canary.
// Intended to be called once from tools package init.
func RegisterHardMaxResolveCanary(fn func() SelfCheckItem) {
	hardMaxResolveCanary = fn
}

// operatorCapsCanary is installed by internal/tools init (Wave 43).
// Registration avoids a diagnostics → tools import cycle. Nil means tools not linked.
var operatorCapsCanary func() SelfCheckItem

// RegisterOperatorCapsCanary installs the offline operator caps snapshot item.
// Intended to be called once from tools package init.
func RegisterOperatorCapsCanary(fn func() SelfCheckItem) {
	operatorCapsCanary = fn
}

// securityCanary is a planted secret value used only inside self-check; it must
// never appear in the report output.
const securityCanary = "QA005_SELFCHECK_CANARY_token_must_never_appear_9b2e4f"

// minOfflineFallthroughFixtures is the Wave 33+ OfflineFallthroughFixtures floor
// (empty/HTML/Bearer WWW-Authenticate/authn fail-closed matrix). Shrink is fail.
const minOfflineFallthroughFixtures = 12

// RunSecuritySelfCheck executes offline canaries (QA-005 MVP / Wave 34 expand).
// No network I/O. No keyring secret values are read into the report.
func RunSecuritySelfCheck(ctx context.Context, opts SelfCheckOptions) (SelfCheckReport, error) {
	if err := ctx.Err(); err != nil {
		return SelfCheckReport{}, apperr.Wrap(apperr.CodeCancelled, "security self-check cancelled", err)
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	rep := SelfCheckReport{
		Version:                   opts.Version,
		Commit:                    opts.Commit,
		IndependentReviewRequired: true,
		GeneratedAt:               now().UTC().Format(time.RFC3339),
		Residuals: []string{
			"This is an automated self-assessment, not an independent penetration test (QA-005 residual).",
			"No live Jenkins/OAuth/gateway adversarial exercise is performed offline.",
			"Supply-chain / package signing (PKG-001) and update path residual are out of scope here.",
			"Critical/high findings from external review must be tracked to closure before broad production.",
			"Live jwt-auth-filter / Jenkins RS lab (OAUTH-009) remains residual — offline contracts only here.",
			"HTTP loopback without --http-require-token / JENKINS_MCP_HTTP_REQUIRE_TOKEN / JENKINS_MCP_HTTP_DENY_ANONYMOUS remains open to local processes (KD-008 residual; prefer stdio; deny-anonymous off by default).",
		},
	}
	if opts.Profile != nil {
		rep.ProfileID = string(opts.Profile.ID)
	}

	rep.Items = append(rep.Items, checkRedactionCanary())
	rep.Items = append(rep.Items, checkWriterSplitLineCanary())
	if !opts.SkipSupportBundleCanary {
		rep.Items = append(rep.Items, checkSupportBundleCanary())
	}
	rep.Items = append(rep.Items, checkPolicySignatureMode(opts))
	rep.Items = append(rep.Items, checkOIDCStructural(opts.Profile))
	rep.Items = append(rep.Items, checkRSQualificationResidual(opts.Profile, opts.Getenv))
	rep.Items = append(rep.Items, checkHTTPRequireTokenResidual())
	rep.Items = append(rep.Items, checkHTTPAllowedHostsResidual())
	rep.Items = append(rep.Items, checkTelemetryDefaultOff())
	rep.Items = append(rep.Items, checkReadOnlyDefault())
	rep.Items = append(rep.Items, checkMutationsOptInDefault())
	rep.Items = append(rep.Items, checkOriginPinDocumented())
	rep.Items = append(rep.Items, checkJenkinsOriginPinResidual())
	rep.Items = append(rep.Items, checkHardMaxResolveResidual())
	rep.Items = append(rep.Items, checkOperatorCapsSnapshot())
	rep.Items = append(rep.Items, checkAdapterFrameworkResidual())
	rep.Items = append(rep.Items, checkAdapterAllowlistProvenanceLite())
	rep.Items = append(rep.Items, checkListfilterDenyOnlyResidual())
	rep.Items = append(rep.Items, checkPolicyResourceDenyResidual())
	rep.Items = append(rep.Items, checkPolicyMultisigLiteResidual())
	rep.Items = append(rep.Items, checkJenkinsResilienceResidual())
	rep.Items = append(rep.Items, checkFleetTelemetryForceOffResidual())
	rep.Items = append(rep.Items, checkUpdateLKGResidual())
	rep.Items = append(rep.Items, checkMutationConfirmCooldownResidual())
	rep.Items = append(rep.Items, checkGatewayResidualStatusHonesty(opts.Getenv))

	// Final canary: planted secret must not appear anywhere in serialized report.
	if leak := reportContainsCanary(rep, securityCanary); leak {
		rep.Items = append(rep.Items, SelfCheckItem{
			Name:    "report_canary_leak",
			Status:  SelfCheckFail,
			Message: "internal canary leaked into self-check report (redaction failure)",
			Control: "SEC-002",
		})
	} else {
		rep.Items = append(rep.Items, SelfCheckItem{
			Name:    "report_canary_leak",
			Status:  SelfCheckOK,
			Message: "planted canary absent from self-check report",
			Control: "SEC-002",
		})
	}

	rep.Overall = overallSelfCheck(rep.Items)
	// Sanitize all messages once more.
	for i := range rep.Items {
		rep.Items[i].Message = redact.SanitizeForModel(rep.Items[i].Message)
	}
	return rep, nil
}

func checkRedactionCanary() SelfCheckItem {
	// Plant bearer + basic-ish patterns; ensure redaction removes canary.
	raw := "Authorization: Bearer " + securityCanary + "\npassword=" + securityCanary
	out := redact.RedactText(raw)
	if strings.Contains(out, securityCanary) {
		return SelfCheckItem{
			Name:    "redaction_canary",
			Status:  SelfCheckFail,
			Message: "redaction left canary secret material in output",
			Control: "SEC-002",
		}
	}
	if !strings.Contains(out, redact.Replacement) {
		return SelfCheckItem{
			Name:    "redaction_canary",
			Status:  SelfCheckWarn,
			Message: "redaction ran but no [REDACTED] marker found (pattern coverage residual)",
			Control: "SEC-002",
		}
	}
	return SelfCheckItem{
		Name:    "redaction_canary",
		Status:  SelfCheckOK,
		Message: "redaction canary passed (secret material replaced)",
		Control: "SEC-002",
		Details: map[string]any{"marker": redact.Replacement},
	}
}

// checkWriterSplitLineCanary proves Wave 33/34 line-buffered redact.Writer:
// Authorization Bearer canary split across two Write calls + Flush must never
// appear in the underlying output (line reassembly before RedactText).
func checkWriterSplitLineCanary() SelfCheckItem {
	var buf bytes.Buffer
	w := redact.NewWriter(&buf)
	// Split mid-token so neither chunk alone is a complete Bearer line.
	mid := len(securityCanary) / 2
	if mid < 1 {
		mid = 1
	}
	p1 := []byte("Authorization: Bearer " + securityCanary[:mid])
	p2 := []byte(securityCanary[mid:] + " trailing")
	if n, err := w.Write(p1); err != nil || n != len(p1) {
		return SelfCheckItem{
			Name:    "writer_split_line_canary",
			Status:  SelfCheckFail,
			Message: "redact Writer split Write part1 failed",
			Control: "SEC-002",
		}
	}
	// Incomplete line must not forward yet (no newline).
	if buf.Len() != 0 {
		// Even if forwarded early, must not contain canary — still fail hard on canary.
		if strings.Contains(buf.String(), securityCanary) {
			return SelfCheckItem{
				Name:    "writer_split_line_canary",
				Status:  SelfCheckFail,
				Message: "split-line canary leaked before Flush (Writer line buffer broken)",
				Control: "SEC-002",
			}
		}
		return SelfCheckItem{
			Name:    "writer_split_line_canary",
			Status:  SelfCheckFail,
			Message: "Writer forwarded incomplete line before newline (line buffer residual)",
			Control: "SEC-002",
		}
	}
	if n, err := w.Write(p2); err != nil || n != len(p2) {
		return SelfCheckItem{
			Name:    "writer_split_line_canary",
			Status:  SelfCheckFail,
			Message: "redact Writer split Write part2 failed",
			Control: "SEC-002",
		}
	}
	if err := w.Flush(); err != nil {
		return SelfCheckItem{
			Name:    "writer_split_line_canary",
			Status:  SelfCheckFail,
			Message: "redact Writer Flush failed",
			Control: "SEC-002",
		}
	}
	out := buf.String()
	if strings.Contains(out, securityCanary) {
		return SelfCheckItem{
			Name:    "writer_split_line_canary",
			Status:  SelfCheckFail,
			Message: "split-Write Authorization Bearer canary present after Flush",
			Control: "SEC-002",
		}
	}
	// Partial halves must also be absent once reassembled and redacted.
	if strings.Contains(out, securityCanary[:mid]) || strings.Contains(out, securityCanary[mid:]) {
		return SelfCheckItem{
			Name:    "writer_split_line_canary",
			Status:  SelfCheckFail,
			Message: "split-Write canary fragment present after Flush",
			Control: "SEC-002",
		}
	}
	if !strings.Contains(out, redact.Replacement) {
		return SelfCheckItem{
			Name:    "writer_split_line_canary",
			Status:  SelfCheckWarn,
			Message: "Writer flushed without [REDACTED] marker (pattern coverage residual)",
			Control: "SEC-002",
		}
	}
	return SelfCheckItem{
		Name:    "writer_split_line_canary",
		Status:  SelfCheckOK,
		Message: "Writer line buffer redacted split Authorization Bearer canary (Write+Write+Flush)",
		Control: "SEC-002",
		Details: map[string]any{"marker": redact.Replacement},
	}
}

func checkSupportBundleCanary() SelfCheckItem {
	// Cheap: category plan must exclude secret categories and include scrubbed set.
	included := DefaultBundleCategories()
	excluded := BundleExcludedCategories
	if len(included) == 0 {
		return SelfCheckItem{
			Name:    "support_bundle_canary",
			Status:  SelfCheckFail,
			Message: "support bundle include list empty",
			Control: "OPS-001",
		}
	}
	needExclude := []string{"tokens_or_api_keys", "keyring_material", "authorization_headers", "full_build_logs"}
	exSet := make(map[string]struct{}, len(excluded))
	for _, e := range excluded {
		exSet[e] = struct{}{}
	}
	for _, n := range needExclude {
		if _, ok := exSet[n]; !ok {
			return SelfCheckItem{
				Name:    "support_bundle_canary",
				Status:  SelfCheckFail,
				Message: fmt.Sprintf("support bundle must exclude %q", n),
				Control: "OPS-001",
			}
		}
	}
	// Ensure no include category looks like a secret dump.
	for _, c := range included {
		cl := strings.ToLower(c)
		if strings.Contains(cl, "token") || strings.Contains(cl, "password") || strings.Contains(cl, "keyring") {
			return SelfCheckItem{
				Name:    "support_bundle_canary",
				Status:  SelfCheckFail,
				Message: "include category looks secret-bearing",
				Control: "OPS-001",
			}
		}
	}
	return SelfCheckItem{
		Name:    "support_bundle_canary",
		Status:  SelfCheckOK,
		Message: "support-bundle category plan excludes secrets/logs/keyring",
		Control: "OPS-001",
		Details: map[string]any{
			"included_count": len(included),
			"excluded_count": len(excluded),
		},
	}
}

func checkPolicySignatureMode(opts SelfCheckOptions) SelfCheckItem {
	var res policy.LoadResult
	var err error
	if opts.PolicyResult != nil {
		res = *opts.PolicyResult
	} else {
		res, err = policy.LoadFromEnviron()
		if err != nil {
			// Fail-closed load error is itself a security-relevant signal.
			return SelfCheckItem{
				Name:    "policy_signature_mode",
				Status:  SelfCheckFail,
				Message: "policy load failed closed: " + apperr.ModelMessage(err),
				Control: "MGR-001",
			}
		}
	}
	state := res.SignatureState
	if state == "" {
		state = policy.SigStateAbsent
	}
	item := SelfCheckItem{
		Name:    "policy_signature_mode",
		Control: "MGR-001",
		Details: map[string]any{
			"signature_state": state,
			"present":         res.Present,
		},
	}
	if res.KeyID != "" {
		item.Details["key_id"] = res.KeyID // non-secret id only
	}
	switch state {
	case policy.SigStateVerified:
		item.Status = SelfCheckOK
		item.Message = "policy bundle signature verified (Ed25519)"
	case policy.SigStateUnverifiedPilot, policy.SigStatePresentField:
		item.Status = SelfCheckWarn
		item.Message = "policy signature mode is pilot/unverified; production should use signed bundles + trusted keys"
	case policy.SigStateAbsent:
		item.Status = SelfCheckInfo
		item.Message = "no policy overlay present (builtin RO + optional flags still apply)"
	case policy.SigStateUnsignedRejected:
		item.Status = SelfCheckFail
		item.Message = "unsigned policy rejected"
	default:
		item.Status = SelfCheckWarn
		item.Message = "unknown policy signature state token"
	}
	return item
}

func checkOIDCStructural(p *profile.Profile) SelfCheckItem {
	if p == nil {
		return SelfCheckItem{
			Name:    "oidc_profile_structural",
			Status:  SelfCheckSkip,
			Message: "no profile supplied; skip OIDC structural check",
			Control: "OAUTH-001",
		}
	}
	if p.AuthMethod != profile.AuthMethodOIDC {
		return SelfCheckItem{
			Name:    "oidc_profile_structural",
			Status:  SelfCheckSkip,
			Message: "profile auth method is not oidc_bearer",
			Control: "OAUTH-001",
			Details: map[string]any{"auth_method": string(p.AuthMethod)},
		}
	}
	if err := p.Validate(); err != nil {
		return SelfCheckItem{
			Name:    "oidc_profile_structural",
			Status:  SelfCheckFail,
			Message: "OIDC profile failed structural validation: " + apperr.ModelMessage(err),
			Control: "OAUTH-001",
		}
	}
	if p.OIDC == nil {
		return SelfCheckItem{
			Name:    "oidc_profile_structural",
			Status:  SelfCheckFail,
			Message: "oidc_bearer profile missing OIDC settings",
			Control: "OAUTH-001",
		}
	}
	// Audience / issuer present (values may be logged as non-secret config).
	details := map[string]any{
		"issuer_set":    strings.TrimSpace(p.OIDC.Issuer) != "",
		"audience_set":  strings.TrimSpace(p.OIDC.JenkinsAudience) != "",
		"client_id_set": strings.TrimSpace(p.OIDC.ClientID) != "",
		// Never include raw tokens; profile must not have them.
	}
	return SelfCheckItem{
		Name:    "oidc_profile_structural",
		Status:  SelfCheckOK,
		Message: "OIDC profile structural validation passed (issuer/audience/clientId present; Jenkins-as-AS rejected by Validate)",
		Control: "OAUTH-001",
		Details: details,
	}
}

func checkTelemetryDefaultOff() SelfCheckItem {
	// Ambient process env posture (warn if enabled). ForceOff lite is a separate
	// pure canary (fleet_telemetry_force_off_residual / MGR-002).
	// Default off: only truthy JENKINS_MCP_TELEMETRY enables export.
	v := strings.TrimSpace(strings.ToLower(os.Getenv("JENKINS_MCP_TELEMETRY")))
	enabled := v == "1" || v == "true" || v == "yes" || v == "on"
	if enabled {
		return SelfCheckItem{
			Name:    "telemetry_default_off",
			Status:  SelfCheckWarn,
			Message: "fleet telemetry is ENABLED in this environment (default is off; confirm policy approval)",
			Control: "MGR-002",
			Details: map[string]any{"enabled": true},
		}
	}
	return SelfCheckItem{
		Name:    "telemetry_default_off",
		Status:  SelfCheckOK,
		Message: "fleet telemetry is off by default (JENKINS_MCP_TELEMETRY unset/false)",
		Control: "MGR-002",
		Details: map[string]any{"enabled": false},
	}
}

func checkReadOnlyDefault() SelfCheckItem {
	// Builtin default RO is effective when no allow-mutations and no skip.
	st := policy.ComputeEffectiveReadOnly(policy.Inputs{})
	if !st.Effective {
		return SelfCheckItem{
			Name:    "read_only_default",
			Status:  SelfCheckFail,
			Message: "builtin default read-only is not effective",
			Control: "POL-001",
		}
	}
	// force + allow-mutations still RO
	st2 := policy.ComputeEffectiveReadOnly(policy.Inputs{
		AllowMutations: true,
		Force:          policy.StaticForce{Force: true, Present: true},
	})
	if !st2.Effective {
		return SelfCheckItem{
			Name:    "read_only_default",
			Status:  SelfCheckFail,
			Message: "force_read_only does not defeat allow-mutations",
			Control: "POL-001",
		}
	}
	return SelfCheckItem{
		Name:    "read_only_default",
		Status:  SelfCheckOK,
		Message: "global read-only default effective; enterprise force cannot be defeated by allow-mutations",
		Control: "POL-001",
		Details: map[string]any{"sources": st.Sources},
	}
}

// checkMutationsOptInDefault asserts pilot default Inputs leave AllowMutationsOptIn
// false so mutation tools are not registered by surprise (POL-001 / Wave 30 residual).
func checkMutationsOptInDefault() SelfCheckItem {
	gate := policy.NewReadOnlyGate(policy.Inputs{})
	if gate.AllowMutationsOptIn() {
		return SelfCheckItem{
			Name:    "mutations_opt_in_default",
			Status:  SelfCheckFail,
			Message: "AllowMutationsOptIn true with zero Inputs (surprise mutation registration)",
			Control: "POL-001",
		}
	}
	if gate.ShouldRegisterMutations() {
		return SelfCheckItem{
			Name:    "mutations_opt_in_default",
			Status:  SelfCheckFail,
			Message: "ShouldRegisterMutations true under pilot default RO (mutations would register)",
			Control: "POL-001",
		}
	}
	// Nil gate is fail-closed (no mutations).
	var nilGate *policy.ReadOnlyGate
	if nilGate.AllowMutationsOptIn() || nilGate.ShouldRegisterMutations() {
		return SelfCheckItem{
			Name:    "mutations_opt_in_default",
			Status:  SelfCheckFail,
			Message: "nil ReadOnlyGate does not fail closed for mutation registration",
			Control: "POL-001",
		}
	}
	return SelfCheckItem{
		Name:    "mutations_opt_in_default",
		Status:  SelfCheckOK,
		Message: "AllowMutationsOptIn default false; no surprise mutation tool registration",
		Control: "POL-001",
		Details: map[string]any{
			"allow_mutations_opt_in":    false,
			"mutations_should_register": false,
		},
	}
}

// checkHTTPRequireTokenResidual documents KD-008 control: non-local always
// requires a shared secret (ValidateHTTPConfig pure check); loopback without
// require-token remains residual (pass/warn honesty, not a hard fail).
// Wave 35: non-local also requires AllowedHosts before the token check; the
// empty-token probe supplies hosts so we exercise validateHTTPTokenRequirement.
func checkHTTPRequireTokenResidual() SelfCheckItem {
	// Pure fail-closed: empty token + AllowNonLocal must error.
	// Origins + hosts required first (Wave 16/35); omit either → different errors.
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = "0.0.0.0:8765"
	cfg.AllowNonLocal = true
	cfg.AllowedOrigins = []string{"https://cursor.example"}
	cfg.AllowedHosts = []string{"mcp.example.corp"}
	cfg.BearerToken = "" // empty
	err := mcpserver.ValidateHTTPConfig(cfg)
	if err == nil {
		return SelfCheckItem{
			Name:    "http_require_token_residual",
			Status:  SelfCheckFail,
			Message: "ValidateHTTPConfig accepted AllowNonLocal with empty BearerToken (KD-008 break)",
			Control: "KD-008",
		}
	}
	// Never put token material in the message; only assert error present.
	msg := strings.ToLower(apperr.ModelMessage(err))
	if !strings.Contains(msg, "token") && !strings.Contains(msg, "secret") {
		return SelfCheckItem{
			Name:    "http_require_token_residual",
			Status:  SelfCheckFail,
			Message: "AllowNonLocal empty-token error missing token/secret guidance",
			Control: "KD-008",
			Details: map[string]any{"error_class": "unexpected"},
		}
	}
	// RequireToken alone on loopback also fails closed without secret.
	cfgLoop := mcpserver.DefaultHTTPConfig()
	cfgLoop.Addr = "127.0.0.1:8765"
	cfgLoop.RequireToken = true
	cfgLoop.BearerToken = ""
	if err2 := mcpserver.ValidateHTTPConfig(cfgLoop); err2 == nil {
		return SelfCheckItem{
			Name:    "http_require_token_residual",
			Status:  SelfCheckFail,
			Message: "ValidateHTTPConfig accepted RequireToken with empty BearerToken",
			Control: "KD-008",
		}
	}
	// Loopback default (no RequireToken, empty token) remains allowed — residual.
	cfgCompat := mcpserver.DefaultHTTPConfig()
	cfgCompat.Addr = "127.0.0.1:8765"
	if err3 := mcpserver.ValidateHTTPConfig(cfgCompat); err3 != nil {
		return SelfCheckItem{
			Name:    "http_require_token_residual",
			Status:  SelfCheckFail,
			Message: "loopback default HTTP config unexpectedly rejected",
			Control: "KD-008",
		}
	}
	return SelfCheckItem{
		Name:   "http_require_token_residual",
		Status: SelfCheckWarn, // residual honesty: loopback without require-token still open locally
		// Mention opt-in envs (names only — never secrets). Default remains open for pilot.
		Message: "non-local always requires HTTP shared secret; loopback without --http-require-token / JENKINS_MCP_HTTP_REQUIRE_TOKEN / JENKINS_MCP_HTTP_DENY_ANONYMOUS remains residual (prefer stdio; deny-anonymous off by default)",
		Control: "KD-008",
		Details: map[string]any{
			"non_local_empty_token_rejected": true,
			"require_token_empty_rejected":   true,
			"loopback_optional_token":        true,
			"allowed_hosts_required":         true, // Wave 36: non-local token probe supplies AllowedHosts
			"deny_anonymous_default_off":     true, // Wave 41: opt-in alias of require-token
			"residual":                       "loopback_without_require_token",
		},
	}
}

// checkHTTPAllowedHostsResidual is a KD-008 canary independent of the token
// path: AllowNonLocal + origins + token but empty AllowedHosts must fail closed
// (DNS rebinding defense). Positive: all three present → ValidateHTTPConfig OK.
func checkHTTPAllowedHostsResidual() SelfCheckItem {
	// Missing AllowedHosts while non-local (token + origins present) → fail closed.
	cfgMissing := mcpserver.DefaultHTTPConfig()
	cfgMissing.Addr = "0.0.0.0:8765"
	cfgMissing.AllowNonLocal = true
	cfgMissing.AllowedOrigins = []string{"https://cursor.example"}
	cfgMissing.BearerToken = "selfcheck-not-a-real-secret" // non-empty; never logged
	cfgMissing.AllowedHosts = nil
	err := mcpserver.ValidateHTTPConfig(cfgMissing)
	if err == nil {
		return SelfCheckItem{
			Name:    "http_allowed_hosts_residual",
			Status:  SelfCheckFail,
			Message: "ValidateHTTPConfig accepted AllowNonLocal with empty AllowedHosts (KD-008 host break)",
			Control: "KD-008",
		}
	}
	msg := strings.ToLower(apperr.ModelMessage(err))
	if !strings.Contains(msg, "host") && !strings.Contains(msg, "allowed-host") {
		return SelfCheckItem{
			Name:    "http_allowed_hosts_residual",
			Status:  SelfCheckFail,
			Message: "AllowNonLocal empty-hosts error missing host / allowed-host guidance",
			Control: "KD-008",
			Details: map[string]any{"error_class": "unexpected"},
		}
	}
	// Positive: origins + hosts + token under AllowNonLocal must succeed.
	cfgOK := mcpserver.DefaultHTTPConfig()
	cfgOK.Addr = "0.0.0.0:8765"
	cfgOK.AllowNonLocal = true
	cfgOK.AllowedOrigins = []string{"https://cursor.example"}
	cfgOK.AllowedHosts = []string{"mcp.example.corp"}
	cfgOK.BearerToken = "selfcheck-not-a-real-secret"
	if err2 := mcpserver.ValidateHTTPConfig(cfgOK); err2 != nil {
		return SelfCheckItem{
			Name:    "http_allowed_hosts_residual",
			Status:  SelfCheckFail,
			Message: "ValidateHTTPConfig rejected complete non-local config (origins+hosts+token)",
			Control: "KD-008",
			Details: map[string]any{"error_class": "unexpected"},
		}
	}
	// Never put the probe token in Message/Details.
	return SelfCheckItem{
		Name:    "http_allowed_hosts_residual",
		Status:  SelfCheckOK,
		Message: "AllowNonLocal requires AllowedHosts (fail closed); complete non-local config accepted",
		Control: "KD-008",
		Details: map[string]any{
			"non_local_empty_hosts_rejected": true,
			"non_local_complete_accepted":    true,
		},
	}
}

func checkOriginPinDocumented() SelfCheckItem {
	// NET-004 TLS posture offline canary (diagnostic insecure dual-gated).
	// Pure origin-pin contracts live in checkJenkinsOriginPinResidual (NET-001).
	if strings.TrimSpace(string(os.Getenv("JENKINS_MCP_DIAG_INSECURE_TLS"))) == "1" {
		return SelfCheckItem{
			Name:    "origin_tls_posture",
			Status:  SelfCheckWarn,
			Message: "JENKINS_MCP_DIAG_INSECURE_TLS=1 is set (diagnostic only; never leave enabled)",
			Control: "NET-004",
		}
	}
	return SelfCheckItem{
		Name:    "origin_tls_posture",
		Status:  SelfCheckOK,
		Message: "diagnostic insecure TLS env not set; TLS verify remains default posture",
		Control: "NET-004",
	}
}

// checkHardMaxResolveResidual is Wave 38 / MCP-001: AbsoluteMaxHardMaxBytes
// fail-closed on serve bootstrap resolve. Implementation is registered by
// internal/tools (single source of truth for ResolveHardMaxBytes).
func checkHardMaxResolveResidual() SelfCheckItem {
	if hardMaxResolveCanary == nil {
		return SelfCheckItem{
			Name:    "hard_max_resolve_residual",
			Status:  SelfCheckFail,
			Message: "hard max resolve canary not registered (tools package not linked)",
			Control: "MCP-001",
		}
	}
	return hardMaxResolveCanary()
}

// checkOperatorCapsSnapshot is Wave 43: secret-free integer snapshot of process
// operator caps (live getters when tools is linked). LiveHardMax mid-serve value
// is not available offline without serve; hard-max details use constants only.
func checkOperatorCapsSnapshot() SelfCheckItem {
	if operatorCapsCanary == nil {
		return SelfCheckItem{
			Name:    "operator_caps_snapshot",
			Status:  SelfCheckFail,
			Message: "operator caps snapshot not registered (tools package not linked)",
			Control: "MCP-001",
		}
	}
	return operatorCapsCanary()
}

// checkListfilterDenyOnlyResidual is Wave 39 / POL-004 (+ Wave 40 light polish):
// pure listfilter helpers used by list-row privacy.
// NameDeniedByPatterns is deny-only (empty patterns/name → false).
// Deny*FromEvaluator copy-out documents that list policy filters exist for
// nodes / jobs / views / artifacts / branches (no tools import cycle).
func checkListfilterDenyOnlyResidual() SelfCheckItem {
	// Empty / nil patterns must never deny (deny-only semantics).
	if policy.NameDeniedByPatterns(nil, "secret-view") {
		return SelfCheckItem{
			Name:    "listfilter_deny_only_residual",
			Status:  SelfCheckFail,
			Message: "NameDeniedByPatterns denied with nil patterns (must be deny-only empty→false)",
			Control: "POL-004",
		}
	}
	if policy.NameDeniedByPatterns([]string{}, "secret-view") {
		return SelfCheckItem{
			Name:    "listfilter_deny_only_residual",
			Status:  SelfCheckFail,
			Message: "NameDeniedByPatterns denied with empty patterns (must be deny-only empty→false)",
			Control: "POL-004",
		}
	}
	if policy.NameDeniedByPatterns([]string{"secret-view"}, "") {
		return SelfCheckItem{
			Name:    "listfilter_deny_only_residual",
			Status:  SelfCheckFail,
			Message: "NameDeniedByPatterns denied empty name (must be deny-only empty→false)",
			Control: "POL-004",
		}
	}
	// Positive: a real pattern match still works (structural presence of matcher).
	if !policy.NameDeniedByPatterns([]string{"secret-view", "hr/**"}, "secret-view") {
		return SelfCheckItem{
			Name:    "listfilter_deny_only_residual",
			Status:  SelfCheckFail,
			Message: "NameDeniedByPatterns missed exact deny match for secret-view",
			Control: "POL-004",
		}
	}
	if policy.NameDeniedByPatterns([]string{"secret-view"}, "public-view") {
		return SelfCheckItem{
			Name:    "listfilter_deny_only_residual",
			Status:  SelfCheckFail,
			Message: "NameDeniedByPatterns denied non-matching name (false positive)",
			Control: "POL-004",
		}
	}

	// All list-row Deny*FromEvaluator helpers: nil / AllowAll / empty document → nil.
	type fromEval struct {
		name string
		fn   func(policy.PolicyEvaluator) []string
	}
	helpers := []fromEval{
		{"DenyNodeNamesFromEvaluator", policy.DenyNodeNamesFromEvaluator},
		{"DenyJobPrefixesFromEvaluator", policy.DenyJobPrefixesFromEvaluator},
		{"DenyViewNamesFromEvaluator", policy.DenyViewNamesFromEvaluator},
		{"DenyArtifactPathsFromEvaluator", policy.DenyArtifactPathsFromEvaluator},
		{"DenyBranchNamesFromEvaluator", policy.DenyBranchNamesFromEvaluator},
	}
	for _, h := range helpers {
		if got := h.fn(nil); got != nil {
			return SelfCheckItem{
				Name:    "listfilter_deny_only_residual",
				Status:  SelfCheckFail,
				Message: h.name + "(nil) must return nil",
				Control: "POL-004",
			}
		}
		if got := h.fn(policy.AllowAllEvaluator{}); got != nil {
			return SelfCheckItem{
				Name:    "listfilter_deny_only_residual",
				Status:  SelfCheckFail,
				Message: h.name + "(AllowAll) must return nil",
				Control: "POL-004",
			}
		}
	}
	emptyEv := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	for _, h := range helpers {
		if got := h.fn(emptyEv); got != nil {
			return SelfCheckItem{
				Name:    "listfilter_deny_only_residual",
				Status:  SelfCheckFail,
				Message: h.name + "(empty document) must return nil",
				Control: "POL-004",
			}
		}
	}

	// Live patterns: copy-out present for each list surface; slices independent of Document.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyNodeNames:     []string{"prod-agent-*"},
		DenyJobPrefixes:   []string{"secret-folder"},
		DenyViewNames:     []string{"secret-view", "hr/**"},
		DenyArtifactPaths: []string{"secrets/**"},
		DenyBranchNames:   []string{"release/*"},
	})
	// Views: multi-entry + mutation independence (regression for Wave 38 list_views).
	gotViews := policy.DenyViewNamesFromEvaluator(ev)
	if len(gotViews) != 2 || gotViews[0] != "secret-view" {
		return SelfCheckItem{
			Name:    "listfilter_deny_only_residual",
			Status:  SelfCheckFail,
			Message: "DenyViewNamesFromEvaluator must return live deny_view_names copy",
			Control: "POL-004",
		}
	}
	gotViews[0] = "mutated"
	if again := policy.DenyViewNamesFromEvaluator(ev); again[0] != "secret-view" {
		return SelfCheckItem{
			Name:    "listfilter_deny_only_residual",
			Status:  SelfCheckFail,
			Message: "DenyViewNamesFromEvaluator returned non-copy slice (Document mutated)",
			Control: "POL-004",
		}
	}
	// Structural presence of the other list-filter copy-outs (nodes/jobs/artifacts/branches).
	if got := policy.DenyNodeNamesFromEvaluator(ev); len(got) != 1 || got[0] != "prod-agent-*" {
		return SelfCheckItem{
			Name:    "listfilter_deny_only_residual",
			Status:  SelfCheckFail,
			Message: "DenyNodeNamesFromEvaluator must return live deny_node_names copy",
			Control: "POL-004",
		}
	}
	if got := policy.DenyJobPrefixesFromEvaluator(ev); len(got) != 1 || got[0] != "secret-folder" {
		return SelfCheckItem{
			Name:    "listfilter_deny_only_residual",
			Status:  SelfCheckFail,
			Message: "DenyJobPrefixesFromEvaluator must return live deny_job_prefixes copy",
			Control: "POL-004",
		}
	}
	if got := policy.DenyArtifactPathsFromEvaluator(ev); len(got) != 1 || got[0] != "secrets/**" {
		return SelfCheckItem{
			Name:    "listfilter_deny_only_residual",
			Status:  SelfCheckFail,
			Message: "DenyArtifactPathsFromEvaluator must return live deny_artifact_paths copy",
			Control: "POL-004",
		}
	}
	if got := policy.DenyBranchNamesFromEvaluator(ev); len(got) != 1 || got[0] != "release/*" {
		return SelfCheckItem{
			Name:    "listfilter_deny_only_residual",
			Status:  SelfCheckFail,
			Message: "DenyBranchNamesFromEvaluator must return live deny_branch_names copy",
			Control: "POL-004",
		}
	}

	return SelfCheckItem{
		Name:    "listfilter_deny_only_residual",
		Status:  SelfCheckOK,
		Message: "listfilter helpers present: NameDeniedByPatterns deny-only; Deny*FromEvaluator for nodes/jobs/views/artifacts/branches",
		Control: "POL-004",
		Details: map[string]any{
			"empty_patterns_deny_nothing":     true,
			"empty_name_deny_nothing":         true,
			"exact_match_denies":              true,
			"non_match_allows":                true,
			"nil_evaluator_nil_patterns":      true,
			"view_patterns_copy_out":          true,
			"node_patterns_copy_out":          true,
			"job_prefix_patterns_copy_out":    true,
			"artifact_path_patterns_copy_out": true,
			"branch_patterns_copy_out":        true,
			// Surfaces that use list-row privacy (documentation only; pure policy check).
			"list_filters_nodes_jobs_views_artifacts": true,
		},
	}
}

// checkPolicyResourceDenyResidual is Wave 39 / POL-004: DocumentFromOverlay copies
// resource deny lists (deny_view_names / deny_artifact_paths / deny_branch_names)
// without elevating. Nil/empty overlay → pilot document with no denials.
// Pure policy package; no secrets, no network.
func checkPolicyResourceDenyResidual() SelfCheckItem {
	// Empty overlay round-trip: no resource denials, pilot mode, never elevates.
	emptyDoc := policy.DocumentFromOverlay(nil)
	if emptyDoc.Mode != policy.ModePilot {
		return SelfCheckItem{
			Name:    "policy_resource_deny_residual",
			Status:  SelfCheckFail,
			Message: "DocumentFromOverlay(nil) must be pilot mode",
			Control: "POL-004",
		}
	}
	if len(emptyDoc.DenyViewNames) != 0 || len(emptyDoc.DenyArtifactPaths) != 0 ||
		len(emptyDoc.DenyBranchNames) != 0 || len(emptyDoc.DenyNodeNames) != 0 ||
		len(emptyDoc.DenyJobPrefixes) != 0 || emptyDoc.DenyTools != nil {
		return SelfCheckItem{
			Name:    "policy_resource_deny_residual",
			Status:  SelfCheckFail,
			Message: "DocumentFromOverlay(nil) must not invent deny lists (deny-only empty)",
			Control: "POL-004",
		}
	}

	// Non-empty overlay: resource deny fields copy into Document (no elevation API).
	o := &policy.Overlay{
		Version:           1,
		Mode:              policy.ModePilot,
		DenyViewNames:     []string{"secret-view"},
		DenyArtifactPaths: []string{"secrets/**"},
		DenyBranchNames:   []string{"release/*"},
		DenyNodeNames:     []string{"prod-agent-*"},
	}
	doc := policy.DocumentFromOverlay(o)
	if len(doc.DenyViewNames) != 1 || doc.DenyViewNames[0] != "secret-view" {
		return SelfCheckItem{
			Name:    "policy_resource_deny_residual",
			Status:  SelfCheckFail,
			Message: "DocumentFromOverlay did not copy deny_view_names",
			Control: "POL-004",
		}
	}
	if len(doc.DenyArtifactPaths) != 1 || doc.DenyArtifactPaths[0] != "secrets/**" {
		return SelfCheckItem{
			Name:    "policy_resource_deny_residual",
			Status:  SelfCheckFail,
			Message: "DocumentFromOverlay did not copy deny_artifact_paths",
			Control: "POL-004",
		}
	}
	if len(doc.DenyBranchNames) != 1 || doc.DenyBranchNames[0] != "release/*" {
		return SelfCheckItem{
			Name:    "policy_resource_deny_residual",
			Status:  SelfCheckFail,
			Message: "DocumentFromOverlay did not copy deny_branch_names",
			Control: "POL-004",
		}
	}
	if len(doc.DenyNodeNames) != 1 || doc.DenyNodeNames[0] != "prod-agent-*" {
		return SelfCheckItem{
			Name:    "policy_resource_deny_residual",
			Status:  SelfCheckFail,
			Message: "DocumentFromOverlay did not copy deny_node_names",
			Control: "POL-004",
		}
	}
	// Document is deny-only: no grant/AllowTools path; empty deny_tools must stay nil.
	if doc.DenyTools != nil {
		return SelfCheckItem{
			Name:    "policy_resource_deny_residual",
			Status:  SelfCheckFail,
			Message: "DocumentFromOverlay invented DenyTools without overlay deny_tools (elevation risk)",
			Control: "POL-004",
		}
	}

	return SelfCheckItem{
		Name:    "policy_resource_deny_residual",
		Status:  SelfCheckOK,
		Message: "DocumentFromOverlay copies deny_view/artifact/branch/node without elevating; empty overlay ok",
		Control: "POL-004",
		Details: map[string]any{
			"empty_overlay_no_denials":   true,
			"deny_view_names_copied":     true,
			"deny_artifact_paths_copied": true,
			"deny_branch_names_copied":   true,
			"deny_node_names_copied":     true,
			"no_grant_elevation":         true,
		},
	}
}

// checkRSQualificationResidual reports OAUTH-009 offline RS matrix + live-lab residual
// (secret-free). Never claims production go for jwt-auth-filter without lab evidence.
// Wave 34: requires OfflineFallthroughFixtures count ≥ floor and live_lab_still_required.
func checkRSQualificationResidual(p *profile.Profile, getenv func(string) string) SelfCheckItem {
	method := ""
	if p != nil {
		method = string(p.AuthMethod)
	}
	sum := auth.BuildOfflineRSQualificationSummary(method)
	fixtureN := sum.FallthroughFixtureCount
	if fixtureN == 0 {
		// Defense in depth if summary field regresses: count fixtures directly.
		fixtureN = len(auth.OfflineFallthroughFixtures())
	}
	modeB, modeResidual := gatewayModeBResidual(getenv)
	details := map[string]any{
		"fallthrough_must_deny":       sum.FallthroughMustDeny,
		"jwks_outage_behavior":        sum.JWKSOutageBehavior,
		"jwks_outage_acceptable":      sum.JWKSOutageAcceptable,
		"required_route_count":        sum.RequiredRouteCount,
		"outside_api_glob_count":      sum.OutsideAPIGlobCount,
		"inventory_ok":                sum.InventoryOK,
		"threats_contract_tested":     sum.ThreatsContractTested,
		"threats_residual_lab":        sum.ThreatsResidualLab,
		"fallthrough_fixture_count":   fixtureN,
		"min_fallthrough_fixtures":    minOfflineFallthroughFixtures,
		"classifier_matrix_done_star": sum.ClassifierMatrixDoneStar,
		"live_lab_still_required":     sum.LiveLabStillRequired,
		"offline_automated":           sum.OfflineAutomated,
		"live_lab_residuals":          sum.LiveLabResiduals,
		"doc":                         sum.Doc,
		// Note: detail keys must not contain "token" (SanitizeCheck drops them).
		"id_jwt_never_api_credential": true,
		"gateway_mode_b_enabled":      modeB,
	}
	if method != "" {
		details["auth_method"] = method
	}
	if modeB {
		details["gateway_mode_matrix_residual"] = modeResidual
		details["mode_b_live_rs_qualified"] = false
		// residual_id oauth009_offline links REL lite / pilot checklist residual.
		details["residual_id"] = "oauth009_offline"
		details["oauth009_offline"] = true
	}

	item := SelfCheckItem{
		Name:    "rs_qualification",
		Control: "OAUTH-009",
		Details: details,
	}

	if !sum.FallthroughMustDeny || !sum.JWKSOutageAcceptable || !sum.InventoryOK {
		item.Status = SelfCheckFail
		item.Message = "RS qualification offline contracts broken (fallthrough/JWKS/inventory)"
		return item
	}
	if fixtureN < minOfflineFallthroughFixtures {
		item.Status = SelfCheckFail
		item.Message = fmt.Sprintf(
			"OfflineFallthroughFixtures count %d below floor %d (matrix regression)",
			fixtureN, minOfflineFallthroughFixtures)
		return item
	}
	if !sum.ClassifierMatrixDoneStar {
		item.Status = SelfCheckFail
		item.Message = "RS classifier matrix Done* flag false while fixtures present"
		return item
	}
	if !sum.LiveLabStillRequired {
		// Honesty guard: offline path must never claim live lab complete.
		item.Status = SelfCheckFail
		item.Message = "live_lab_still_required false offline (must not claim production RS pin)"
		return item
	}

	// Always surface live_lab residual in message/details; oidc_bearer / Mode B elevates warn.
	baseMsg := fmt.Sprintf(
		"RS offline matrix present (%d fixtures ≥%d, %d routes, fallthrough_must_deny); live_lab_still_required residual",
		fixtureN, minOfflineFallthroughFixtures, sum.RequiredRouteCount)

	if method == string(profile.AuthMethodOIDC) {
		item.Status = SelfCheckWarn
		item.Message = baseMsg + "; oidc_bearer needs live jwt-auth-filter lab"
		if modeB {
			item.Message += "; gateway Mode B also residual"
		}
		return item
	}
	if modeB {
		item.Status = SelfCheckWarn
		item.Message = baseMsg + "; gateway Mode B (jwt_rs_bearer) enabled — offline vault not live RS pin (residual_id=oauth009_offline / OAUTH-009)"
		return item
	}

	// Offline contracts ok for non-oidc_bearer; live lab remains residual (details).
	item.Status = SelfCheckOK
	item.Message = baseMsg
	return item
}

func overallSelfCheck(items []SelfCheckItem) SelfCheckStatus {
	var warn bool
	for _, it := range items {
		switch it.Status {
		case SelfCheckFail:
			return SelfCheckFail
		case SelfCheckWarn:
			warn = true
		}
	}
	if warn {
		return SelfCheckWarn
	}
	return SelfCheckOK
}

func reportContainsCanary(rep SelfCheckReport, canary string) bool {
	b, err := json.Marshal(rep)
	if err != nil {
		return false
	}
	return strings.Contains(string(b), canary)
}

// FormatSelfCheckText writes a human-readable report (secret-free).
func FormatSelfCheckText(w interface{ Write([]byte) (int, error) }, rep SelfCheckReport) {
	_, _ = fmt.Fprintf(w, "jenkins-mcp security self-check  overall=%s\n", rep.Overall)
	if rep.Version != "" {
		_, _ = fmt.Fprintf(w, "binary: %s commit=%s\n", rep.Version, rep.Commit)
	}
	if rep.ProfileID != "" {
		_, _ = fmt.Fprintf(w, "profile: %s\n", rep.ProfileID)
	}
	_, _ = fmt.Fprintf(w, "independent_review_required: %v\n", rep.IndependentReviewRequired)
	_, _ = fmt.Fprintln(w, "checks:")
	for _, it := range rep.Items {
		ctrl := ""
		if it.Control != "" {
			ctrl = " [" + it.Control + "]"
		}
		_, _ = fmt.Fprintf(w, "  %-28s %-5s %s%s\n", it.Name, it.Status, it.Message, ctrl)
	}
	if len(rep.Residuals) > 0 {
		_, _ = fmt.Fprintln(w, "residuals:")
		for _, r := range rep.Residuals {
			_, _ = fmt.Fprintf(w, "  - %s\n", r)
		}
	}
	_, _ = fmt.Fprintln(w, "See docs/security/security-review-checklist.md for the full control map.")
}

// FormatSelfCheckJSON writes indented JSON.
func FormatSelfCheckJSON(w interface{ Write([]byte) (int, error) }, rep SelfCheckReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
