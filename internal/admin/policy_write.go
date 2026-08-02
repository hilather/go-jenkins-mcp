package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// MaxPolicyDraftBytes caps validate/apply request bodies (fail closed).
const MaxPolicyDraftBytes = 256 << 10 // 256 KiB

// Policy field error (validate/apply). Secret-free only.
type PolicyFieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// OverlayGetResponse is GET /admin/v1/policy/overlay (UI-004).
// Never includes private keys, PEM, or envelope signature material.
type OverlayGetResponse struct {
	Available      bool            `json:"available"`
	PathBase       string          `json:"path_base,omitempty"`
	SignatureState string          `json:"signature_state,omitempty"`
	Overlay        *policy.Overlay `json:"overlay,omitempty"`
	Notes          []string        `json:"notes,omitempty"`
	Residual       string          `json:"residual,omitempty"`
}

// PolicyValidateRequest is the body for POST /admin/v1/policy/validate|apply.
// Draft is a pilot overlay document (version 1). Signature field is ignored.
type PolicyValidateRequest struct {
	// Overlay is the draft overlay (preferred).
	Overlay *policy.Overlay `json:"overlay,omitempty"`
	// ProfileID is optional (audit correlation only).
	ProfileID string `json:"profileId,omitempty"`
}

// PolicyValidateResponse is POST /admin/v1/policy/validate.
type PolicyValidateResponse struct {
	Valid            bool                           `json:"valid"`
	Errors           []PolicyFieldError             `json:"errors,omitempty"`
	EffectivePreview *policy.EffectivePolicyExplain `json:"effectivePreview,omitempty"`
	Notes            []string                       `json:"notes,omitempty"`
}

// PolicyApplyResponse is POST /admin/v1/policy/apply.
type PolicyApplyResponse struct {
	Applied   bool                           `json:"applied"`
	PathBase  string                         `json:"path_base,omitempty"`
	Effective *policy.EffectivePolicyExplain `json:"effective,omitempty"`
	Errors    []PolicyFieldError             `json:"errors,omitempty"`
	Notes     []string                       `json:"notes,omitempty"`
}

// handlePolicyOverlayGET returns the current plain pilot overlay if present.
// Signed bundles are not returned as editable documents (residual honesty).
func (s *server) handlePolicyOverlayGET(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	// Read is covered by PermRead (all authenticated roles).
	if !CheckPermission(w, r, PermRead) {
		return
	}
	paths, err := s.resolvePaths()
	if err != nil {
		writeAppErr(w, err)
		return
	}
	resp, err := loadPlainOverlayDocument(paths)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handlePolicyValidate validates a draft overlay (dry-run) without writing.
func (s *server) handlePolicyValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermPolicyWrite) {
		return
	}
	draft, profileID, err := decodePolicyDraft(r)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	paths, err := s.resolvePaths()
	if err != nil {
		writeAppErr(w, err)
		return
	}
	result := s.validateDraftOverlay(paths, draft, profileID)
	if !result.Valid {
		// Best-effort audit for validate deny (widening attempts, etc.).
		s.emitPolicyAudit(r.Context(), profileID, audit.TypePolicyValidate, audit.DecisionDeny,
			firstReason(result.Errors), nil)
	}
	writeJSON(w, http.StatusOK, result)
}

// handlePolicyApply validates and writes a plain pilot overlay (mode 0600).
// Does not sign. Refuses when require-signed / POLICY_REQUIRED mode is active.
func (s *server) handlePolicyApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermPolicyWrite) {
		return
	}
	draft, profileID, err := decodePolicyDraft(r)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	paths, err := s.resolvePaths()
	if err != nil {
		writeAppErr(w, err)
		return
	}

	// Fail closed: no plain write when signed policy is required.
	if blocked, msg := plainApplyBlocked(paths); blocked {
		s.emitPolicyAudit(r.Context(), profileID, audit.TypePolicyApply, audit.DecisionDeny,
			"require_signed", nil)
		writeJSON(w, http.StatusForbidden, PolicyApplyResponse{
			Applied: false,
			Errors: []PolicyFieldError{{
				Field:   "overlay",
				Message: msg,
			}},
			Notes: []string{msg},
		})
		return
	}

	// Re-validate with the same rules as validate (no partial apply).
	v := s.validateDraftOverlay(paths, draft, profileID)
	if !v.Valid {
		s.emitPolicyAudit(r.Context(), profileID, audit.TypePolicyApply, audit.DecisionDeny,
			firstReason(v.Errors), nil)
		writeJSON(w, http.StatusBadRequest, PolicyApplyResponse{
			Applied: false,
			Errors:  v.Errors,
			Notes:   v.Notes,
		})
		return
	}

	// Write plain overlay only to DefaultPolicyFile (never overwrite signed bundle path).
	outPath := paths.DefaultPolicyFile()
	// If JENKINS_MCP_POLICY_FILE points at a plain path, honor it when not a bundle.
	if envPath := strings.TrimSpace(os.Getenv(policy.EnvPolicyFileVar)); envPath != "" {
		if st, stErr := os.Stat(envPath); stErr == nil && !st.IsDir() {
			raw, rerr := os.ReadFile(envPath)
			if rerr == nil && policy.LooksLikeBundle(raw) {
				msg := "JENKINS_MCP_POLICY_FILE points at a signed bundle; browser apply refused (use CLI policy sign on host)"
				s.emitPolicyAudit(r.Context(), profileID, audit.TypePolicyApply, audit.DecisionDeny,
					"signed_bundle_path", nil)
				writeJSON(w, http.StatusForbidden, PolicyApplyResponse{
					Applied: false,
					Errors:  []PolicyFieldError{{Field: "overlay", Message: msg}},
					Notes:   []string{msg},
				})
				return
			}
		}
		// Env override for plain overlay target.
		if !strings.HasSuffix(strings.ToLower(envPath), ".bundle.json") {
			outPath = envPath
		}
	}

	if err := writePlainOverlayFile(outPath, draft); err != nil {
		s.emitPolicyAudit(r.Context(), profileID, audit.TypePolicyApply, audit.DecisionDeny,
			"write_failed", nil)
		writeAppErr(w, err)
		return
	}

	// Build applied effective summary from written draft (secret-free).
	ex := explainDraft(profileID, draft, paths, outPath)
	s.emitPolicyAudit(r.Context(), profileID, audit.TypePolicyApply, audit.DecisionSuccess,
		"applied", map[string]string{
			"path_base":                 filepath.Base(outPath),
			"force_read_only":           fmt.Sprintf("%v", draft.ForceReadOnly),
			"fleet_telemetry_force_off": fmt.Sprintf("%v", draft.FleetTelemetryForceOff),
			"deny_tools_count":          fmt.Sprintf("%d", len(draft.DenyTools)),
		})
	writeJSON(w, http.StatusOK, PolicyApplyResponse{
		Applied:   true,
		PathBase:  filepath.Base(outPath),
		Effective: &ex,
		Notes: []string{
			"plain pilot overlay written (mode 0600); signing remains host-side CLI only",
		},
	})
}

// decodePolicyDraft reads and bounds the request body into a draft Overlay.
func decodePolicyDraft(r *http.Request) (*policy.Overlay, string, error) {
	if r == nil || r.Body == nil {
		return nil, "", apperr.New(apperr.CodeInvalidArgument, "request body is required")
	}
	limited := io.LimitReader(r.Body, MaxPolicyDraftBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, "", apperr.Wrap(apperr.CodeInvalidArgument, "read policy draft", err)
	}
	if len(raw) > MaxPolicyDraftBytes {
		return nil, "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("policy draft exceeds %d bytes", MaxPolicyDraftBytes))
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, "", apperr.New(apperr.CodeInvalidArgument, "request body is empty")
	}

	// Accept either { "overlay": {...} } or a bare Overlay document.
	var wrap PolicyValidateRequest
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, "", apperr.Wrap(apperr.CodeInvalidArgument, "policy draft JSON invalid", err)
	}
	var draft *policy.Overlay
	if wrap.Overlay != nil {
		draft = wrap.Overlay
	} else {
		// Bare overlay: try unmarshal root as Overlay when version present.
		var bare policy.Overlay
		if err := json.Unmarshal(raw, &bare); err != nil {
			return nil, "", apperr.Wrap(apperr.CodeInvalidArgument, "policy draft JSON invalid", err)
		}
		if bare.Version == 0 && wrap.ProfileID == "" {
			return nil, "", apperr.New(apperr.CodeInvalidArgument,
				"policy draft must include overlay object or bare overlay with version")
		}
		if bare.Version != 0 {
			draft = &bare
		}
	}
	if draft == nil {
		return nil, "", apperr.New(apperr.CodeInvalidArgument, "overlay field is required")
	}
	// Never accept or persist signature material from the browser.
	draft.Signature = ""
	profileID := strings.TrimSpace(wrap.ProfileID)
	return draft, profileID, nil
}

// validateDraftOverlay runs structural + monotonic-restrict checks.
func (s *server) validateDraftOverlay(paths config.Paths, draft *policy.Overlay, profileID string) PolicyValidateResponse {
	resp := PolicyValidateResponse{Valid: true}
	if draft == nil {
		return PolicyValidateResponse{
			Valid:  false,
			Errors: []PolicyFieldError{{Field: "overlay", Message: "overlay is required"}},
		}
	}
	// Strip any client-supplied signature before validation.
	draft.Signature = ""

	if err := draft.Validate(); err != nil {
		resp.Valid = false
		resp.Errors = append(resp.Errors, fieldErrorsFromValidate(err)...)
		return resp
	}

	// Load current baseline (plain or signed content) for monotonic restrict.
	current, currentForce, notes, loadErr := loadCurrentPolicyBaseline(paths)
	if loadErr != nil {
		// Fail closed on unreadable present policy (do not apply over corruption).
		resp.Valid = false
		resp.Errors = append(resp.Errors, PolicyFieldError{
			Field:   "overlay",
			Message: apperr.ModelMessage(loadErr),
		})
		return resp
	}
	resp.Notes = append(resp.Notes, notes...)

	// Monotonic restrict: force RO + deny-list supersets (UI-003/004).
	// CanWidenForceReadOnly is always false for every admin role.
	restrictErrs := checkMonotonicRestrict(current, draft, currentForce)
	if len(restrictErrs) > 0 {
		resp.Valid = false
		resp.Errors = append(resp.Errors, restrictErrs...)
		return resp
	}

	ex := explainDraft(profileID, draft, paths, paths.DefaultPolicyFile())
	resp.EffectivePreview = &ex
	return resp
}

// checkMonotonicRestrict ensures draft does not widen access relative to current.
//
// v1 rules (documented residual for multi-source merge complexity):
//   - When current effective force_read_only is true, draft must keep force_read_only=true.
//   - When current fleet_telemetry_force_off is true, draft must keep it true
//     (MGR-002; admin cannot re-enable fleet telemetry against enterprise pin).
//   - When a current overlay exists, each deny list on the draft must be a set
//     superset of the corresponding current list (entries may only grow).
//   - When current mode is strict, draft must remain strict (pilot would widen).
//   - When current max_result_bytes is set, draft may only lower or keep the cap
//     (nil draft cap would remove the enterprise-style bound — reject).
//   - When current max_tools_per_minute / max_tools_burst is set, draft may only
//     lower or keep (HOST-006; LowerRate never raises live rate; write path must
//     not widen the overlay-enforced cap either).
func checkMonotonicRestrict(current *policy.Overlay, draft *policy.Overlay, currentForceEffective bool) []PolicyFieldError {
	var errs []PolicyFieldError
	if draft == nil {
		return []PolicyFieldError{{Field: "overlay", Message: "overlay is required"}}
	}

	forceOn := currentForceEffective
	if current != nil && current.ForceReadOnly {
		forceOn = true
	}
	// Admin never defeats enterprise force RO (CanWidenForceReadOnly always false).
	if forceOn && !draft.ForceReadOnly && !CanWidenForceReadOnly(RolePolicyAdmin) {
		errs = append(errs, PolicyFieldError{
			Field:   "force_read_only",
			Message: "cannot set force_read_only=false when enterprise/current force is enforced (admin cannot widen force RO)",
		})
	}

	if current == nil {
		return errs
	}

	// MGR-002: fleet_telemetry_force_off is lower-only (true pin cannot be cleared
	// via admin pilot apply — same fail-closed posture as force_read_only).
	if current.FleetTelemetryForceOff && !draft.FleetTelemetryForceOff {
		errs = append(errs, PolicyFieldError{
			Field:   "fleet_telemetry_force_off",
			Message: "cannot set fleet_telemetry_force_off=false when current overlay forces fleet telemetry off (admin cannot re-enable against enterprise pin)",
		})
	}

	if current.NormalizeMode() == policy.ModeStrict && draft.NormalizeMode() != policy.ModeStrict {
		errs = append(errs, PolicyFieldError{
			Field:   "mode",
			Message: "cannot weaken mode from strict to pilot",
		})
	}

	// Deny lists: proposed must be superset of current (set-diff: no removals).
	errs = append(errs, denySupersetErrors("deny_tools", current.DenyTools, draft.DenyTools)...)
	errs = append(errs, denySupersetErrors("deny_job_prefixes", current.DenyJobPrefixes, draft.DenyJobPrefixes)...)
	errs = append(errs, denySupersetErrors("deny_node_names", current.DenyNodeNames, draft.DenyNodeNames)...)
	errs = append(errs, denySupersetErrors("deny_view_names", current.DenyViewNames, draft.DenyViewNames)...)
	errs = append(errs, denySupersetErrors("deny_artifact_paths", current.DenyArtifactPaths, draft.DenyArtifactPaths)...)
	errs = append(errs, denySupersetErrors("deny_branch_names", current.DenyBranchNames, draft.DenyBranchNames)...)

	// max_result_bytes: current cap may only stay or lower.
	if curN, ok := current.EffectiveMaxResultBytes(); ok {
		if draft.MaxResultBytes == nil {
			errs = append(errs, PolicyFieldError{
				Field:   "max_result_bytes",
				Message: "cannot clear max_result_bytes when current overlay enforces a cap",
			})
		} else if *draft.MaxResultBytes > curN {
			errs = append(errs, PolicyFieldError{
				Field:   "max_result_bytes",
				Message: fmt.Sprintf("cannot raise max_result_bytes above current cap %d", curN),
			})
		}
	}
	// max_tools_per_minute / max_tools_burst: same monotonic lower-or-keep.
	if curN, ok := current.EffectiveMaxToolsPerMinute(); ok {
		if draft.MaxToolsPerMinute == nil {
			errs = append(errs, PolicyFieldError{
				Field:   "max_tools_per_minute",
				Message: "cannot clear max_tools_per_minute when current overlay enforces a cap",
			})
		} else if *draft.MaxToolsPerMinute > curN {
			errs = append(errs, PolicyFieldError{
				Field:   "max_tools_per_minute",
				Message: fmt.Sprintf("cannot raise max_tools_per_minute above current cap %d", curN),
			})
		}
	}
	if curN, ok := current.EffectiveMaxToolsBurst(); ok {
		if draft.MaxToolsBurst == nil {
			errs = append(errs, PolicyFieldError{
				Field:   "max_tools_burst",
				Message: "cannot clear max_tools_burst when current overlay enforces a cap",
			})
		} else if *draft.MaxToolsBurst > curN {
			errs = append(errs, PolicyFieldError{
				Field:   "max_tools_burst",
				Message: fmt.Sprintf("cannot raise max_tools_burst above current cap %d", curN),
			})
		}
	}
	return errs
}

func denySupersetErrors(field string, current, proposed []string) []PolicyFieldError {
	if len(current) == 0 {
		return nil
	}
	have := make(map[string]struct{}, len(proposed))
	for _, p := range proposed {
		p = strings.TrimSpace(p)
		if p != "" {
			have[p] = struct{}{}
		}
	}
	var missing []string
	for _, c := range current {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, ok := have[c]; !ok {
			missing = append(missing, c)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	// Cap message length; do not dump unbounded lists.
	show := missing
	if len(show) > 5 {
		show = show[:5]
	}
	return []PolicyFieldError{{
		Field: field,
		Message: fmt.Sprintf(
			"deny list must be a superset of current (missing %d entr%s: %s)",
			len(missing), pluralEntry(len(missing)), strings.Join(show, ", ")),
	}}
}

func pluralEntry(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// loadPlainOverlayDocument resolves the policy path and returns a GET response.
func loadPlainOverlayDocument(paths config.Paths) (OverlayGetResponse, error) {
	resp := OverlayGetResponse{Available: false}
	opts := policy.LoadOptions{Paths: &paths, SkipLastGood: true}
	path, err := policy.ResolvePolicyPath(opts)
	if err != nil {
		return resp, err
	}
	resp.PathBase = filepath.Base(path)

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			resp.SignatureState = policy.SigStateAbsent
			resp.Notes = []string{"no enterprise policy file loaded"}
			resp.Residual = "no plain overlay at resolved path; draft editor may create pilot overlay.json"
			return resp, nil
		}
		return resp, apperr.Wrap(apperr.CodePolicyDenial,
			fmt.Sprintf("enterprise policy unreadable at %s", filepath.Base(path)), err)
	}

	if policy.LooksLikeBundle(raw) {
		// Do not return envelope signature / multi-sig material. Residual honesty only.
		resp.SignatureState = "signed_bundle"
		resp.Available = false
		resp.Notes = []string{
			"resolved policy is a signed bundle; browser cannot edit signature material",
			"use host-side CLI (jenkins-mcp policy sign) for signed apply",
		}
		resp.Residual = "signed-bundle apply via browser is out of scope (UI-004 residual)"
		return resp, nil
	}

	var o policy.Overlay
	if err := json.Unmarshal(raw, &o); err != nil {
		return resp, apperr.Wrap(apperr.CodePolicyDenial,
			"enterprise policy overlay is invalid JSON (fail closed)", err)
	}
	// Capture legacy stub presence before stripping (never return the value).
	hadStubSig := strings.TrimSpace(o.Signature) != ""
	// Strip legacy signature stub — never surface signature material to the SPA.
	o.Signature = ""
	if err := o.Validate(); err != nil {
		return resp, apperr.Wrap(apperr.CodePolicyDenial,
			"enterprise policy overlay failed validation (fail closed)", err)
	}
	resp.Available = true
	resp.Overlay = &o
	if hadStubSig {
		resp.SignatureState = policy.SigStatePresentField
	} else {
		resp.SignatureState = policy.SigStateUnverifiedPilot
	}
	resp.Notes = []string{"plain pilot overlay (unsigned); production should use signed bundles"}
	return resp, nil
}

// loadCurrentPolicyBaseline loads the current overlay for monotonic checks.
// Returns current overlay (may be nil), whether force is effectively on, notes, error.
func loadCurrentPolicyBaseline(paths config.Paths) (*policy.Overlay, bool, []string, error) {
	var notes []string
	// Prefer plain overlay at default path for pilot editor baseline.
	plainPath := paths.DefaultPolicyFile()
	if envPath := strings.TrimSpace(os.Getenv(policy.EnvPolicyFileVar)); envPath != "" {
		plainPath = envPath
	}

	raw, err := os.ReadFile(plainPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Also try ResolvePolicyPath (may pick bundle).
			opts := policy.LoadOptions{Paths: &paths, SkipLastGood: true}
			resolved, rerr := policy.ResolvePolicyPath(opts)
			if rerr != nil {
				return nil, false, notes, nil
			}
			raw2, err2 := os.ReadFile(resolved)
			if err2 != nil {
				if os.IsNotExist(err2) {
					return nil, false, notes, nil
				}
				return nil, false, notes, apperr.Wrap(apperr.CodePolicyDenial, "policy unreadable", err2)
			}
			raw = raw2
			plainPath = resolved
		} else {
			return nil, false, notes, apperr.Wrap(apperr.CodePolicyDenial, "policy unreadable", err)
		}
	}

	if policy.LooksLikeBundle(raw) {
		// Extract overlay object only (no signature bytes returned to callers).
		var env struct {
			Overlay policy.Overlay `json:"overlay"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, false, notes, apperr.Wrap(apperr.CodePolicyDenial, "policy bundle JSON invalid", err)
		}
		env.Overlay.Signature = ""
		if err := env.Overlay.Validate(); err != nil {
			return nil, false, notes, apperr.Wrap(apperr.CodePolicyDenial, "policy overlay validation", err)
		}
		notes = append(notes, "baseline is signed bundle overlay content (browser apply still blocked)")
		return &env.Overlay, env.Overlay.ForceReadOnly, notes, nil
	}

	var o policy.Overlay
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, false, notes, apperr.Wrap(apperr.CodePolicyDenial, "policy overlay JSON invalid", err)
	}
	o.Signature = ""
	if err := o.Validate(); err != nil {
		return nil, false, notes, apperr.Wrap(apperr.CodePolicyDenial, "policy overlay validation", err)
	}
	return &o, o.ForceReadOnly, notes, nil
}

// PlainApplyBlocked reports whether plain overlay / bindings write must be refused
// (multi-fleet signed path). Used by BFF and adminops MCP for parity.
//
// Refuses when: POLICY_REQUIRED, REQUIRE_SIGNED_POLICY, trusted public keys are
// configured, or the resolved policy file is a signed bundle.
func PlainApplyBlocked(paths config.Paths) (bool, string) {
	return plainApplyBlocked(paths)
}

// plainApplyBlocked reports whether plain overlay write must be refused.
func plainApplyBlocked(paths config.Paths) (bool, string) {
	// JENKINS_MCP_POLICY_REQUIRED → production-style enforcement.
	if policyRequiredFromEnv() {
		return true, "JENKINS_MCP_POLICY_REQUIRED is set: plain overlay write refused; use CLI policy sign on host"
	}
	// JENKINS_MCP_REQUIRE_SIGNED_POLICY → multi-fleet signed path; no plain SPA write.
	if policy.ParseEnvReadOnly(os.Getenv(policy.EnvRequireSignedPolicyVar)) {
		return true, "JENKINS_MCP_REQUIRE_SIGNED_POLICY is set: plain overlay/bindings write refused; use CLI policy sign on host"
	}
	// Trusted public keys present → signed bundles required for serve.
	keys, err := policy.LoadTrustedKeysFromEnviron(&paths)
	if err == nil && keys != nil && keys.Len() > 0 {
		return true, "trusted policy keys are configured: signed bundles required; use CLI policy sign on host (keys never leave the host)"
	}
	// Existing resolved file is a signed bundle → do not clobber with plain.
	opts := policy.LoadOptions{Paths: &paths, SkipLastGood: true}
	path, err := policy.ResolvePolicyPath(opts)
	if err == nil {
		if raw, rerr := os.ReadFile(path); rerr == nil && policy.LooksLikeBundle(raw) {
			return true, "resolved policy is a signed bundle; plain browser apply refused (CLI sign on host)"
		}
	}
	// Env path pointing at a signed bundle (even if ResolvePolicyPath differs).
	if envPath := strings.TrimSpace(os.Getenv(policy.EnvPolicyFileVar)); envPath != "" {
		if raw, rerr := os.ReadFile(envPath); rerr == nil && policy.LooksLikeBundle(raw) {
			return true, "JENKINS_MCP_POLICY_FILE is a signed bundle; plain overlay write refused (CLI sign on host)"
		}
	}
	return false, ""
}

func policyRequiredFromEnv() bool {
	return policy.ParseEnvReadOnly(os.Getenv(policy.EnvPolicyRequiredVar))
}

// writePlainOverlayFile writes o as JSON with mode 0600 (atomic replace when possible).
func writePlainOverlayFile(path string, o *policy.Overlay) error {
	if o == nil {
		return apperr.New(apperr.CodeInvalidArgument, "overlay is nil")
	}
	o.Signature = ""
	if err := o.Validate(); err != nil {
		return apperr.Wrap(apperr.CodeInvalidArgument, "overlay validation", err)
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return apperr.New(apperr.CodeInvalidArgument, "policy path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "create policy dir", err)
	}
	_ = os.Chmod(dir, 0o700)

	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "marshal overlay", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".overlay-*.tmp")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "create temp overlay", err)
	}
	tmpName := tmp.Name()
	// Ensure cleanup on any failure path.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return apperr.Wrap(apperr.CodeInternal, "write temp overlay", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return apperr.Wrap(apperr.CodeInternal, "chmod temp overlay", err)
	}
	if err := tmp.Close(); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "close temp overlay", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "rename overlay into place", err)
	}
	// Re-assert destination mode (rename may preserve tmp mode; still set 0600).
	_ = os.Chmod(path, 0o600)
	return nil
}

func explainDraft(profileID string, draft *policy.Overlay, paths config.Paths, path string) policy.EffectivePolicyExplain {
	res := policy.LoadResult{
		Overlay:        draft,
		Path:           path,
		Present:        true,
		SignatureState: policy.SigStateUnverifiedPilot,
	}
	if draft != nil {
		res.Present = true
	}
	ro := policy.Inputs{
		Force: policy.AsEnterpriseForce(draft),
	}
	ex := policy.ExplainEffective(profileID, res, ro)
	if ex.PolicyPathBase == "" {
		ex.PolicyPathBase = filepath.Base(path)
	}
	return ex
}

func fieldErrorsFromValidate(err error) []PolicyFieldError {
	if err == nil {
		return nil
	}
	msg := apperr.ModelMessage(err)
	// Strip leading code prefix if present.
	if i := strings.Index(msg, ": "); i >= 0 && i < 32 {
		// keep full message; apperr often prefixes code
	}
	field := "overlay"
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "fleet_telemetry_force_off"):
		field = "fleet_telemetry_force_off"
	case strings.Contains(lower, "force_read_only"):
		field = "force_read_only"
	case strings.Contains(lower, "deny_tools"):
		field = "deny_tools"
	case strings.Contains(lower, "deny_job_prefixes"):
		field = "deny_job_prefixes"
	case strings.Contains(lower, "deny_node_names"):
		field = "deny_node_names"
	case strings.Contains(lower, "deny_view_names"):
		field = "deny_view_names"
	case strings.Contains(lower, "deny_artifact_paths"):
		field = "deny_artifact_paths"
	case strings.Contains(lower, "deny_branch_names"):
		field = "deny_branch_names"
	case strings.Contains(lower, "max_result_bytes"):
		field = "max_result_bytes"
	case strings.Contains(lower, "max_tools_per_minute"):
		field = "max_tools_per_minute"
	case strings.Contains(lower, "max_tools_burst"):
		field = "max_tools_burst"
	case strings.Contains(lower, "mode"):
		field = "mode"
	case strings.Contains(lower, "version"):
		field = "version"
	}
	return []PolicyFieldError{{Field: field, Message: msg}}
}

func firstReason(errs []PolicyFieldError) string {
	if len(errs) == 0 {
		return "invalid"
	}
	f := strings.TrimSpace(errs[0].Field)
	if f == "" {
		return "invalid"
	}
	// Stable machine-ish reason without free-form message dump.
	return "field_" + f
}

// emitPolicyAudit best-effort writes a secret-free audit event for policy ops.
func (s *server) emitPolicyAudit(ctx context.Context, profileID, typ, decision, reason string, _ map[string]string) {
	if s == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		profileID = strings.TrimSpace(s.cfg.ProfileID)
	}
	if profileID == "" {
		// No profile to bind; skip durable write (still no secrets).
		return
	}
	if err := ValidateProfileID(profileID); err != nil {
		return
	}
	paths, err := s.resolvePaths()
	if err != nil {
		return
	}
	// Prefer profile data dir when profile exists.
	var dataOverride string
	if p, err := s.loadProfile(profileID); err == nil && p != nil {
		dataOverride = strings.TrimSpace(p.DataDir)
	}
	auditPath, err := ProfileAuditPath(paths, profileID, dataOverride)
	if err != nil {
		return
	}
	dir := filepath.Dir(auditPath)
	sink, err := audit.NewFile(audit.FileConfig{Dir: dir})
	if err != nil {
		return
	}
	defer func() { _ = sink.Close() }()

	ev := audit.Event{
		Time:       time.Now().UTC(),
		Type:       typ,
		ProfileID:  profileID,
		Action:     "policy",
		Decision:   decision,
		ReasonCode: reason,
	}.Normalize()
	_ = sink.Emit(ctx, ev)
}
