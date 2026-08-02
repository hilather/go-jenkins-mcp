package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// BindingsGetResponse is GET /admin/v1/policy/bindings (UI-011).
// Secret-free: binding targets and deny patterns only — never tokens.
type BindingsGetResponse struct {
	Available      bool                  `json:"available"`
	PathBase       string                `json:"path_base,omitempty"`
	SignatureState string                `json:"signature_state,omitempty"`
	Users          []policy.UserBinding  `json:"users,omitempty"`
	Groups         []policy.GroupBinding `json:"groups,omitempty"`
	Notes          []string              `json:"notes,omitempty"`
	Residual       string                `json:"residual,omitempty"`
	// FleetSoT reminds operators multi-fleet SoT is config/signed policy.
	FleetSoT string `json:"fleet_sot,omitempty"`
}

// BindingsPutRequest replaces subjects on the plain pilot overlay (policy_admin).
type BindingsPutRequest struct {
	Users     []policy.UserBinding  `json:"users,omitempty"`
	Groups    []policy.GroupBinding `json:"groups,omitempty"`
	ProfileID string                `json:"profileId,omitempty"`
}

// BindingsPutResponse is PUT /admin/v1/policy/bindings.
type BindingsPutResponse struct {
	Applied  bool                  `json:"applied"`
	PathBase string                `json:"path_base,omitempty"`
	Users    []policy.UserBinding  `json:"users,omitempty"`
	Groups   []policy.GroupBinding `json:"groups,omitempty"`
	Errors   []PolicyFieldError    `json:"errors,omitempty"`
	Notes    []string              `json:"notes,omitempty"`
}

// BindingsPreviewRequest is POST /admin/v1/policy/bindings/preview.
// Subject identity is operator-supplied for **preview only** (not authn).
type BindingsPreviewRequest struct {
	JenkinsUserID   string   `json:"jenkins_user_id,omitempty"`
	ExternalSubject string   `json:"external_subject,omitempty"`
	Groups          []string `json:"groups,omitempty"`
	ToolName        string   `json:"tool_name,omitempty"`
	JobName         string   `json:"job_name,omitempty"`
	ProfileID       string   `json:"profileId,omitempty"`
}

// BindingsPreviewResponse is secret-free evaluate result for a draft identity.
type BindingsPreviewResponse struct {
	Allowed    bool     `json:"allowed"`
	ReasonCode string   `json:"reason_code,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// handlePolicyBindingsGET lists subject bindings from plain overlay (or residual).
func (s *server) handlePolicyBindingsGET(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermRead) {
		return
	}
	paths, err := s.resolvePaths()
	if err != nil {
		writeAppErr(w, err)
		return
	}
	ovResp, err := loadPlainOverlayDocument(paths)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	resp := BindingsGetResponse{
		Available:      ovResp.Available,
		PathBase:       ovResp.PathBase,
		SignatureState: ovResp.SignatureState,
		Notes:          append([]string{}, ovResp.Notes...),
		Residual:       ovResp.Residual,
		FleetSoT:       "configuration/signed policy (MGR-001); SPA is pilot break-glass only",
	}
	if ovResp.Overlay != nil && ovResp.Overlay.Subjects != nil {
		resp.Users = append([]policy.UserBinding(nil), ovResp.Overlay.Subjects.Users...)
		resp.Groups = append([]policy.GroupBinding(nil), ovResp.Overlay.Subjects.Groups...)
	}
	if !resp.Available && resp.Residual == "" {
		resp.Residual = "no plain overlay; create via Policy apply or fleet gitops pack"
	}
	writeJSON(w, http.StatusOK, resp)
}

// handlePolicyBindingsPUT replaces subjects on plain overlay (policy_write).
func (s *server) handlePolicyBindingsPUT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermPolicyWrite) {
		return
	}
	paths, err := s.resolvePaths()
	if err != nil {
		writeAppErr(w, err)
		return
	}
	if blocked, msg := plainApplyBlocked(paths); blocked {
		s.emitPolicyAudit(r.Context(), "", audit.TypePolicyApply, audit.DecisionDeny, "require_signed", nil)
		writeJSON(w, http.StatusForbidden, BindingsPutResponse{
			Applied: false,
			Errors:  []PolicyFieldError{{Field: "bindings", Message: msg}},
			Notes:   []string{msg},
		})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxPolicyDraftBytes+1))
	if err != nil {
		writeAppErr(w, apperr.Wrap(apperr.CodeInvalidArgument, "read bindings body", err))
		return
	}
	if len(body) > MaxPolicyDraftBytes {
		writeAppErr(w, apperr.New(apperr.CodeInvalidArgument, "bindings body too large"))
		return
	}
	var req BindingsPutRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeAppErr(w, apperr.Wrap(apperr.CodeInvalidArgument, "bindings JSON invalid", err))
		return
	}
	subjects := &policy.SubjectBindings{
		Users:  req.Users,
		Groups: req.Groups,
	}
	if err := subjects.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, BindingsPutResponse{
			Applied: false,
			Errors:  []PolicyFieldError{{Field: "subjects", Message: err.Error()}},
		})
		return
	}

	// Load or create plain overlay, then set subjects.
	base, _, notes, err := loadCurrentPolicyBaseline(paths)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	if base == nil {
		base = &policy.Overlay{
			Version:       1,
			Mode:          policy.ModePilot,
			ForceReadOnly: true,
		}
		notes = append(notes, "created pilot overlay shell for bindings")
	}
	// Refuse write when baseline was a signed bundle extract without plain path.
	outPath := paths.DefaultPolicyFile()
	if envPath := strings.TrimSpace(os.Getenv(policy.EnvPolicyFileVar)); envPath != "" {
		if st, stErr := os.Stat(envPath); stErr == nil && !st.IsDir() {
			raw, rerr := os.ReadFile(envPath)
			if rerr == nil && policy.LooksLikeBundle(raw) {
				msg := "signed bundle path active; browser bindings write refused (use host-side signed policy)"
				writeJSON(w, http.StatusForbidden, BindingsPutResponse{
					Applied: false,
					Errors:  []PolicyFieldError{{Field: "bindings", Message: msg}},
					Notes:   []string{msg},
				})
				return
			}
		}
		if !strings.HasSuffix(strings.ToLower(envPath), ".bundle.json") {
			outPath = envPath
		}
	}

	base.Subjects = subjects
	if err := base.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, BindingsPutResponse{
			Applied: false,
			Errors:  []PolicyFieldError{{Field: "overlay", Message: err.Error()}},
		})
		return
	}
	if err := writePlainOverlayFile(outPath, base); err != nil {
		s.emitPolicyAudit(r.Context(), req.ProfileID, audit.TypePolicyApply, audit.DecisionDeny, "write_failed", nil)
		writeAppErr(w, err)
		return
	}
	s.emitPolicyAudit(r.Context(), req.ProfileID, audit.TypePolicyApply, audit.DecisionSuccess, "bindings_applied", map[string]string{
		"path_base":    filepath.Base(outPath),
		"users_count":  fmt.Sprintf("%d", len(subjects.Users)),
		"groups_count": fmt.Sprintf("%d", len(subjects.Groups)),
	})
	writeJSON(w, http.StatusOK, BindingsPutResponse{
		Applied:  true,
		PathBase: filepath.Base(outPath),
		Users:    subjects.Users,
		Groups:   subjects.Groups,
		Notes: append(notes,
			"plain pilot overlay subjects written (mode 0600); multi-fleet SoT remains signed config for production"),
	})
}

// handlePolicyBindingsPreview evaluates deny-only for a hypothetical subject
// against the current loaded overlay (including signed when present).
func (s *server) handlePolicyBindingsPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermRead) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeAppErr(w, apperr.Wrap(apperr.CodeInvalidArgument, "read preview body", err))
		return
	}
	var req BindingsPreviewRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeAppErr(w, apperr.Wrap(apperr.CodeInvalidArgument, "preview JSON invalid", err))
		return
	}
	user := strings.TrimSpace(req.JenkinsUserID)
	if user == "" {
		user = "preview-user"
	}
	pid := strings.TrimSpace(req.ProfileID)
	if pid == "" {
		pid = "preview"
	}
	// policy.NewSubject accepts contracts.ProfileID — construct via string cast in policy package only.
	// Avoid importing contracts here (depgraph allow-list for admin).
	sub := policy.NewSubjectFromString(pid, user, true)
	if ext := strings.TrimSpace(req.ExternalSubject); ext != "" {
		sub = sub.WithExternal(ext)
	}
	if len(req.Groups) > 0 {
		sub = sub.WithGateway("", "", req.Groups)
	}

	// Prefer process LoadFromEnviron when available; else plain overlay.
	var ov *policy.Overlay
	if res, err := policy.LoadFromEnviron(); err == nil && res.Overlay != nil {
		ov = res.Overlay
	} else {
		paths, perr := s.resolvePaths()
		if perr == nil {
			if base, _, _, berr := loadCurrentPolicyBaseline(paths); berr == nil {
				ov = base
			}
		}
	}
	if ov == nil {
		writeJSON(w, http.StatusOK, BindingsPreviewResponse{
			Allowed: true,
			Notes:   []string{"no overlay loaded; deny-only has nothing to attach"},
		})
		return
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	tool := strings.TrimSpace(req.ToolName)
	if tool == "" {
		tool = "jenkins_get_build_logs"
	}
	act := policy.Action{ToolName: tool, Class: policy.EffectRead}
	tgt := policy.Target{JobName: strings.TrimSpace(req.JobName)}
	d := ev.Evaluate(sub, act, tgt)
	writeJSON(w, http.StatusOK, BindingsPreviewResponse{
		Allowed:    d.Allowed(),
		ReasonCode: d.ReasonCode,
		Notes: []string{
			"preview uses current overlay/bundle deny-only evaluator; identity is not process authn",
			"multi-fleet production SoT is signed config — SPA preview is break-glass only",
		},
	})
}
