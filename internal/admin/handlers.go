package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

// healthResponse is GET /admin/v1/health.
// enabledModes is a secret-free HOST-011 listing (mode ids only; no tokens).
// multiUserEnabled / credentialMode / haMultiReplica / gatewayReady / rateEnabled
// are secret-free gateway residual posture (HOST-008); never tokens or subjects.
type healthResponse struct {
	Status       string   `json:"status"`
	Version      string   `json:"version"`
	Commit       string   `json:"commit"`
	UIBuild      string   `json:"uiBuild"`
	EnabledModes []string `json:"enabledModes,omitempty"`
	// CredentialMode is the primary HOST-011 mode id from env (empty if invalid).
	CredentialMode string `json:"credentialMode,omitempty"`
	// MultiUserEnabled is true when JENKINS_MCP_GATEWAY_MULTI_USER is truthy.
	// Not a production multi-user GO pin — foundation residual only.
	MultiUserEnabled bool `json:"multiUserEnabled"`
	// GatewayReady is always false on the admin BFF (separate process from MCP
	// serve; Ready lives on serve GET /readyz). Honest residual.
	GatewayReady bool `json:"gatewayReady"`
	// HAMultiReplica is always false (HOST-008 Tier A single-replica default).
	HAMultiReplica bool `json:"haMultiReplica"`
	// RateEnabled is true when subject rate env would enable HOST-006 limiting
	// (empty JENKINS_MCP_SUBJECT_RATE_PER_MINUTE = default on; 0 = disabled).
	// Process-local residual only — not multi-replica shared rate (HOST-008).
	RateEnabled bool `json:"rateEnabled"`
	// Residual notes multi-user / HA honesty when relevant (secret-free).
	Residual string `json:"residual,omitempty"`
}

// versionResponse is GET /admin/v1/version (subset of jenkins-mcp version --json).
// uiBuild is the SPA asset build id when available (UI-008).
type versionResponse struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"buildTime"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	UIBuild   string `json:"uiBuild"`
}

// metricsResponse is GET /admin/v1/metrics.
type metricsResponse struct {
	Available bool             `json:"available"`
	Counters  map[string]int64 `json:"counters"`
	Gauges    map[string]int64 `json:"gauges"`
	Residual  string           `json:"residual,omitempty"`
}

// meResponse is GET /admin/v1/me (UI-003). Never includes the token value.
type meResponse struct {
	Authenticated   bool     `json:"authenticated"`
	Role            string   `json:"role"`
	Permissions     []string `json:"permissions"`
	TokenConfigured bool     `json:"tokenConfigured"`
	// Residual is set for pilot modes (e.g. loopback without shared secret).
	Residual string `json:"residual,omitempty"`
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	// HOST-007 / HOST-008: secret-free enabled modes + gateway residual posture.
	// Full vault inventory remains on GET /admin/v1/gateway/vault (hash-only subjects).
	// Never tokens, vault bytes, Authorization headers, or raw subjects.
	modes := healthEnabledModes()
	mode := string(gateway.CredentialModeFromEnviron(os.Getenv))
	if !gateway.CredentialMode(mode).Valid() {
		mode = ""
	}
	multiUser := gateway.MultiUserEnabled(os.Getenv)
	rateEnabled := gateway.SubjectRateEnabledFromEnviron(os.Getenv)
	residual := ""
	if multiUser {
		// Secret-free honesty only (SPA reads residual; no SPA rebuild required for this string).
		// multi_user_offline + host008_single_replica residual ids: release-evidence --offline.
		residual = "JENKINS_MCP_GATEWAY_MULTI_USER is set (foundation residual; not production multi-user GO; haMultiReplica always false / HOST-008 single-replica; no tokens in health)"
	}
	writeJSON(w, http.StatusOK, healthResponse{
		Status:           "ok",
		Version:          s.cfg.Version,
		Commit:           s.cfg.Commit,
		UIBuild:          s.cfg.UIBuild,
		EnabledModes:     modes,
		CredentialMode:   mode,
		MultiUserEnabled: multiUser,
		GatewayReady:     false, // admin BFF ≠ MCP serve Ready probe
		HAMultiReplica:   false, // HOST-008 Tier A default
		RateEnabled:      rateEnabled,
		Residual:         residual,
	})
}

// healthEnabledModes returns HOST-011 enabled credential mode ids from env
// (secret-free). Invalid config → empty slice (operators use /gateway/vault residual).
func healthEnabledModes() []string {
	mx, err := gateway.ModeMatrixFromEnviron(os.Getenv)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(mx.Enabled))
	for _, m := range mx.Enabled {
		out = append(out, m.String())
	}
	return out
}

// handleMe returns the process role and permissions (UI-003).
// authenticated is true when the shared secret matched (or no token is
// required on loopback residual). The token value is never returned.
func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	role := RoleFromContext(r.Context())
	if role == "" {
		role = s.cfg.Role
	}
	if role == "" {
		role = RoleViewer
	}
	tokenConfigured := strings.TrimSpace(s.cfg.BearerToken) != ""
	// Auth middleware already 401s when token required and missing/wrong.
	// Reaching this handler means either no gate or token matched.
	authenticated := true
	if tokenConfigured && !TokenMatches(r, s.cfg.BearerToken) {
		// Should not reach here when middleware is in place; fail closed.
		authenticated = false
	}
	resp := meResponse{
		Authenticated:   authenticated,
		Role:            role.String(),
		Permissions:     role.PermissionStrings(),
		TokenConfigured: tokenConfigured,
	}
	if !tokenConfigured {
		resp.Residual = "no admin token on loopback (pilot-only; prefer --require-token); process role still applies"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, versionResponse{
		Version:   s.cfg.Version,
		Commit:    s.cfg.Commit,
		BuildTime: s.cfg.BuildTime,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		UIBuild:   s.cfg.UIBuild,
	})
}

func (s *server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	reg := telemetry.Global()
	if reg == nil || reg.Metrics == nil {
		writeJSON(w, http.StatusOK, metricsResponse{
			Available: false,
			Counters:  map[string]int64{},
			Gauges:    map[string]int64{},
			Residual:  "process-local snapshot; empty if no serve registry",
		})
		return
	}
	snap := reg.Snapshot()
	if snap.Counters == nil {
		snap.Counters = map[string]int64{}
	}
	if snap.Gauges == nil {
		snap.Gauges = map[string]int64{}
	}
	writeJSON(w, http.StatusOK, metricsResponse{
		Available: true,
		Counters:  snap.Counters,
		Gauges:    snap.Gauges,
		Residual:  "process-local snapshot; empty if no serve registry",
	})
}

func (s *server) handlePolicyEffective(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	id := r.PathValue("id")
	if err := ValidateProfileID(id); err != nil {
		writeAppErr(w, err)
		return
	}
	p, err := s.loadProfile(id)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	polRes, err := policy.LoadFromEnviron()
	if err != nil {
		writeAppErr(w, err)
		return
	}
	// Optional simulation flags (must not defeat enterprise force).
	q := r.URL.Query()
	readOnly := queryTruthy(q.Get("readOnly")) || queryTruthy(q.Get("read-only"))
	allowMut := queryTruthy(q.Get("allowMutations")) || queryTruthy(q.Get("allow-mutations"))
	profileRO := p.EffectiveReadOnly()
	ro := policy.Inputs{
		FlagReadOnly:    readOnly,
		EnvReadOnly:     policy.EnvReadOnlyFromEnviron(),
		ProfileReadOnly: &profileRO,
		Force:           policy.AsEnterpriseForce(polRes.Overlay),
		AllowMutations:  allowMut,
	}
	ex := policy.ExplainEffective(id, polRes, ro)
	writeJSON(w, http.StatusOK, ex)
}

func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	id := r.PathValue("id")
	if err := ValidateProfileID(id); err != nil {
		writeAppErr(w, err)
		return
	}
	q := r.URL.Query()
	aq := AuditQuery{
		Type: q.Get("type"),
	}
	if lim := strings.TrimSpace(q.Get("limit")); lim != "" {
		n, err := strconv.Atoi(lim)
		if err != nil || n < 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid_argument", "limit must be a non-negative integer")
			return
		}
		aq.Limit = n
	}
	if before := strings.TrimSpace(q.Get("before")); before != "" {
		t, err := time.Parse(time.RFC3339, before)
		if err != nil {
			// Also accept RFC3339Nano.
			t, err = time.Parse(time.RFC3339Nano, before)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_argument", "before must be RFC3339")
				return
			}
		}
		t = t.UTC()
		aq.Before = &t
	}

	// Prefer profile.DataDir when the profile exists; missing profile still
	// allows reading default XDG audit path (empty events if no file).
	var dataOverride string
	if p, err := s.loadProfile(id); err == nil && p != nil {
		dataOverride = strings.TrimSpace(p.DataDir)
	}

	paths, err := s.resolvePaths()
	if err != nil {
		writeAppErr(w, err)
		return
	}
	path, err := ProfileAuditPath(paths, id, dataOverride)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	page, err := ReadAuditFile(path, id, aq)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *server) handleDoctorProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	id := r.PathValue("id")
	s.runDoctor(w, r, id)
}

func (s *server) handleDoctorDefault(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("profile"))
	if id == "" {
		id = strings.TrimSpace(s.cfg.ProfileID)
	}
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_argument", "profile id is required (path, ?profile=, or --profile)")
		return
	}
	s.runDoctor(w, r, id)
}

func (s *server) runDoctor(w http.ResponseWriter, r *http.Request, id string) {
	if err := ValidateProfileID(id); err != nil {
		writeAppErr(w, err)
		return
	}
	p, err := s.loadProfile(id)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	// offline=1 default true for v1; offline=0 enables network identity (bounded).
	// Fail closed: online doctor requires a configured shared secret so loopback
	// residual without token cannot exercise keyring → Jenkins whoAmI.
	offline := true
	if v := strings.TrimSpace(r.URL.Query().Get("offline")); v != "" {
		// offline=1/true → offline; offline=0/false → online request
		offline = queryTruthy(v)
	}
	if !offline && strings.TrimSpace(s.cfg.BearerToken) == "" {
		writeJSONError(w, http.StatusForbidden, "permission_denied",
			"online doctor requires admin shared secret (configure --admin-token-env or --admin-token-file)")
		return
	}
	paths, err := s.resolvePaths()
	if err != nil {
		writeAppErr(w, err)
		return
	}
	var polPtr *policy.LoadResult
	if polRes, polErr := policy.LoadFromEnviron(); polErr == nil {
		polPtr = &polRes
	}
	kr := s.cfg.Keyring
	if kr == nil {
		kr = keyring.Default()
	}
	docOpts := diagnostics.DoctorOptions{
		Profile:      p,
		Paths:        &paths,
		Keyring:      kr,
		Version:      s.cfg.Version,
		Commit:       s.cfg.Commit,
		BuildTime:    s.cfg.BuildTime,
		SkipNetwork:  offline,
		PolicyResult: polPtr,
	}
	if reg := telemetry.Global(); reg != nil {
		docOpts.Metrics = reg.Metrics
	}
	ctx := r.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	rep, err := diagnostics.RunDoctor(ctx, docOpts)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	// Report is already secret-free (SanitizeCheck applied inside RunDoctor).
	writeJSON(w, http.StatusOK, rep)
}

func (s *server) loadProfile(id string) (*profile.Profile, error) {
	if s.cfg.LoadProfile != nil {
		return s.cfg.LoadProfile(id)
	}
	paths, err := s.resolvePaths()
	if err != nil {
		return nil, err
	}
	st := profile.NewStore(paths)
	return st.Load(id)
}

func (s *server) resolvePaths() (config.Paths, error) {
	if s.cfg.Paths != nil {
		return *s.cfg.Paths, nil
	}
	return config.Resolve()
}

func queryTruthy(v string) bool {
	v = strings.TrimSpace(v)
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") || strings.EqualFold(v, "on")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{
		"code":    code,
		"message": message,
	})
}

func writeAppErr(w http.ResponseWriter, err error) {
	if err == nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	code := apperr.CodeOf(err)
	if code == "" {
		code = apperr.CodeInternal
	}
	status := httpStatusForCode(code)
	msg := apperr.ModelMessage(err)
	// Strip leading "code: " prefix from Error() for cleaner message field.
	if prefix := string(code) + ": "; strings.HasPrefix(msg, prefix) {
		msg = strings.TrimPrefix(msg, prefix)
	}
	writeJSONError(w, status, string(code), msg)
}

func httpStatusForCode(code apperr.Code) int {
	switch code {
	case apperr.CodeAuthentication:
		return http.StatusUnauthorized
	case apperr.CodeAuthorization, apperr.CodePolicyDenial:
		return http.StatusForbidden
	case apperr.CodeNotFound:
		return http.StatusNotFound
	case apperr.CodeInvalidArgument:
		return http.StatusBadRequest
	case apperr.CodeThrottled:
		return http.StatusTooManyRequests
	case apperr.CodeTimeout:
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}
