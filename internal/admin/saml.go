package admin

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/saml"
)

// CookieSAMLSession is the process-local SAML admin session cookie name.
const CookieSAMLSession = "jenkins_mcp_admin_saml"

// SAMLOptions configures optional admin SAML SSO (POL-007).
type SAMLOptions struct {
	Config saml.Config
	Trust  saml.TrustMaterial
	// SessionHMACKey signs session cookies (from env; never logged).
	SessionHMACKey []byte
	// Audit sink optional.
	Audit audit.Sink
	// Now optional clock for tests.
	Now func() time.Time
	// SessionTTL default 8h.
	SessionTTL time.Duration
}

// samlRuntime holds process-local session store (not multi-pod HA).
type samlRuntime struct {
	mu       sync.Mutex
	opts     SAMLOptions
	sessions map[string]samlSession // sid → session
}

type samlSession struct {
	Role            Role
	SubjectRedacted string
	GroupMatched    string
	Expires         time.Time
}

func newSAMLRuntime(opts SAMLOptions) *samlRuntime {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = 8 * time.Hour
	}
	return &samlRuntime{opts: opts, sessions: make(map[string]samlSession)}
}

func (rt *samlRuntime) enabled() bool {
	return rt != nil && rt.opts.Config.Enabled
}

func (rt *samlRuntime) require() bool {
	return rt != nil && rt.opts.Config.Require
}

// handleSAMLStatus is GET /admin/v1/saml/status — secret-free.
func (s *server) handleSAMLStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if s.saml == nil || !s.saml.enabled() {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":  false,
			"require":  false,
			"residual": "saml_disabled; shared-secret pilot remains",
		})
		return
	}
	out := s.saml.opts.Config.StatusMap()
	out["acs_path"] = "/admin/v1/saml/acs"
	out["login_path"] = "/admin/v1/saml/login"
	writeJSON(w, http.StatusOK, out)
}

// handleSAMLLogin is GET /admin/v1/saml/login — residual offline: no live IdP redirect URL with secrets.
// Returns 501 with residual when no SSO URL is configured (live IdP pin residual).
func (s *server) handleSAMLLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if s.saml == nil || !s.saml.enabled() {
		writeJSONError(w, http.StatusNotFound, "not_found", "saml not enabled")
		return
	}
	// Offline residual: browser redirect to real IdP is live pin residual.
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"code":     "not_implemented",
		"message":  "saml IdP redirect residual (configure mock lab or live IdP pin)",
		"residual": "live_entra_okta_adfs_pin",
		"acs":      "/admin/v1/saml/acs",
	})
}

// handleSAMLACS is POST /admin/v1/saml/acs — Assertion Consumer Service (form SAMLResponse).
func (s *server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if s.saml == nil || !s.saml.enabled() {
		writeJSONError(w, http.StatusNotFound, "not_found", "saml not enabled")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_argument", "invalid form")
		return
	}
	b64 := r.FormValue("SAMLResponse")
	raw, err := saml.DecodeSAMLResponse(b64)
	if err != nil {
		s.emitSAMLAudit(audit.TypeLoginFail, "saml_decode", "")
		writeJSONError(w, http.StatusUnauthorized, "authentication", "unauthorized")
		return
	}
	id, err := saml.ValidateAndMap(s.saml.opts.Config, raw, saml.ValidateOptions{
		Now:   s.saml.opts.Now().UTC(),
		Trust: s.saml.opts.Trust,
	})
	if err != nil {
		s.emitSAMLAudit(audit.TypeLoginFail, "saml_validate", "")
		writeJSONError(w, http.StatusUnauthorized, "authentication", "unauthorized")
		return
	}
	roleName, matched, err := saml.ResolveAdminRole(s.saml.opts.Config, id.Groups)
	if err != nil {
		s.emitSAMLAudit(audit.TypeLoginFail, "saml_role_unmapped", id.SubjectRedacted)
		writeJSONError(w, http.StatusForbidden, "authorization", "permission denied")
		return
	}
	role, err := ParseRole(roleName)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "authorization", "permission denied")
		return
	}
	sid, err := s.saml.createSession(role, id.SubjectRedacted, matched)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "session create failed")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieSAMLSession,
		Value:    sid,
		Path:     "/admin/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// Secure residual for HTTPS terminators; loopback pilot allows Secure=false.
		Secure: false,
		MaxAge: int(s.saml.opts.SessionTTL.Seconds()),
	})
	s.emitSAMLAudit(audit.TypeLoginSuccess, "saml_acs", id.SubjectRedacted)
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":    true,
		"role":             role.String(),
		"subject_redacted": id.SubjectRedacted,
		"group_matched":    matched,
		// Never echo groups list in full if large — count only.
		"group_count": len(id.Groups),
	})
}

func (rt *samlRuntime) createSession(role Role, subjectRedacted, matched string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	sid := base64.RawURLEncoding.EncodeToString(b[:])
	// Optional HMAC stamp when key configured (integrity of cookie value).
	if len(rt.opts.SessionHMACKey) > 0 {
		mac := hmac.New(sha256.New, rt.opts.SessionHMACKey)
		_, _ = mac.Write([]byte(sid))
		sid = sid + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	// Prune expired
	now := rt.opts.Now()
	for k, v := range rt.sessions {
		if now.After(v.Expires) {
			delete(rt.sessions, k)
		}
	}
	rt.sessions[sid] = samlSession{
		Role:            role,
		SubjectRedacted: subjectRedacted,
		GroupMatched:    matched,
		Expires:         now.Add(rt.opts.SessionTTL),
	}
	return sid, nil
}

func (rt *samlRuntime) lookupSession(sid string) (samlSession, bool) {
	if rt == nil || sid == "" {
		return samlSession{}, false
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	sess, ok := rt.sessions[sid]
	if !ok {
		return samlSession{}, false
	}
	if rt.opts.Now().After(sess.Expires) {
		delete(rt.sessions, sid)
		return samlSession{}, false
	}
	return sess, true
}

func (s *server) emitSAMLAudit(typ, reason, subjectRedacted string) {
	if s == nil {
		return
	}
	// Prefer injected sink (tests). Production serve path opens the profile
	// audit File under <data>/audit/ — same as emitPolicyAudit / emitOpsAudit.
	// LoadSAMLOptionsFromEnviron does not set Audit; silent nil was a bug.
	sink := audit.Sink(nil)
	if s.saml != nil {
		sink = s.saml.opts.Audit
	}
	closeSink := func() {}
	if sink == nil {
		var err error
		sink, closeSink, err = s.openProfileAuditSink()
		if err != nil || sink == nil {
			return
		}
	}
	defer closeSink()

	ev := audit.Event{
		Type:          typ,
		Decision:      audit.DecisionFail,
		ReasonCode:    reason,
		ProfileID:     strings.TrimSpace(s.cfg.ProfileID),
		Action:        "saml_admin",
		SchemaVersion: 1,
	}
	if typ == audit.TypeLoginSuccess {
		ev.Decision = audit.DecisionSuccess
	}
	if subjectRedacted != "" {
		ev.ExternalSubject = subjectRedacted
		ev.SubjectKeyHash = audit.HashOpaque(subjectRedacted)
	}
	_ = audit.Emit(context.Background(), sink, ev)
}

// openProfileAuditSink opens a File sink under the configured profile data dir
// (AUD-001). Best-effort; returns nil when no profile/data root is available.
func (s *server) openProfileAuditSink() (audit.Sink, func(), error) {
	if s == nil {
		return nil, func() {}, apperr.New(apperr.CodeInvalidArgument, "nil server")
	}
	profileID := strings.TrimSpace(s.cfg.ProfileID)
	if profileID == "" {
		return nil, func() {}, nil
	}
	if err := ValidateProfileID(profileID); err != nil {
		return nil, func() {}, err
	}
	paths, err := s.resolvePaths()
	if err != nil {
		return nil, func() {}, err
	}
	var dataOverride string
	if p, err := s.loadProfile(profileID); err == nil && p != nil {
		dataOverride = strings.TrimSpace(p.DataDir)
	}
	auditPath, err := ProfileAuditPath(paths, profileID, dataOverride)
	if err != nil {
		return nil, func() {}, err
	}
	dir := filepath.Dir(auditPath)
	// Ensure audit dir can be created when profile data root exists or is creatable.
	sink, err := audit.NewFile(audit.FileConfig{Dir: dir})
	if err != nil {
		return nil, func() {}, err
	}
	return sink, func() { _ = sink.Close() }, nil
}

// EnvSAMLSessionKey is optional HMAC key material for session cookies.
const EnvSAMLSessionKey = "JENKINS_MCP_SAML_SESSION_KEY"

// LoadSAMLOptionsFromEnviron builds SAMLOptions when config env is set.
func LoadSAMLOptionsFromEnviron() (SAMLOptions, error) {
	cfg, err := saml.LoadConfigFromEnviron()
	if err != nil {
		return SAMLOptions{}, err
	}
	if !cfg.Enabled {
		return SAMLOptions{}, nil
	}
	opts := SAMLOptions{Config: cfg}
	if p := strings.TrimSpace(cfg.IdPCertificatePEMPath); p != "" {
		trust, err := saml.LoadTrustFromPEMFile(p)
		if err != nil {
			return SAMLOptions{}, err
		}
		opts.Trust = trust
	}
	if k := strings.TrimSpace(os.Getenv(EnvSAMLSessionKey)); k != "" {
		opts.SessionHMACKey = []byte(k)
	}
	return opts, nil
}

// sessionRoleFromRequest returns SAML session role when cookie present.
func (s *server) sessionRoleFromRequest(r *http.Request) (Role, bool) {
	if s == nil || s.saml == nil || !s.saml.enabled() || r == nil {
		return "", false
	}
	c, err := r.Cookie(CookieSAMLSession)
	if err != nil || c == nil || c.Value == "" {
		return "", false
	}
	sess, ok := s.saml.lookupSession(c.Value)
	if !ok {
		return "", false
	}
	return sess.Role, true
}

// meSAMLFields adds SAML residual fields to /me when enabled.
func (s *server) meSAMLFields() map[string]any {
	if s == nil || s.saml == nil || !s.saml.enabled() {
		return nil
	}
	return map[string]any{
		"saml_enabled": true,
		"saml_require": s.saml.require(),
		"residual":     "live_entra_okta_adfs_pin",
	}
}
