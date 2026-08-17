package admin

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// PurgeConfirmToken is the exact body.confirm string required for fleet-cache
// purge (FLC-063). Must match fleetcache.PurgeConfirmToken / adminops.ConfirmPURGE.
const PurgeConfirmToken = fleetcache.PurgeConfirmToken // "PURGE"

// fleetCachePurgeRequest is POST /admin/v1/fleet-cache/purge body.
type fleetCachePurgeRequest struct {
	// Confirm must be exactly PurgeConfirmToken ("PURGE").
	Confirm string `json:"confirm"`
	// LocatorHash is the sealed object locator (required).
	LocatorHash string `json:"locator_hash"`
	// ManifestDigest optional version scope.
	ManifestDigest string `json:"manifest_digest"`
	// MaxOwners optional bound (0 → library default).
	MaxOwners int `json:"max_owners"`
	// Reason secret-free operator note (scrubbed).
	Reason string `json:"reason"`
	// ProfileID optional audit correlation (not used for authorization).
	ProfileID string `json:"profile_id"`
}

// handleFleetCacheStatus is GET /admin/v1/fleet-cache/status (FLC-063).
// Viewer+. Process-local status; multi-member aggregation residual. Secret-free.
func (s *server) handleFleetCacheStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermRead) {
		return
	}
	cfg, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{Getenv: os.Getenv})
	if err != nil {
		writeAppErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, fleetcache.StatusSnapshot(cfg, nil, nil, fleetcache.StatusOptions{}))
}

// handleFleetCacheDoctor is GET /admin/v1/fleet-cache/doctor (FLC-063).
// Viewer+. Secret-free doctor checks + nested status.
func (s *server) handleFleetCacheDoctor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermRead) {
		return
	}
	cfg, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{Getenv: os.Getenv})
	if err != nil {
		writeAppErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, fleetcache.DoctorSnapshot(cfg, nil, nil, fleetcache.StatusOptions{}))
}

// handleFleetCachePurge is POST /admin/v1/fleet-cache/purge (FLC-063).
// Operator+ (cache_destructive). Body confirm must be exactly "PURGE".
// Process-local tombstone + optional local sink; no HTTP peer purge fan-out.
// Never tokens, raw logs, or Jenkins origin deletes.
func (s *server) handleFleetCachePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermCacheDestructive) {
		return
	}
	var req fleetCachePurgeRequest
	if err := decodeOpsBody(r, &req); err != nil {
		writeAppErr(w, err)
		return
	}
	if req.Confirm != PurgeConfirmToken {
		writeJSONError(w, http.StatusBadRequest, "invalid_argument",
			`confirm must be exactly "PURGE" (double-confirm required)`)
		return
	}
	if strings.TrimSpace(req.LocatorHash) == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_argument", "locator_hash is required")
		return
	}

	// Authorize against the REQUEST role (SAML-mapped, attached by the auth
	// middleware and already checked for PermCacheDestructive above) — not the
	// static process role, which would 403 a SAML-mapped operator whenever the
	// process runs with the default viewer role.
	var role string
	switch RoleFromContext(r.Context()) {
	case RoleOperator:
		role = fleetcache.PurgeRoleOperator
	case RolePolicyAdmin:
		role = fleetcache.PurgeRolePolicyAdmin
	default:
		// Defensive: permission middleware should already have denied viewer.
		writeJSONError(w, http.StatusForbidden, "permission_denied",
			"fleet-cache purge requires operator role")
		return
	}

	ctx := r.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	out, err := fleetcache.AdminPurge(ctx, fleetcache.AdminPurgeOptions{
		Role:           role,
		Confirm:        PurgeConfirmToken,
		LocatorHash:    req.LocatorHash,
		ManifestDigest: req.ManifestDigest,
		MaxOwners:      req.MaxOwners,
		Reason:         req.Reason,
		LocalOnly:      true,
	})

	// Best-effort AUD-001 (process/profile data dir when available).
	s.emitAdminAudit(req.ProfileID, audit.Event{
		Type:       audit.TypeAdminFleetCachePurge,
		Action:     "fleet_cache_purge",
		Decision:   auditDecision(err),
		ReasonCode: "confirm_PURGE",
		TargetHash: audit.HashOpaque(strings.ToLower(strings.TrimSpace(req.LocatorHash))),
	})

	if err != nil {
		writeAppErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// auditEvent builds a secret-free admin mutation audit event (AUD-001):
// decision derived from the operation error, opaque hash-only target.
func auditEvent(typ, action string, opErr error, target string) audit.Event {
	e := audit.Event{
		Type:       typ,
		Action:     action,
		Decision:   auditDecision(opErr),
		ReasonCode: "admin_bff",
	}
	if t := strings.TrimSpace(target); t != "" {
		e.TargetHash = audit.HashOpaque(t)
	}
	return e
}

// emitAdminAudit best-effort writes a secret-free admin mutation event under
// the profile's audit JSONL dir (AUD-001). Failures are ignored (must not
// break the primary op); the event itself is hash-only and secret-free.
func (s *server) emitAdminAudit(profileID string, e audit.Event) {
	id := strings.TrimSpace(profileID)
	// The request-body profile_id is audit correlation only, but it feeds a
	// filesystem path — validate like every other profile-scoped handler so a
	// traversal value ("../../..") can never escape the profiles root.
	if id != "" {
		if err := ValidateProfileID(id); err != nil {
			id = ""
		}
	}
	if id == "" {
		id = strings.TrimSpace(s.cfg.ProfileID)
	}
	if id == "" {
		id = "admin"
	}
	e.ProfileID = id
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	paths, err := s.resolvePaths()
	if err != nil {
		return
	}
	dir := paths.ProfileDataDir(id)
	// Only emit when data root already exists (same as emitOpsAudit).
	if _, err := os.Stat(filepath.Clean(dir)); err != nil {
		return
	}
	auditDir := filepath.Join(filepath.Clean(dir), "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		return
	}
	sink, err := audit.NewFile(audit.FileConfig{Dir: auditDir})
	if err != nil {
		return
	}
	defer func() { _ = sink.Close() }()
	_ = audit.Emit(context.Background(), sink, e)
}
