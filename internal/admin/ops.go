package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

// EvictConfirmToken is the exact body.confirm string required for destructive
// cache eviction (UI-007). SPA and operators must type this token.
const EvictConfirmToken = "EVICT"

// maxOpsBodyBytes caps JSON bodies for ops POST routes (fail closed).
const maxOpsBodyBytes = 1 << 16 // 64 KiB

// --- secret-free response types (UI-007) ---

// profileSummary is a secret-free profile row for list/detail.
// Never includes tokens, passwords, keyring payloads, or client secrets.
type profileSummary struct {
	ID              string `json:"id"`
	DisplayName     string `json:"displayName,omitempty"`
	JenkinsURL      string `json:"jenkinsURL"`
	JenkinsHost     string `json:"jenkinsHost,omitempty"`
	AuthMethod      string `json:"authMethod"`
	Username        string `json:"username,omitempty"`
	ReadOnly        bool   `json:"readOnly"`
	HasCredential   bool   `json:"hasCredential"`
	CacheEncryption bool   `json:"cacheEncryption"`
	// DataDirSet is true when the profile has an explicit absolute dataDir.
	// The path itself is not returned (may be high-cardinality / local-only).
	DataDirSet bool `json:"dataDirSet,omitempty"`
}

type profileListResponse struct {
	Profiles []profileSummary `json:"profiles"`
}

// cacheSummary is GET .../cache (secret-free quota/usage).
// When the store is unavailable, Available is false and Residual explains why
// (HTTP 200, not 500) so the SPA can show an honest empty state.
type cacheSummary struct {
	ProfileID     string            `json:"profileId"`
	Available     bool              `json:"available"`
	NeedsEviction bool              `json:"needsEviction,omitempty"`
	Usage         *store.UsageStats `json:"usage,omitempty"`
	Pins          int               `json:"pins,omitempty"`
	Residual      string            `json:"residual,omitempty"`
}

// evictionCandidateJSON mirrors CLI cache eviction-plan candidate rows.
type evictionCandidateJSON struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Bytes  int64  `json:"bytes"`
	Age    string `json:"age,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// evictionPlanResponse is secret-free plan/apply result for cache ops.
type evictionPlanResponse struct {
	ProfileID         string                  `json:"profileId"`
	NeedsEviction     bool                    `json:"needsEviction"`
	Usage             store.UsageStats        `json:"usage"`
	BytesNeeded       int64                   `json:"bytesNeeded"`
	TotalReclaimBytes int64                   `json:"totalReclaimBytes"`
	DryRun            bool                    `json:"dryRun"`
	Applied           bool                    `json:"applied,omitempty"`
	PinsSkipped       int                     `json:"pinsSkipped"`
	Candidates        []evictionCandidateJSON `json:"candidates"`
	PlannedAt         string                  `json:"plannedAt,omitempty"`
	Evicted           int                     `json:"evicted,omitempty"`
	Failed            int                     `json:"failed,omitempty"`
	ReclaimedBytes    int64                   `json:"reclaimedBytes,omitempty"`
	Interrupted       bool                    `json:"interrupted,omitempty"`
	JournalRecovered  int                     `json:"journalRecovered,omitempty"`
	JournalReclaimed  int64                   `json:"journalReclaimedBytes,omitempty"`
	JournalConsistent bool                    `json:"journalConsistent,omitempty"`
	Errors            []string                `json:"errors,omitempty"`
}

type cacheEvictRequest struct {
	// Confirm must be exactly EvictConfirmToken for apply.
	Confirm     string `json:"confirm"`
	TargetBytes int64  `json:"targetBytes"`
}

type cacheEvictPlanRequest struct {
	TargetBytes int64 `json:"targetBytes"`
}

type supportBundleRequest struct {
	Preview bool `json:"preview"`
	// Offline defaults true when omitted (zero value). Online (false) requires
	// a configured admin shared secret (same fail-closed rule as doctor).
	Offline *bool `json:"offline"`
}

type supportBundleResponse struct {
	ProfileID  string   `json:"profileId"`
	Preview    bool     `json:"preview"`
	Path       string   `json:"path,omitempty"`
	Bytes      int64    `json:"bytes,omitempty"`
	CreatedAt  string   `json:"createdAt,omitempty"`
	Included   []string `json:"included"`
	Excluded   []string `json:"excluded"`
	OutputPath string   `json:"outputPath,omitempty"`
	Categories []string `json:"categories,omitempty"`
}

// handleProfilesList is GET /admin/v1/profiles (UI-007).
func (s *server) handleProfilesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermRead) {
		return
	}
	ids, err := s.listProfileIDs()
	if err != nil {
		writeAppErr(w, err)
		return
	}
	out := profileListResponse{Profiles: make([]profileSummary, 0, len(ids))}
	for _, id := range ids {
		p, err := s.loadProfile(id)
		if err != nil {
			// Skip unreadable profiles rather than failing the whole list.
			continue
		}
		out.Profiles = append(out.Profiles, s.summarizeProfile(r.Context(), p))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleProfileGet is GET /admin/v1/profiles/{id} (UI-007).
func (s *server) handleProfileGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermRead) {
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
	writeJSON(w, http.StatusOK, s.summarizeProfile(r.Context(), p))
}

// handleProfileCache is GET /admin/v1/profiles/{id}/cache (UI-007).
func (s *server) handleProfileCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermRead) {
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
	writeJSON(w, http.StatusOK, s.cacheSummaryFor(r.Context(), p))
}

// handleCacheEvictPlan is POST /admin/v1/profiles/{id}/cache/evict-plan (read, non-destructive).
func (s *server) handleCacheEvictPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermRead) {
		return
	}
	id := r.PathValue("id")
	if err := ValidateProfileID(id); err != nil {
		writeAppErr(w, err)
		return
	}
	var req cacheEvictPlanRequest
	if err := decodeOpsBody(r, &req); err != nil {
		writeAppErr(w, err)
		return
	}
	if req.TargetBytes < 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_argument", "targetBytes must be non-negative")
		return
	}
	p, err := s.loadProfile(id)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	plan, err := s.runEvictPlan(r.Context(), p, req.TargetBytes)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

// handleCacheEvict is POST /admin/v1/profiles/{id}/cache/evict (operator + confirm).
func (s *server) handleCacheEvict(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermCacheDestructive) {
		return
	}
	id := r.PathValue("id")
	if err := ValidateProfileID(id); err != nil {
		writeAppErr(w, err)
		return
	}
	var req cacheEvictRequest
	if err := decodeOpsBody(r, &req); err != nil {
		writeAppErr(w, err)
		return
	}
	if req.Confirm != EvictConfirmToken {
		writeJSONError(w, http.StatusBadRequest, "invalid_argument",
			`confirm must be exactly "EVICT" (double-confirm required)`)
		return
	}
	if req.TargetBytes < 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_argument", "targetBytes must be non-negative")
		return
	}
	p, err := s.loadProfile(id)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	out, err := s.runEvictApply(r.Context(), p, req.TargetBytes)
	// Always try to audit apply attempts (success or failure), secret-free.
	s.emitOpsAudit(p, audit.Event{
		Type:       audit.TypeAdminCacheEvict,
		ProfileID:  string(p.ID),
		Action:     "cache_evict",
		Decision:   auditDecision(err),
		ReasonCode: "confirm_EVICT",
	})
	if err != nil {
		writeAppErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSupportBundle is POST /admin/v1/profiles/{id}/support-bundle (operator).
func (s *server) handleSupportBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	// Support-bundle creation is day-2 ops; reuse operator cache_destructive.
	if !CheckPermission(w, r, PermCacheDestructive) {
		return
	}
	id := r.PathValue("id")
	if err := ValidateProfileID(id); err != nil {
		writeAppErr(w, err)
		return
	}
	var req supportBundleRequest
	if err := decodeOpsBody(r, &req); err != nil {
		writeAppErr(w, err)
		return
	}
	offline := true
	if req.Offline != nil {
		offline = *req.Offline
	}
	// Online doctor-inside-bundle needs shared secret (same as doctor endpoint).
	if !offline && strings.TrimSpace(s.cfg.BearerToken) == "" {
		writeJSONError(w, http.StatusForbidden, "permission_denied",
			"online support-bundle requires admin shared secret (configure --admin-token-env or --admin-token-file)")
		return
	}
	p, err := s.loadProfile(id)
	if err != nil {
		writeAppErr(w, err)
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
	res, err := diagnostics.CreateSupportBundle(ctx, diagnostics.SupportBundleOptions{
		Profile:      p,
		Paths:        &paths,
		DoctorOpts:   docOpts,
		PolicyResult: polPtr,
		Version:      s.cfg.Version,
		Commit:       s.cfg.Commit,
		BuildTime:    s.cfg.BuildTime,
		PreviewOnly:  req.Preview,
	})
	// Audit non-preview creates (and failed create attempts).
	if !req.Preview {
		s.emitOpsAudit(p, audit.Event{
			Type:       audit.TypeAdminSupportBundle,
			ProfileID:  string(p.ID),
			Action:     "support_bundle_create",
			Decision:   auditDecision(err),
			ReasonCode: "admin_console",
		})
	}
	if err != nil {
		writeAppErr(w, err)
		return
	}
	out := supportBundleResponse{
		ProfileID:  string(p.ID),
		Preview:    req.Preview,
		Path:       res.Path,
		Bytes:      res.Bytes,
		Included:   res.Plan.Included,
		Excluded:   res.Plan.Excluded,
		OutputPath: res.Plan.OutputPath,
		Categories: res.Categories,
	}
	if !res.CreatedAt.IsZero() {
		out.CreatedAt = res.CreatedAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSecuritySelfCheck is GET /admin/v1/profiles/{id}/security-selfcheck (UI-007).
func (s *server) handleSecuritySelfCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermRead) {
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
	paths, err := s.resolvePaths()
	if err != nil {
		writeAppErr(w, err)
		return
	}
	var polPtr *policy.LoadResult
	if polRes, polErr := policy.LoadFromEnviron(); polErr == nil {
		polPtr = &polRes
	}
	ctx := r.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{
		Profile:      p,
		Paths:        &paths,
		PolicyResult: polPtr,
		Version:      s.cfg.Version,
		Commit:       s.cfg.Commit,
	})
	if err != nil {
		writeAppErr(w, err)
		return
	}
	// Self-check report is secret-free by construction (canary tests).
	writeJSON(w, http.StatusOK, rep)
}

// --- helpers ---

func (s *server) listProfileIDs() ([]string, error) {
	if s.cfg.ListProfiles != nil {
		return s.cfg.ListProfiles()
	}
	paths, err := s.resolvePaths()
	if err != nil {
		return nil, err
	}
	return profile.NewStore(paths).List()
}

func (s *server) summarizeProfile(ctx context.Context, p *profile.Profile) profileSummary {
	if p == nil {
		return profileSummary{}
	}
	sum := profileSummary{
		ID:              string(p.ID),
		DisplayName:     strings.TrimSpace(p.DisplayName),
		JenkinsURL:      strings.TrimSpace(p.JenkinsURL),
		JenkinsHost:     jenkinsHostOnly(p.JenkinsURL),
		AuthMethod:      string(p.AuthMethod),
		Username:        strings.TrimSpace(p.Username),
		ReadOnly:        p.EffectiveReadOnly(),
		CacheEncryption: p.CacheEncryption,
		DataDirSet:      strings.TrimSpace(p.DataDir) != "",
	}
	sum.HasCredential = s.credentialPresent(ctx, p)
	return sum
}

func jenkinsHostOnly(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// credentialPresent reports keyring presence without returning secret values.
// Fail closed to false on errors (including unavailable keyring).
func (s *server) credentialPresent(ctx context.Context, p *profile.Profile) bool {
	if p == nil || strings.TrimSpace(p.Username) == "" {
		return false
	}
	kr := s.cfg.Keyring
	if kr == nil {
		// Avoid Default() Secret Service side effects on list paths in tests/CI.
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	prov := auth.NewAPITokenProvider(kr)
	st, err := prov.Status(ctx, auth.ProfileFrom(p))
	if err != nil {
		return false
	}
	return st.HasCredential
}

func (s *server) cacheSummaryFor(ctx context.Context, p *profile.Profile) cacheSummary {
	id := ""
	if p != nil {
		id = string(p.ID)
	}
	meta, dataDir, err := s.openProfileMeta(p)
	if err != nil {
		return cacheSummary{
			ProfileID: id,
			Available: false,
			Residual:  "cache store unavailable: " + apperr.ModelMessage(err),
		}
	}
	defer func() { _ = meta.Close() }()

	qm, err := store.NewQuotaManager(meta, dataDir, store.QuotaConfig{})
	if err != nil {
		return cacheSummary{
			ProfileID: id,
			Available: false,
			Residual:  "quota manager unavailable: " + apperr.ModelMessage(err),
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	need, usage, err := qm.NeedsEviction(ctx)
	if err != nil {
		return cacheSummary{
			ProfileID: id,
			Available: false,
			Residual:  "usage stats unavailable: " + apperr.ModelMessage(err),
		}
	}
	if usage.Profile == "" {
		usage.Profile = id
	}
	pins := 0
	if list, perr := meta.ListPins(ctx); perr == nil {
		pins = len(list)
	}
	u := usage
	return cacheSummary{
		ProfileID:     id,
		Available:     true,
		NeedsEviction: need,
		Usage:         &u,
		Pins:          pins,
	}
}

func (s *server) runEvictPlan(ctx context.Context, p *profile.Profile, targetBytes int64) (evictionPlanResponse, error) {
	meta, dataDir, err := s.openProfileMeta(p)
	if err != nil {
		return evictionPlanResponse{}, err
	}
	defer func() { _ = meta.Close() }()

	qm, err := store.NewQuotaManager(meta, dataDir, store.QuotaConfig{})
	if err != nil {
		return evictionPlanResponse{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	need, _, err := qm.NeedsEviction(ctx)
	if err != nil {
		return evictionPlanResponse{}, err
	}
	plan, err := qm.PlanEviction(ctx, targetBytes)
	if err != nil {
		return evictionPlanResponse{}, err
	}
	id := string(p.ID)
	if plan.Usage.Profile == "" {
		plan.Usage.Profile = id
	}
	pinsSkipped := 0
	if list, perr := meta.ListPins(ctx); perr == nil {
		pinsSkipped = len(list)
	}
	return evictionPlanResponse{
		ProfileID:         id,
		NeedsEviction:     need,
		Usage:             plan.Usage,
		BytesNeeded:       plan.BytesNeeded,
		TotalReclaimBytes: plan.TotalReclaimBytes,
		DryRun:            true,
		PinsSkipped:       pinsSkipped,
		Candidates:        candidatesToJSON(plan),
		PlannedAt:         time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (s *server) runEvictApply(ctx context.Context, p *profile.Profile, targetBytes int64) (evictionPlanResponse, error) {
	meta, dataDir, err := s.openProfileMeta(p)
	if err != nil {
		return evictionPlanResponse{}, err
	}
	defer func() { _ = meta.Close() }()

	qm, err := store.NewQuotaManager(meta, dataDir, store.QuotaConfig{})
	if err != nil {
		return evictionPlanResponse{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return evictionPlanResponse{}, apperr.Wrap(apperr.CodeCancelled, "eviction cancelled", err)
	}

	// Recover incomplete journal first (same order as CLI / serve Maintainer).
	jr, err := qm.RecoverEvictJournal(ctx)
	if err != nil {
		return evictionPlanResponse{}, err
	}
	need, _, err := qm.NeedsEviction(ctx)
	if err != nil {
		return evictionPlanResponse{}, err
	}
	plan, err := qm.PlanEviction(ctx, targetBytes)
	if err != nil {
		return evictionPlanResponse{}, err
	}
	id := string(p.ID)
	if plan.Usage.Profile == "" {
		plan.Usage.Profile = id
	}
	pinsSkipped := 0
	if list, perr := meta.ListPins(ctx); perr == nil {
		pinsSkipped = len(list)
	}
	out := evictionPlanResponse{
		ProfileID:         id,
		NeedsEviction:     need,
		Usage:             plan.Usage,
		BytesNeeded:       plan.BytesNeeded,
		TotalReclaimBytes: plan.TotalReclaimBytes,
		DryRun:            false,
		Applied:           false,
		PinsSkipped:       pinsSkipped,
		Candidates:        candidatesToJSON(plan),
		PlannedAt:         time.Now().UTC().Format(time.RFC3339Nano),
		JournalRecovered:  jr.Evicted,
		JournalReclaimed:  jr.ReclaimedBytes,
		JournalConsistent: jr.JournalConsistent,
	}
	if len(plan.Candidates) == 0 {
		out.Applied = true
		return out, nil
	}
	er, err := qm.Evict(ctx, plan)
	out.Evicted = er.Evicted
	out.Failed = er.Failed
	out.ReclaimedBytes = er.ReclaimedBytes
	out.Interrupted = er.Interrupted
	out.JournalConsistent = er.JournalConsistent
	out.Errors = er.Errors
	if er.Plan.Applied {
		out.Applied = true
		out.DryRun = false
	}
	if need2, usage2, uerr := qm.NeedsEviction(ctx); uerr == nil {
		out.NeedsEviction = need2
		if usage2.Profile == "" {
			usage2.Profile = id
		}
		out.Usage = usage2
	}
	return out, err
}

// openProfileMeta opens an existing profile data root + meta store.
// Fail closed: does not create a data directory when missing.
func (s *server) openProfileMeta(p *profile.Profile) (*store.Meta, string, error) {
	if p == nil {
		return nil, "", apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	dataDir, err := s.resolveProfileDataDir(p)
	if err != nil {
		return nil, "", err
	}
	if err := store.ValidateDir(dataDir); err != nil {
		return nil, "", err
	}
	meta, err := store.Open(dataDir)
	if err != nil {
		return nil, "", err
	}
	return meta, dataDir, nil
}

// resolveProfileDataDir returns the profile data root without creating it.
func (s *server) resolveProfileDataDir(p *profile.Profile) (string, error) {
	if p == nil {
		return "", apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	id := strings.TrimSpace(string(p.ID))
	if id == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}
	if err := ValidateProfileID(id); err != nil {
		return "", err
	}
	var dataRoot string
	if strings.TrimSpace(p.DataDir) != "" {
		dataRoot = p.DataDir
	} else {
		paths, err := s.resolvePaths()
		if err != nil {
			return "", err
		}
		dataRoot = paths.ProfileDataDir(id)
	}
	clean := filepath.Clean(dataRoot)
	if filepath.Base(clean) == id {
		return clean, nil
	}
	return filepath.Join(clean, id), nil
}

func candidatesToJSON(plan store.EvictPlan) []evictionCandidateJSON {
	out := make([]evictionCandidateJSON, 0, len(plan.Candidates))
	for _, c := range plan.Candidates {
		out = append(out, evictionCandidateJSON{
			Kind:   c.Tier,
			ID:     c.ID,
			Bytes:  c.ReclaimBytes,
			Age:    c.Age,
			Reason: c.Reason,
		})
	}
	return out
}

func decodeOpsBody(r *http.Request, dst any) error {
	if r == nil || r.Body == nil {
		// Empty body is OK (zero-value request).
		return nil
	}
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, maxOpsBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return apperr.Wrap(apperr.CodeInvalidArgument, "failed to read request body", err)
	}
	if len(data) > maxOpsBodyBytes {
		return apperr.New(apperr.CodeInvalidArgument, "request body too large")
	}
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, "invalid JSON body")
	}
	return nil
}

func auditDecision(err error) string {
	if err != nil {
		return audit.DecisionFail
	}
	return audit.DecisionSuccess
}

// emitOpsAudit best-effort writes a secret-free admin ops event under the
// profile audit JSONL. Failures are ignored (must not break the primary op).
func (s *server) emitOpsAudit(p *profile.Profile, e audit.Event) {
	if p == nil {
		return
	}
	// Prefer explicit dataDir; else XDG profile data root.
	dir := strings.TrimSpace(p.DataDir)
	if dir == "" {
		paths, err := s.resolvePaths()
		if err != nil {
			return
		}
		dir = paths.ProfileDataDir(string(p.ID))
	}
	// Audit sink lives under <data>/audit/ (same as ProfileAuditPath).
	auditDir := filepath.Join(filepath.Clean(dir), "audit")
	// Ensure parent data dir exists only if already present — do not create
	// full profile trees just for audit. MkdirAll audit/ is OK when data root exists.
	if _, err := os.Stat(filepath.Clean(dir)); err != nil {
		return
	}
	sink, err := audit.NewFile(audit.FileConfig{Dir: auditDir})
	if err != nil {
		return
	}
	defer func() { _ = sink.Close() }()
	_ = audit.Emit(context.Background(), sink, e)
}
