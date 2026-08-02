package adminops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/admin"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
)

// Config wires process identity for admin MCP ops (secret-free).
type Config struct {
	// Role is the process admin console role (viewer|operator|policy_admin).
	Role Role
	// Version / Commit / BuildTime for health/version tools.
	Version   string
	Commit    string
	BuildTime string
	// ProfileStore lists/loads connection profiles (no credentials in results).
	ProfileStore *profile.Store
	// Paths is optional pre-resolved XDG paths; nil → config.Resolve().
	Paths *config.Paths
	// Metrics is optional process metrics (serve registry).
	Metrics *telemetry.Metrics
	// Audit is optional sink for write self-audit (AUD-001).
	Audit audit.Sink
	// Doctor runs offline/online doctor for a profile (optional; uses diagnostics).
	// When nil, Doctor builds diagnostics.RunDoctor from ProfileStore + Paths.
	Gate *policy.ReadOnlyGate
	// FlagReadOnly / AllowMutations for effective policy + doctor.
	FlagReadOnly   bool
	AllowMutations bool
	// Getenv for residual-status honesty; nil → os.Getenv.
	Getenv func(string) string
	// DefaultProfileID when tool omits profile_id (serve profile).
	DefaultProfileID string
}

// Service implements admin day-2 operations for MCP tools.
type Service struct {
	cfg Config
}

// New constructs a Service. Role defaults to viewer when empty.
func New(cfg Config) *Service {
	if strings.TrimSpace(string(cfg.Role)) == "" {
		cfg.Role = RoleViewer
	}
	if cfg.Getenv == nil {
		cfg.Getenv = os.Getenv
	}
	return &Service{cfg: cfg}
}

// Role returns the process role (secret-free).
func (s *Service) Role() Role {
	if s == nil {
		return RoleViewer
	}
	return s.cfg.Role
}

func (s *Service) getenv(k string) string {
	if s == nil || s.cfg.Getenv == nil {
		return os.Getenv(k)
	}
	return s.cfg.Getenv(k)
}

func (s *Service) resolvePaths() (config.Paths, error) {
	if s.cfg.Paths != nil {
		return *s.cfg.Paths, nil
	}
	return config.Resolve()
}

func (s *Service) emitWriteAudit(profileID, typ, action, decision, reason string) {
	if s == nil || s.cfg.Audit == nil {
		return
	}
	_ = audit.Emit(context.Background(), s.cfg.Audit, audit.Event{
		Time:       time.Now().UTC(),
		Type:       typ,
		ProfileID:  profileID,
		Action:     action,
		Decision:   decision,
		ReasonCode: reason,
	})
}

// --- Read results (secret-free) ---

// HealthResult mirrors admin GET /health honesty fields (subset, secret-free).
type HealthResult struct {
	Status           string   `json:"status"`
	Version          string   `json:"version,omitempty"`
	Commit           string   `json:"commit,omitempty"`
	EnabledModes     []string `json:"enabledModes,omitempty"`
	CredentialMode   string   `json:"credentialMode,omitempty"`
	MultiUserEnabled bool     `json:"multiUserEnabled"`
	GatewayReady     bool     `json:"gatewayReady"`
	HAMultiReplica   bool     `json:"haMultiReplica"`
	Residual         string   `json:"residual,omitempty"`
}

// VersionResult is secret-free build metadata.
type VersionResult struct {
	Version   string `json:"version,omitempty"`
	Commit    string `json:"commit,omitempty"`
	BuildTime string `json:"buildTime,omitempty"`
	GoVersion string `json:"goVersion,omitempty"`
	OS        string `json:"os,omitempty"`
	Arch      string `json:"arch,omitempty"`
}

// MeResult never includes the admin token value.
type MeResult struct {
	Authenticated   bool     `json:"authenticated"`
	Role            string   `json:"role"`
	Permissions     []string `json:"permissions"`
	TokenConfigured bool     `json:"tokenConfigured"`
	Residual        string   `json:"residual,omitempty"`
}

// ProfileSummary is secret-free (no credentials).
type ProfileSummary struct {
	ID            string `json:"id"`
	DisplayName   string `json:"displayName,omitempty"`
	JenkinsURL    string `json:"jenkinsURL,omitempty"`
	AuthMethod    string `json:"authMethod,omitempty"`
	Username      string `json:"username,omitempty"`
	ReadOnly      bool   `json:"readOnly"`
	HasCredential bool   `json:"hasCredential"`
}

// MetricsResult is process-local counters/gauges only.
type MetricsResult struct {
	Available bool             `json:"available"`
	Counters  map[string]int64 `json:"counters"`
	Gauges    map[string]int64 `json:"gauges"`
	Residual  string           `json:"residual,omitempty"`
}

// AuditListResult is a capped secret-free event page.
type AuditListResult struct {
	ProfileID string        `json:"profileId"`
	Events    []audit.Event `json:"events"`
	Truncated bool          `json:"truncated"`
}

// AuditSettingsResult mirrors type filter catalog.
type AuditSettingsResult struct {
	ProfileID string          `json:"profileId"`
	Types     []string        `json:"types"`
	Enabled   map[string]bool `json:"enabled"`
	PathNote  string          `json:"pathNote,omitempty"`
	Residual  string          `json:"residual,omitempty"`
}

// --- Health / version / me ---

// Health returns process health (always ok for local MCP process).
func (s *Service) Health(_ context.Context) (HealthResult, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return HealthResult{}, err
	}
	mode := string(gateway.CredentialModeFromEnviron(s.getenv))
	if !gateway.CredentialMode(mode).Valid() {
		mode = ""
	}
	modes, _ := gateway.ParseEnabledModes(s.getenv(gateway.EnvGatewayEnabledModes))
	modeStrs := make([]string, 0, len(modes))
	for _, m := range modes {
		modeStrs = append(modeStrs, string(m))
	}
	if len(modeStrs) == 0 && mode != "" {
		modeStrs = []string{mode}
	}
	return HealthResult{
		Status:           "ok",
		Version:          s.cfg.Version,
		Commit:           s.cfg.Commit,
		EnabledModes:     modeStrs,
		CredentialMode:   mode,
		MultiUserEnabled: gateway.MultiUserEnabled(s.getenv),
		GatewayReady:     false, // admin MCP ≠ live Ready probe
		HAMultiReplica:   false,
		Residual:         "admin mcp process health; gatewayReady always false here; multi-pod residual",
	}, nil
}

// Version returns build metadata.
func (s *Service) Version(_ context.Context) (VersionResult, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return VersionResult{}, err
	}
	return VersionResult{
		Version:   s.cfg.Version,
		Commit:    s.cfg.Commit,
		BuildTime: s.cfg.BuildTime,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}, nil
}

// Me returns role + permissions (never the token).
func (s *Service) Me(_ context.Context) (MeResult, error) {
	// Me is always allowed for authenticated MCP session; role still reported.
	role := s.Role()
	perms := role.Permissions()
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, string(p))
	}
	tok := strings.TrimSpace(s.getenv("JENKINS_MCP_ADMIN_TOKEN"))
	res := MeResult{
		Authenticated:   true,
		Role:            string(role),
		Permissions:     out,
		TokenConfigured: tok != "",
	}
	if !res.TokenConfigured {
		res.Residual = "admin token env not set (MCP ops use process role; pilot residual)"
	}
	return res, nil
}

// ResidualStatus returns diagnostics.BuildGatewayResidualStatus map.
func (s *Service) ResidualStatus(_ context.Context) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return nil, err
	}
	return diagnostics.BuildGatewayResidualStatus(s.getenv), nil
}

// Metrics returns process-local telemetry snapshot.
func (s *Service) Metrics(_ context.Context) (MetricsResult, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return MetricsResult{}, err
	}
	m := s.cfg.Metrics
	if m == nil {
		if reg := telemetry.Global(); reg != nil {
			m = reg.Metrics
		}
	}
	if m == nil {
		return MetricsResult{
			Available: false,
			Counters:  map[string]int64{},
			Gauges:    map[string]int64{},
			Residual:  "process-local snapshot; empty if no serve registry",
		}, nil
	}
	snap := m.Snapshot()
	if snap.Counters == nil {
		snap.Counters = map[string]int64{}
	}
	if snap.Gauges == nil {
		snap.Gauges = map[string]int64{}
	}
	return MetricsResult{
		Available: true,
		Counters:  snap.Counters,
		Gauges:    snap.Gauges,
		Residual:  "process-local snapshot; multi-pod aggregation residual",
	}, nil
}

func (s *Service) profileID(arg string) string {
	id := strings.TrimSpace(arg)
	if id == "" {
		id = strings.TrimSpace(s.cfg.DefaultProfileID)
	}
	return id
}

// ListProfiles returns secret-free profile summaries.
func (s *Service) ListProfiles(_ context.Context) ([]ProfileSummary, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return nil, err
	}
	if s.cfg.ProfileStore == nil {
		return nil, apperr.New(apperr.CodeCapabilityMissing, "profile store not configured")
	}
	ids, err := s.cfg.ProfileStore.List()
	if err != nil {
		return nil, err
	}
	out := make([]ProfileSummary, 0, len(ids))
	for _, id := range ids {
		sum, err := s.profileSummary(id)
		if err != nil {
			// Skip unreadable profiles (fail closed per id, continue list).
			continue
		}
		out = append(out, sum)
	}
	return out, nil
}

// GetProfile returns one secret-free profile summary.
func (s *Service) GetProfile(_ context.Context, profileID string) (ProfileSummary, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return ProfileSummary{}, err
	}
	id := s.profileID(profileID)
	if err := admin.ValidateProfileID(id); err != nil {
		return ProfileSummary{}, err
	}
	return s.profileSummary(id)
}

func (s *Service) profileSummary(id string) (ProfileSummary, error) {
	if s.cfg.ProfileStore == nil {
		return ProfileSummary{}, apperr.New(apperr.CodeCapabilityMissing, "profile store not configured")
	}
	p, err := s.cfg.ProfileStore.Load(id)
	if err != nil {
		return ProfileSummary{}, err
	}
	view := p.AuthView()
	return ProfileSummary{
		ID:            string(p.ID),
		DisplayName:   strings.TrimSpace(p.DisplayName),
		JenkinsURL:    strings.TrimSpace(p.JenkinsURL),
		AuthMethod:    string(p.AuthMethod),
		Username:      view.Username,
		ReadOnly:      p.EffectiveReadOnly(),
		HasCredential: strings.TrimSpace(view.Username) != "" || p.AuthMethod != "",
	}, nil
}

// PolicyEffective returns policy.ExplainEffective for a profile.
func (s *Service) PolicyEffective(_ context.Context, profileID string, readOnly, allowMutations bool) (policy.EffectivePolicyExplain, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return policy.EffectivePolicyExplain{}, err
	}
	id := s.profileID(profileID)
	if err := admin.ValidateProfileID(id); err != nil {
		return policy.EffectivePolicyExplain{}, err
	}
	var profileRO *bool
	if s.cfg.ProfileStore != nil {
		if p, err := s.cfg.ProfileStore.Load(id); err == nil && p != nil {
			v := p.EffectiveReadOnly()
			profileRO = &v
		}
	}
	polRes, err := policy.LoadFromEnviron()
	if err != nil {
		return policy.EffectivePolicyExplain{}, err
	}
	// Prefer explicit tool args; fall back to serve flags.
	roFlag := readOnly || s.cfg.FlagReadOnly
	allowMut := allowMutations || s.cfg.AllowMutations
	ro := policy.Inputs{
		FlagReadOnly:    roFlag,
		AllowMutations:  allowMut,
		ProfileReadOnly: profileRO,
		Force:           policy.AsEnterpriseForce(polRes.Overlay),
	}
	return policy.ExplainEffective(id, polRes, ro), nil
}

// Doctor runs diagnostics for a profile (offline default for MCP safety).
func (s *Service) Doctor(ctx context.Context, profileID string, offline bool) (diagnostics.Report, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return diagnostics.Report{}, err
	}
	id := s.profileID(profileID)
	if err := admin.ValidateProfileID(id); err != nil {
		return diagnostics.Report{}, err
	}
	if s.cfg.ProfileStore == nil {
		return diagnostics.Report{}, apperr.New(apperr.CodeCapabilityMissing, "profile store not configured")
	}
	p, err := s.cfg.ProfileStore.Load(id)
	if err != nil {
		return diagnostics.Report{}, err
	}
	paths, err := s.resolvePaths()
	if err != nil {
		return diagnostics.Report{}, err
	}
	polRes, _ := policy.LoadFromEnviron()
	polPtr := &polRes
	return diagnostics.RunDoctor(ctx, diagnostics.DoctorOptions{
		Profile:        p,
		Paths:          &paths,
		Version:        s.cfg.Version,
		Commit:         s.cfg.Commit,
		BuildTime:      s.cfg.BuildTime,
		SkipNetwork:    offline,
		PolicyResult:   polPtr,
		FlagReadOnly:   s.cfg.FlagReadOnly,
		AllowMutations: s.cfg.AllowMutations,
		Gate:           s.cfg.Gate,
		Metrics:        s.cfg.Metrics,
		Getenv:         s.getenv,
	})
}

// CacheStatus returns L1 cache summary for a profile.
func (s *Service) CacheStatus(ctx context.Context, profileID string) (diagnostics.CacheStatus, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return diagnostics.CacheStatus{}, err
	}
	id := s.profileID(profileID)
	if err := admin.ValidateProfileID(id); err != nil {
		return diagnostics.CacheStatus{}, err
	}
	if s.cfg.ProfileStore == nil {
		return diagnostics.CacheStatus{}, apperr.New(apperr.CodeCapabilityMissing, "profile store not configured")
	}
	p, err := s.cfg.ProfileStore.Load(id)
	if err != nil {
		return diagnostics.CacheStatus{}, err
	}
	paths, err := s.resolvePaths()
	if err != nil {
		return diagnostics.CacheStatus{}, err
	}
	return diagnostics.RunCacheStatus(ctx, diagnostics.CacheStatusOptions{
		Profile: p,
		Paths:   &paths,
	})
}

// SecuritySelfCheck runs offline security self-check for a profile.
func (s *Service) SecuritySelfCheck(ctx context.Context, profileID string) (diagnostics.SelfCheckReport, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return diagnostics.SelfCheckReport{}, err
	}
	id := s.profileID(profileID)
	if err := admin.ValidateProfileID(id); err != nil {
		return diagnostics.SelfCheckReport{}, err
	}
	var p *profile.Profile
	if s.cfg.ProfileStore != nil {
		p, _ = s.cfg.ProfileStore.Load(id)
	}
	paths, err := s.resolvePaths()
	if err != nil {
		return diagnostics.SelfCheckReport{}, err
	}
	return diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{
		Profile: p,
		Paths:   &paths,
		Getenv:  s.getenv,
	})
}

// AuditList reads profile audit JSONL (same-host merge via admin.ReadAuditFile).
func (s *Service) AuditList(_ context.Context, profileID string, limit int, typ, before, externalSubject string) (AuditListResult, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return AuditListResult{}, err
	}
	id := s.profileID(profileID)
	if err := admin.ValidateProfileID(id); err != nil {
		return AuditListResult{}, err
	}
	paths, err := s.resolvePaths()
	if err != nil {
		return AuditListResult{}, err
	}
	var dataOverride string
	if s.cfg.ProfileStore != nil {
		if p, err := s.cfg.ProfileStore.Load(id); err == nil && p != nil {
			dataOverride = strings.TrimSpace(p.DataDir)
		}
	}
	path, err := admin.ProfileAuditPath(paths, id, dataOverride)
	if err != nil {
		return AuditListResult{}, err
	}
	q := admin.AuditQuery{
		Limit:           limit,
		Type:            typ,
		ExternalSubject: externalSubject,
	}
	if strings.TrimSpace(before) != "" {
		t, perr := time.Parse(time.RFC3339, strings.TrimSpace(before))
		if perr != nil {
			return AuditListResult{}, apperr.New(apperr.CodeInvalidArgument, "before must be RFC3339")
		}
		q.Before = &t
	}
	page, err := admin.ReadAuditFile(path, id, q)
	if err != nil {
		return AuditListResult{}, err
	}
	if page.Events == nil {
		page.Events = []audit.Event{}
	}
	return AuditListResult{
		ProfileID: id,
		Events:    page.Events,
		Truncated: page.Truncated,
	}, nil
}

// AuditSettingsGet returns type catalog + enabled map.
func (s *Service) AuditSettingsGet(_ context.Context, profileID string) (AuditSettingsResult, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return AuditSettingsResult{}, err
	}
	id := s.profileID(profileID)
	if err := admin.ValidateProfileID(id); err != nil {
		return AuditSettingsResult{}, err
	}
	dataDir, err := s.profileDataDir(id)
	if err != nil {
		return AuditSettingsResult{}, err
	}
	f := audit.LoadTypeFilter(dataDir)
	return AuditSettingsResult{
		ProfileID: id,
		Types:     audit.KnownEventTypes(),
		Enabled:   f.EnabledMap(),
		PathNote:  "profile_data/audit/type_filter.json",
		Residual:  "type filter applies to File sink; multi-pod residual",
	}, nil
}

// AuditSettingsPut merges enabled map (gateway_ops).
func (s *Service) AuditSettingsPut(_ context.Context, profileID string, enabled map[string]bool) (AuditSettingsResult, error) {
	if err := RequirePermission(s.Role(), PermGatewayOps); err != nil {
		return AuditSettingsResult{}, err
	}
	id := s.profileID(profileID)
	if err := admin.ValidateProfileID(id); err != nil {
		return AuditSettingsResult{}, err
	}
	if enabled == nil {
		return AuditSettingsResult{}, apperr.New(apperr.CodeInvalidArgument, "enabled map required")
	}
	dataDir, err := s.profileDataDir(id)
	if err != nil {
		return AuditSettingsResult{}, err
	}
	cur := audit.LoadTypeFilter(dataDir).EnabledMap()
	for k, v := range enabled {
		if !audit.IsKnownEventType(k) {
			continue
		}
		cur[k] = v
	}
	next := audit.NormalizeEnabled(cur)
	if err := audit.SaveTypeFilter(dataDir, next); err != nil {
		s.emitWriteAudit(id, audit.TypeAuditSettings, "audit_type_filter", audit.DecisionFail, "save_failed")
		return AuditSettingsResult{}, apperr.New(apperr.CodeInternal, "failed to save audit settings")
	}
	s.emitWriteAudit(id, audit.TypeAuditSettings, "audit_type_filter", audit.DecisionSuccess, "type_filter_updated")
	return AuditSettingsResult{
		ProfileID: id,
		Types:     audit.KnownEventTypes(),
		Enabled:   next.EnabledMap(),
		PathNote:  "profile_data/audit/type_filter.json",
		Residual:  "File sink reloads on mtime+size; multi-pod residual",
	}, nil
}

func (s *Service) profileDataDir(profileID string) (string, error) {
	paths, err := s.resolvePaths()
	if err != nil {
		return "", err
	}
	var dataOverride string
	if s.cfg.ProfileStore != nil {
		if p, err := s.cfg.ProfileStore.Load(profileID); err == nil && p != nil {
			dataOverride = strings.TrimSpace(p.DataDir)
		}
	}
	auditJSONL, err := admin.ProfileAuditPath(paths, profileID, dataOverride)
	if err != nil {
		return "", err
	}
	// .../audit/audit.jsonl → profile data dir
	return filepath.Dir(filepath.Dir(auditJSONL)), nil
}

// SupportBundle creates or previews a support bundle (operator).
func (s *Service) SupportBundle(ctx context.Context, profileID string, preview bool) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermCacheDestructive); err != nil {
		return nil, err
	}
	id := s.profileID(profileID)
	if err := admin.ValidateProfileID(id); err != nil {
		return nil, err
	}
	if s.cfg.ProfileStore == nil {
		return nil, apperr.New(apperr.CodeCapabilityMissing, "profile store not configured")
	}
	p, err := s.cfg.ProfileStore.Load(id)
	if err != nil {
		return nil, err
	}
	paths, err := s.resolvePaths()
	if err != nil {
		return nil, err
	}
	polRes, _ := policy.LoadFromEnviron()
	polPtr := &polRes
	docOpts := diagnostics.DoctorOptions{
		Profile:        p,
		Paths:          &paths,
		Version:        s.cfg.Version,
		Commit:         s.cfg.Commit,
		BuildTime:      s.cfg.BuildTime,
		SkipNetwork:    true,
		PolicyResult:   polPtr,
		FlagReadOnly:   s.cfg.FlagReadOnly,
		AllowMutations: s.cfg.AllowMutations,
		Gate:           s.cfg.Gate,
		Metrics:        s.cfg.Metrics,
		Getenv:         s.getenv,
	}
	res, err := diagnostics.CreateSupportBundle(ctx, diagnostics.SupportBundleOptions{
		Profile:      p,
		Paths:        &paths,
		DoctorOpts:   docOpts,
		PolicyResult: polPtr,
		Version:      s.cfg.Version,
		Commit:       s.cfg.Commit,
		BuildTime:    s.cfg.BuildTime,
		PreviewOnly:  preview,
	})
	if !preview {
		dec := audit.DecisionSuccess
		if err != nil {
			dec = audit.DecisionFail
		}
		s.emitWriteAudit(id, audit.TypeAdminSupportBundle, "support_bundle_create", dec, "admin_mcp")
	}
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"profileId":  id,
		"preview":    preview,
		"path":       res.Path,
		"bytes":      res.Bytes,
		"included":   res.Plan.Included,
		"excluded":   res.Plan.Excluded,
		"outputPath": res.Plan.OutputPath,
		"categories": res.Categories,
	}
	return out, nil
}

// CacheEvictPlan returns a non-destructive eviction plan (read).
func (s *Service) CacheEvictPlan(ctx context.Context, profileID string, targetBytes int64) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return nil, err
	}
	return s.runEvict(ctx, profileID, targetBytes, false)
}

// CacheEvict applies eviction; confirm must be EVICT (operator).
func (s *Service) CacheEvict(ctx context.Context, profileID string, targetBytes int64, confirm string) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermCacheDestructive); err != nil {
		return nil, err
	}
	if strings.TrimSpace(confirm) != ConfirmEVICT {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"cache evict requires confirm="+ConfirmEVICT)
	}
	out, err := s.runEvict(ctx, profileID, targetBytes, true)
	dec := audit.DecisionSuccess
	if err != nil {
		dec = audit.DecisionFail
	}
	s.emitWriteAudit(s.profileID(profileID), audit.TypeAdminCacheEvict, "cache_evict", dec, "admin_mcp")
	return out, err
}

func (s *Service) runEvict(ctx context.Context, profileID string, targetBytes int64, apply bool) (map[string]any, error) {
	id := s.profileID(profileID)
	if err := admin.ValidateProfileID(id); err != nil {
		return nil, err
	}
	if s.cfg.ProfileStore == nil {
		return nil, apperr.New(apperr.CodeCapabilityMissing, "profile store not configured")
	}
	p, err := s.cfg.ProfileStore.Load(id)
	if err != nil {
		return nil, err
	}
	paths, err := s.resolvePaths()
	if err != nil {
		return nil, err
	}
	dataDir := strings.TrimSpace(p.DataDir)
	if dataDir == "" {
		dataDir = paths.ProfileDataDir(string(p.ID))
	}
	meta, err := store.Open(dataDir)
	if err != nil {
		return nil, err
	}
	defer meta.Close()
	qcfg, err := store.ResolveQuotaConfigFromEnviron(
		os.Getenv(store.EnvCacheTotalQuotaBytes),
		os.Getenv(store.EnvCacheLowDiskBytes),
	)
	if err != nil {
		return nil, err
	}
	qm, err := store.NewQuotaManager(meta, dataDir, qcfg)
	if err != nil {
		return nil, err
	}
	need, _, err := qm.NeedsEviction(ctx)
	if err != nil {
		return nil, err
	}
	plan, err := qm.PlanEviction(ctx, targetBytes)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"profileId":         id,
		"needsEviction":     need,
		"targetBytes":       targetBytes,
		"totalReclaimBytes": plan.TotalReclaimBytes,
		"plannedCount":      len(plan.Candidates),
		"apply":             apply,
	}
	if apply {
		er, err := qm.Evict(ctx, plan)
		if err != nil {
			return nil, err
		}
		out["evicted"] = er.Evicted
		out["reclaimedBytes"] = er.ReclaimedBytes
	}
	return out, nil
}

// SubjectInvalidate clears process principal cache for a subject (gateway_ops).
func (s *Service) SubjectInvalidate(_ context.Context, subjectKey, tenant, subjectID, profile, confirm string) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermGatewayOps); err != nil {
		return nil, err
	}
	// Confirm optional soft residual: require non-empty confirm for MCP writes.
	if strings.TrimSpace(confirm) == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "confirm string required (e.g. INVALIDATE)")
	}
	key := strings.TrimSpace(subjectKey)
	if key == "" {
		key = gateway.SubjectKeyParts(tenant, subjectID, profile)
	}
	if err := gateway.ValidateSubjectKey(key); err != nil {
		return nil, err
	}
	// Clear process principal cache only (force re-auth residual lite).
	err := gateway.ProcessPrincipalCache().Delete(key)
	cleared := err == nil
	s.emitWriteAudit(profile, audit.TypeAdminSubjectInvalid, "subject_invalidate", audit.DecisionSuccess, "admin_mcp")
	return map[string]any{
		"subjectKeyHash": audit.HashOpaque(key),
		"cleared":        cleared,
		"residual":       "process principal cache only; multi-pod fan-out residual; durable vault not deleted",
	}, nil
}

// ConsentPurge purges progressive consent metadata (gateway_ops).
func (s *Service) ConsentPurge(_ context.Context, action, sessionID, confirm string) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermGatewayOps); err != nil {
		return nil, err
	}
	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "expire", "purge_expired", "expired":
		// no confirm required for expire-only
	case "clear_all", "all":
		if strings.TrimSpace(confirm) != ConfirmCLEAR_ALL {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				"consent clear_all requires confirm="+ConfirmCLEAR_ALL)
		}
	case "session", "delete_session":
		if strings.TrimSpace(sessionID) == "" {
			return nil, apperr.New(apperr.CodeInvalidArgument, "session_id required for session purge")
		}
	default:
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"action must be expire|clear_all|session")
	}
	// Prefer durable consent store path when configured; else process memory store.
	var st gateway.ConsentSessionStore
	var err error
	if gateway.ConsentStorePathConfiguredFromEnviron(s.getenv) {
		st, err = gateway.OpenConsentSessionStoreForPurge("", s.getenv)
		if err != nil {
			return nil, err
		}
	} else {
		st = gateway.ProcessConsentSessionStore()
	}
	var n int
	switch action {
	case "expire", "purge_expired", "expired":
		n, err = st.PurgeExpired()
	case "clear_all", "all":
		err = st.Clear()
		if err == nil {
			// Count not available after Clear — report residual honesty.
			n = -1
		}
	case "session", "delete_session":
		err = st.Delete(sessionID)
		if err == nil {
			n = 1
		}
	}
	dec := audit.DecisionSuccess
	if err != nil {
		dec = audit.DecisionFail
	}
	s.emitWriteAudit("", audit.TypeAdminConsentPurge, "consent_purge", dec, "admin_mcp")
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"action":   action,
		"purged":   n,
		"residual": "metadata only; never tokens; multi-pod residual",
	}, nil
}

// VaultStatus returns Mode A vault inventory honesty (hash-only subjects).
func (s *Service) VaultStatus(ctx context.Context) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return nil, err
	}
	path := gateway.VaultPathFromEnviron(s.getenv)
	out := map[string]any{
		"mode":     string(gateway.CredentialModeAPITokenVault),
		"residual": "Mode A vault inventory; subject key hashes only; never tokens",
	}
	if strings.TrimSpace(s.getenv(gateway.EnvGatewayVaultPath)) == "" {
		out["configured"] = false
		out["shared_api_token_vault_file"] = false
		return out, nil
	}
	out["configured"] = true
	out["shared_api_token_vault_file"] = true
	v, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		out["error"] = "vault_open_failed"
		return out, nil // secret-free honesty
	}
	keys, err := v.ListSubjectKeys(ctx)
	if err != nil {
		out["error"] = "vault_list_failed"
		return out, nil
	}
	hashes := make([]string, 0, len(keys))
	for _, k := range keys {
		hashes = append(hashes, audit.HashOpaque(k))
	}
	out["subjectKeyHashes"] = hashes
	out["count"] = len(hashes)
	return out, nil
}

// PolicyOverlayGet returns plain overlay if available (secret-free).
func (s *Service) PolicyOverlayGet(_ context.Context) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return nil, err
	}
	polRes, err := policy.LoadFromEnviron()
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"available": polRes.Overlay != nil,
		"residual":  "signed bundle edit residual; plain overlay when present",
	}
	if polRes.Overlay != nil {
		out["overlay"] = polRes.Overlay
	}
	if polRes.SignatureState != "" {
		out["signature_state"] = polRes.SignatureState
	}
	return out, nil
}

// PolicyValidate dry-runs an overlay draft (policy_write).
func (s *Service) PolicyValidate(_ context.Context, overlay *policy.Overlay, profileID string) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermPolicyWrite); err != nil {
		return nil, err
	}
	if overlay == nil {
		// Role gate exercised; body residual for MCP schema round-trip.
		return map[string]any{
			"valid": false,
			"notes": []string{"overlay body required for full validate; role gate ok"},
			"errors": []map[string]string{{
				"field":   "overlay",
				"message": "overlay required",
			}},
		}, nil
	}
	if err := overlay.Validate(); err != nil {
		s.emitWriteAudit(profileID, audit.TypePolicyValidate, "policy_validate", audit.DecisionDeny, "invalid_overlay")
		return map[string]any{
			"valid":  false,
			"errors": []map[string]string{{"field": "overlay", "message": err.Error()}},
		}, nil
	}
	// Monotonic residual: cannot turn off force_read_only if enterprise force is on.
	polRes, loadErr := policy.LoadFromEnviron()
	if loadErr != nil {
		// Still allow structural validate of draft; note residual.
		polRes = policy.LoadResult{}
	}
	if polRes.Overlay != nil {
		if force, ok := policy.AsEnterpriseForce(polRes.Overlay).ForceReadOnly(); ok && force && !overlay.ForceReadOnly {
			s.emitWriteAudit(profileID, audit.TypePolicyValidate, "policy_validate", audit.DecisionDeny, "cannot_widen_force_ro")
			return map[string]any{
				"valid": false,
				"errors": []map[string]string{{
					"field":   "force_read_only",
					"message": "cannot disable enterprise force_read_only",
				}},
			}, nil
		}
	}
	s.emitWriteAudit(profileID, audit.TypePolicyValidate, "policy_validate", audit.DecisionSuccess, "ok")
	ex := policy.ExplainEffective(s.profileID(profileID), polRes, policy.Inputs{
		FlagReadOnly:   s.cfg.FlagReadOnly,
		AllowMutations: s.cfg.AllowMutations,
		Force:          policy.AsEnterpriseForce(overlay),
	})
	notes := []string{"validate only; apply requires confirm=APPLY"}
	if loadErr != nil {
		notes = append(notes, "process policy load residual: draft validated structurally only")
	}
	return map[string]any{
		"valid":            true,
		"effectivePreview": ex,
		"notes":            notes,
	}, nil
}

// PolicyApply is residual for durable write via MCP: validates + requires
// confirm=APPLY but does not rewrite signed enterprise bundles. Plain overlay
// path residual documented when not available.
func (s *Service) PolicyApply(_ context.Context, overlay *policy.Overlay, profileID, confirm string) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermPolicyWrite); err != nil {
		return nil, err
	}
	if strings.TrimSpace(confirm) != ConfirmAPPLY {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"policy apply requires confirm="+ConfirmAPPLY)
	}
	v, err := s.PolicyValidate(context.Background(), overlay, profileID)
	if err != nil {
		return nil, err
	}
	if valid, _ := v["valid"].(bool); !valid {
		s.emitWriteAudit(profileID, audit.TypePolicyApply, "policy_apply", audit.DecisionDeny, "validate_failed")
		return map[string]any{
			"applied": false,
			"errors":  v["errors"],
		}, nil
	}
	// Durable apply of plain overlay files is residual when only signed enterprise
	// policy is configured — do not invent a write path that bypasses signing.
	s.emitWriteAudit(profileID, audit.TypePolicyApply, "policy_apply", audit.DecisionFail, "apply_path_residual")
	return map[string]any{
		"applied":  false,
		"residual": "durable policy apply via MCP residual when signed enterprise bundles are in use; use admin BFF policy apply or CLI with keys-dir; validate path Done*",
		"valid":    true,
	}, nil
}

// ToolCatalog lists registered admin_* tool names for parity tests (MCP-OPS-006).
func ToolCatalog() []string {
	return []string{
		"admin_health",
		"admin_version",
		"admin_me",
		"admin_gateway_residual_status",
		"admin_list_profiles",
		"admin_get_profile",
		"admin_policy_effective",
		"admin_policy_overlay_get",
		"admin_policy_validate",
		"admin_policy_apply",
		"admin_metrics",
		"admin_audit_list",
		"admin_audit_settings_get",
		"admin_audit_settings_put",
		"admin_doctor",
		"admin_security_selfcheck",
		"admin_cache_status",
		"admin_cache_evict_plan",
		"admin_cache_evict",
		"admin_support_bundle",
		"admin_gateway_vault_status",
		"admin_subject_invalidate",
		"admin_consent_purge",
		"admin_rbac_list_bindings",
		"admin_rbac_put_binding",
		"admin_rbac_delete_binding",
		// Residual until POL-007 MCP:
		// "admin_saml_status", "admin_saml_config_get",
	}
}

// ResidualTools documents tools not yet implemented (matrix honesty).
func ResidualTools() map[string]string {
	return map[string]string{
		"admin_saml_status":     "POL-007 residual",
		"admin_saml_config_get": "POL-007 residual",
	}
}

// RbacListBindings returns user/group deny bindings from process policy (UI-011 / POL-006).
// Secret-free; never tokens. Multi-fleet SoT remains signed config.
func (s *Service) RbacListBindings(_ context.Context) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return nil, err
	}
	out := map[string]any{
		"fleet_sot": "configuration/signed policy (MGR-001); SPA/MCP is pilot break-glass only",
		"users":     []any{},
		"groups":    []any{},
	}
	res, err := policy.LoadFromEnviron()
	if err != nil {
		out["available"] = false
		out["residual"] = "policy load residual: " + err.Error()
		// Do not leak paths/keys
		if len(out["residual"].(string)) > 200 {
			out["residual"] = "policy load residual (fail closed)"
		}
		return out, nil
	}
	if res.Overlay == nil {
		out["available"] = false
		out["residual"] = "no overlay loaded"
		return out, nil
	}
	out["available"] = true
	out["signature_state"] = res.SignatureState
	if res.Overlay.Subjects != nil {
		out["users"] = res.Overlay.Subjects.Users
		out["groups"] = res.Overlay.Subjects.Groups
	}
	return out, nil
}

// RbacPutBindings replaces subjects on plain overlay when plain write allowed.
// Requires policy_write. Same multi-fleet refuse path as BFF PlainApplyBlocked
// (REQUIRE_SIGNED, trusted keys, signed bundle path).
func (s *Service) RbacPutBindings(ctx context.Context, users []policy.UserBinding, groups []policy.GroupBinding, profileID, confirm string) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermPolicyWrite); err != nil {
		return nil, err
	}
	if strings.TrimSpace(confirm) != "APPLY" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "rbac put requires confirm=APPLY")
	}
	subjects := &policy.SubjectBindings{Users: users, Groups: groups}
	if err := subjects.Validate(); err != nil {
		return nil, err
	}
	paths, err := s.resolvePaths()
	if err != nil {
		s.emitWriteAudit(profileID, audit.TypePolicyApply, "rbac_put", audit.DecisionSuccess, "validated_memory_only")
		return map[string]any{
			"applied":  false,
			"valid":    true,
			"users":    users,
			"groups":   groups,
			"residual": "paths unavailable; bindings validated only (no durable write)",
		}, nil
	}
	// BFF/MCP parity: refuse plain write on multi-fleet signed paths.
	if blocked, msg := admin.PlainApplyBlocked(paths); blocked {
		s.emitWriteAudit(profileID, audit.TypePolicyApply, "rbac_put", audit.DecisionDeny, "plain_apply_blocked")
		return nil, apperr.New(apperr.CodeAuthorization, msg)
	}
	// Build overlay via LoadFromEnviron or empty pilot shell
	res, _ := policy.LoadFromEnviron()
	var base *policy.Overlay
	if res.Overlay != nil {
		cp := *res.Overlay
		base = &cp
	} else {
		base = &policy.Overlay{Version: 1, Mode: policy.ModePilot, ForceReadOnly: true}
	}
	base.Subjects = subjects
	if err := base.Validate(); err != nil {
		return nil, err
	}
	outPath := paths.DefaultPolicyFile()
	if envPath := strings.TrimSpace(os.Getenv(policy.EnvPolicyFileVar)); envPath != "" && !strings.HasSuffix(strings.ToLower(envPath), ".bundle.json") {
		outPath = envPath
	}
	raw, err := json.MarshalIndent(base, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "policy dir", err)
	}
	if err := os.WriteFile(outPath, raw, 0o600); err != nil {
		s.emitWriteAudit(profileID, audit.TypePolicyApply, "rbac_put", audit.DecisionDeny, "write_failed")
		return nil, apperr.Wrap(apperr.CodeInternal, "write policy overlay", err)
	}
	s.emitWriteAudit(profileID, audit.TypePolicyApply, "rbac_put", audit.DecisionSuccess, "applied")
	return map[string]any{
		"applied":   true,
		"path_base": filepath.Base(outPath),
		"users":     users,
		"groups":    groups,
		"notes":     []string{"plain pilot overlay subjects written; multi-fleet production uses signed bundles"},
	}, nil
}

// RbacDeleteBinding removes one user or group binding by id (confirm=DELETE).
func (s *Service) RbacDeleteBinding(ctx context.Context, kind, id, profileID, confirm string) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermPolicyWrite); err != nil {
		return nil, err
	}
	if strings.TrimSpace(confirm) != "DELETE" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "rbac delete requires confirm=DELETE")
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	id = strings.TrimSpace(id)
	if id == "" || (kind != "user" && kind != "group") {
		return nil, apperr.New(apperr.CodeInvalidArgument, "kind must be user|group and id required")
	}
	list, err := s.RbacListBindings(ctx)
	if err != nil {
		return nil, err
	}
	users, _ := list["users"].([]policy.UserBinding)
	// users may be []any from map - re-load overlay
	res, _ := policy.LoadFromEnviron()
	var base *policy.Overlay
	if res.Overlay != nil {
		cp := *res.Overlay
		base = &cp
	} else {
		return map[string]any{"deleted": false, "residual": "no overlay"}, nil
	}
	if base.Subjects == nil {
		return map[string]any{"deleted": false, "residual": "no subjects"}, nil
	}
	switch kind {
	case "user":
		next := make([]policy.UserBinding, 0, len(base.Subjects.Users))
		for _, u := range base.Subjects.Users {
			if !strings.EqualFold(u.JenkinsUserID, id) && u.ExternalSubject != id {
				next = append(next, u)
			}
		}
		base.Subjects.Users = next
	case "group":
		next := make([]policy.GroupBinding, 0, len(base.Subjects.Groups))
		for _, g := range base.Subjects.Groups {
			if g.GroupID != id {
				next = append(next, g)
			}
		}
		base.Subjects.Groups = next
	}
	_ = users
	return s.RbacPutBindings(ctx, base.Subjects.Users, base.Subjects.Groups, profileID, "APPLY")
}
