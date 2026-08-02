package policy

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultReloadMinInterval is the minimum time between source mtime checks
// during Evaluate (Wave 24 hot-reload). Avoids Stat spam under high call rates.
const DefaultReloadMinInterval = 5 * time.Second

// LoadFunc reloads enterprise policy (plain overlay or signed bundle).
// Used by ReloadableDenyOnly for mid-session updates. Must be secret-free in
// errors (no key material / signature bytes).
type LoadFunc func() (LoadResult, error)

// ReloadInfo is a secret-free summary emitted after a successful reload.
// Never includes signature bytes, key material, or path secrets beyond basename.
type ReloadInfo struct {
	// DenyToolsCount is len(overlay.deny_tools).
	DenyToolsCount int
	// DenyJobPrefixesCount is len(overlay.deny_job_prefixes).
	DenyJobPrefixesCount int
	// DenyNodeNamesCount is len(overlay.deny_node_names) (Wave 35).
	DenyNodeNamesCount int
	// DenyViewNamesCount is len(overlay.deny_view_names) (Wave 35).
	DenyViewNamesCount int
	// DenyArtifactPathsCount is len(overlay.deny_artifact_paths) (Wave 36).
	DenyArtifactPathsCount int
	// DenyBranchNamesCount is len(overlay.deny_branch_names) (Wave 37).
	DenyBranchNamesCount int
	// BundleSeq is the verified envelope sequence (0 for plain overlay).
	BundleSeq int64
	// SignatureState is a status token (verified, unverified_pilot, …).
	SignatureState string
	// Mode is pilot or strict.
	Mode string
	// ForceReadOnly mirrors overlay.force_read_only (Wave 25: hot-applied via DynamicForce).
	ForceReadOnly bool
	// FleetTelemetryForceOff mirrors overlay.fleet_telemetry_force_off (MGR-002).
	// Serve OnSuccess may apply Collector.SetForceOff (env cannot re-enable while true).
	FleetTelemetryForceOff bool
	// MaxResultBytes is overlay max_result_bytes when set and positive (0 = unset).
	// Wave 25/31: serve OnSuccess may SetWithinCeiling on tools.LiveHardMax.
	MaxResultBytes int
	// MaxToolsPerMinute is overlay max_tools_per_minute when set and positive (0 = unset).
	// HOST-006: serve OnSuccess may gateway.SubjectRateLimiter.LowerRate (lower only).
	MaxToolsPerMinute int
	// MaxToolsBurst is overlay max_tools_burst when set and positive (0 = unset).
	MaxToolsBurst int
	// Version is the overlay schema version.
	Version int
	// PathBase is filepath.Base of the policy path (model/log safe).
	PathBase string
	// ContentHash is non-secret sha256 of signing payload when verified.
	ContentHash string
}

// ReloadableConfig configures mid-session policy hot-reload (Wave 24).
type ReloadableConfig struct {
	// Load re-reads the policy source. Required for Reload / MaybeReload.
	// Typically policy.LoadFromEnviron or a LoadOverlay closure with fixed opts.
	Load LoadFunc
	// Path is the policy file path used for mtime/size change detection.
	// Empty ⇒ MaybeReload always attempts Load when the min interval elapses
	// (no cheap Stat short-circuit).
	Path string
	// MinInterval between source checks on Evaluate (default 5s). Zero uses default.
	// Negative disables interval throttling (tests).
	MinInterval time.Duration
	// Now is an optional clock (tests). Nil ⇒ time.Now.
	Now func() time.Time
	// OnSuccess is called after a successful evaluator swap (logging). Optional.
	// Must not log secrets; ReloadInfo is already secret-free.
	OnSuccess func(ReloadInfo)
	// OnError is called when a reload attempt fails and last-good is retained. Optional.
	OnError func(error)
}

// reloadSnapshot is an immutable generation of the deny-only evaluator.
type reloadSnapshot struct {
	eval                   *DenyOnlyEvaluator
	mtime                  time.Time
	size                   int64
	hasFileMeta            bool
	bundleSeq              int64
	contentHash            string
	signatureState         string
	denyTools              int
	denyJobPrefs           int
	denyNodeNames          int
	denyViewNames          int
	denyArtPaths           int
	denyBranchNms          int
	mode                   PolicyMode
	forceRO                bool
	fleetTelemetryForceOff bool
	maxResultBytes         int
	maxToolsPerMinute      int
	maxToolsBurst          int
	version                int
	pathBase               string
}

// ReloadableDenyOnly is a thread-safe PolicyEvaluator that can hot-reload the
// underlying deny-only document when the overlay/bundle file changes.
//
// Fail-closed behavior:
//   - Load error (corrupt JSON, signature fail, downgrade, I/O) → keep last-good.
//   - Successful load with Overlay==nil (file absent) → keep last-good when one
//     exists (do not silently open access mid-session by deleting the file).
//   - Never successfully loaded → Evaluate denies (ReasonNoEvaluator).
//
// Residuals (not hot-reloaded until process restart):
//   - Raising max_result_bytes above the serve-bootstrap LiveHardMax ceiling
//   - Raising max_tools_per_minute / max_tools_burst above serve-bootstrap rate
//     (HOST-006 LowerRate is lower-only; raise needs restart with higher env)
//   - Mutation tools omitted without AllowMutations stay unregistered for the process
//
// Hot-applied on successful reload (Wave 24/25/28/30/31/35/36/37 + HOST-006 + MGR-002, via serve OnSuccess + live holders):
//   - deny_tools / deny_job_prefixes / deny_node_names / deny_view_names /
//     deny_artifact_paths / deny_branch_names / mode (this evaluator; ListTools live filter Wave 28)
//   - force_read_only → DynamicForce.Set (dispatch + ListTools mutation visibility)
//   - fleet_telemetry_force_off → fleet.Collector.SetForceOff (env cannot re-enable while true)
//   - max_result_bytes → tools.LiveHardMax.SetWithinCeiling (raise/lower ≤ ceiling)
//   - max_tools_per_minute / max_tools_burst → SubjectRateLimiter.LowerRate (lower only)
//   - AllowMutations + force clear re-lists mutations when registered under opt-in (Wave 30)
type ReloadableDenyOnly struct {
	cfg     ReloadableConfig
	current atomic.Pointer[reloadSnapshot]

	mu        sync.Mutex
	lastCheck time.Time
}

// NewReloadableDenyOnly builds a reloader with no snapshot yet (deny until Seed/Reload).
func NewReloadableDenyOnly(cfg ReloadableConfig) *ReloadableDenyOnly {
	return &ReloadableDenyOnly{cfg: cfg}
}

// NewReloadableFromLoadResult seeds the reloader with an already-loaded result
// (serve path after LoadFromEnviron) without a second disk read for the body.
// Path for mtime tracking comes from cfg.Path, else res.Path.
func NewReloadableFromLoadResult(res LoadResult, cfg ReloadableConfig) *ReloadableDenyOnly {
	r := NewReloadableDenyOnly(cfg)
	if cfg.Path == "" && res.Path != "" {
		r.cfg.Path = res.Path
	}
	_ = r.seedFromResult(res)
	return r
}

// Seed installs an initial LoadResult as last-good without invoking Load.
// Overlay==nil leaves the reloader empty (deny-all until a successful Reload).
func (r *ReloadableDenyOnly) Seed(res LoadResult) {
	if r == nil {
		return
	}
	_ = r.seedFromResult(res)
}

func (r *ReloadableDenyOnly) seedFromResult(res LoadResult) error {
	if res.Overlay == nil {
		return nil
	}
	path := r.cfg.Path
	if path == "" {
		path = res.Path
	}
	snap := snapshotFromResult(res, path)
	// Best-effort file meta for mtime short-circuit.
	if path != "" {
		if fi, err := os.Stat(path); err == nil {
			snap.mtime = fi.ModTime()
			snap.size = fi.Size()
			snap.hasFileMeta = true
		}
	}
	r.current.Store(snap)
	return nil
}

// Evaluate implements PolicyEvaluator. May trigger a throttled reload check.
func (r *ReloadableDenyOnly) Evaluate(subject Subject, action Action, target Target) Decision {
	if r == nil {
		return Decision{
			Effect:      EffectDeny,
			ReasonCode:  ReasonNoEvaluator,
			Explanation: "MCP policy evaluator is not configured (fail closed)",
		}
	}
	r.MaybeReload(r.now())
	snap := r.current.Load()
	if snap == nil || snap.eval == nil {
		return Decision{
			Effect:      EffectDeny,
			ReasonCode:  ReasonNoEvaluator,
			Explanation: "MCP policy evaluator is not configured (fail closed)",
		}
	}
	return snap.eval.Evaluate(subject, action, target)
}

// Document returns a copy of the current document (empty pilot if none).
func (r *ReloadableDenyOnly) Document() Document {
	if r == nil {
		return Document{Mode: ModePilot}
	}
	snap := r.current.Load()
	if snap == nil || snap.eval == nil {
		return Document{Mode: ModePilot}
	}
	return snap.eval.Document()
}

// EffectiveDocument returns the most-restrictive document for subject (POL-006).
// Merges matching user/group bindings from the current snapshot.
func (r *ReloadableDenyOnly) EffectiveDocument(subject Subject) Document {
	if r == nil {
		return Document{Mode: ModePilot}
	}
	r.MaybeReload(r.now())
	snap := r.current.Load()
	if snap == nil || snap.eval == nil {
		return Document{Mode: ModePilot}
	}
	return snap.eval.EffectiveDocument(subject)
}

// BundleSeq returns the current verified bundle sequence (0 if plain/none).
func (r *ReloadableDenyOnly) BundleSeq() int64 {
	if r == nil {
		return 0
	}
	snap := r.current.Load()
	if snap == nil {
		return 0
	}
	return snap.bundleSeq
}

// HasSnapshot reports whether a last-good evaluator is installed.
func (r *ReloadableDenyOnly) HasSnapshot() bool {
	if r == nil {
		return false
	}
	snap := r.current.Load()
	return snap != nil && snap.eval != nil
}

// Reload forces a load attempt ignoring mtime and min-interval (tests / operators).
// On error or absent overlay when a snapshot exists, last-good is retained.
func (r *ReloadableDenyOnly) Reload() error {
	if r == nil {
		return fmt.Errorf("reloadable policy is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastCheck = r.now()
	return r.reloadLocked()
}

// MaybeReload checks the source when min-interval has elapsed and reloads only
// when path mtime/size changed (or Path is empty). Safe under concurrent Evaluate.
func (r *ReloadableDenyOnly) MaybeReload(now time.Time) {
	if r == nil {
		return
	}
	if now.IsZero() {
		now = r.now()
	}
	min := r.cfg.MinInterval
	if min == 0 {
		min = DefaultReloadMinInterval
	}
	// Negative MinInterval: no throttle (tests).

	r.mu.Lock()
	defer r.mu.Unlock()
	if min > 0 && !r.lastCheck.IsZero() && now.Sub(r.lastCheck) < min {
		return
	}
	r.lastCheck = now

	if r.cfg.Path != "" && !r.sourceChangedLocked() {
		return
	}
	_ = r.reloadLocked()
}

func (r *ReloadableDenyOnly) now() time.Time {
	if r.cfg.Now != nil {
		return r.cfg.Now()
	}
	return time.Now()
}

func (r *ReloadableDenyOnly) sourceChangedLocked() bool {
	path := r.cfg.Path
	if path == "" {
		return true
	}
	fi, err := os.Stat(path)
	snap := r.current.Load()
	if err != nil {
		// Missing or unreadable: treat as change so Reload can keep last-good.
		return true
	}
	if snap == nil || !snap.hasFileMeta {
		return true
	}
	if !fi.ModTime().Equal(snap.mtime) || fi.Size() != snap.size {
		return true
	}
	return false
}

// reloadLocked must run under r.mu.
func (r *ReloadableDenyOnly) reloadLocked() error {
	if r.cfg.Load == nil {
		err := fmt.Errorf("policy reload: LoadFunc is nil")
		r.emitError(err)
		return err
	}
	res, err := r.cfg.Load()
	if err != nil {
		r.emitError(err)
		return err
	}
	if res.Overlay == nil {
		// Absent file: keep last-good (fail closed; do not open access mid-session).
		if r.current.Load() != nil {
			err := fmt.Errorf("policy reload: source absent or empty; keeping last-good")
			r.emitError(err)
			return err
		}
		return nil
	}

	path := r.cfg.Path
	if path == "" {
		path = res.Path
	}
	snap := snapshotFromResult(res, path)
	if path != "" {
		if fi, err := os.Stat(path); err == nil {
			snap.mtime = fi.ModTime()
			snap.size = fi.Size()
			snap.hasFileMeta = true
		}
	}

	// Skip no-op swap when content is identical (same hash/seq/deny set fingerprint).
	if prev := r.current.Load(); prev != nil && samePolicyGeneration(prev, snap) {
		// Still refresh file meta so mtime-only touch does not re-log forever.
		r.current.Store(snap)
		return nil
	}

	r.current.Store(snap)
	if r.cfg.OnSuccess != nil {
		r.cfg.OnSuccess(ReloadInfo{
			DenyToolsCount:         snap.denyTools,
			DenyJobPrefixesCount:   snap.denyJobPrefs,
			DenyNodeNamesCount:     snap.denyNodeNames,
			DenyViewNamesCount:     snap.denyViewNames,
			DenyArtifactPathsCount: snap.denyArtPaths,
			DenyBranchNamesCount:   snap.denyBranchNms,
			BundleSeq:              snap.bundleSeq,
			SignatureState:         snap.signatureState,
			Mode:                   string(snap.mode),
			ForceReadOnly:          snap.forceRO,
			FleetTelemetryForceOff: snap.fleetTelemetryForceOff,
			MaxResultBytes:         snap.maxResultBytes,
			MaxToolsPerMinute:      snap.maxToolsPerMinute,
			MaxToolsBurst:          snap.maxToolsBurst,
			Version:                snap.version,
			PathBase:               snap.pathBase,
			ContentHash:            snap.contentHash,
		})
	}
	return nil
}

func (r *ReloadableDenyOnly) emitError(err error) {
	if r.cfg.OnError != nil && err != nil {
		r.cfg.OnError(err)
	}
}

func snapshotFromResult(res LoadResult, path string) *reloadSnapshot {
	ov := res.Overlay
	eval := NewDenyOnlyFromOverlay(ov)
	snap := &reloadSnapshot{
		eval:                   eval,
		bundleSeq:              res.BundleSeq,
		contentHash:            res.ContentHash,
		signatureState:         res.SignatureState,
		mode:                   ov.NormalizeMode(),
		forceRO:                ov.ForceReadOnly,
		fleetTelemetryForceOff: ov.FleetTelemetryForceOff,
		version:                ov.Version,
		pathBase:               sanitizePath(path),
	}
	if n, ok := ov.EffectiveMaxResultBytes(); ok {
		snap.maxResultBytes = n
	}
	if n, ok := ov.EffectiveMaxToolsPerMinute(); ok {
		snap.maxToolsPerMinute = n
	}
	if n, ok := ov.EffectiveMaxToolsBurst(); ok {
		snap.maxToolsBurst = n
	}
	if ov.DenyTools != nil {
		snap.denyTools = len(ov.DenyTools)
	}
	if ov.DenyJobPrefixes != nil {
		snap.denyJobPrefs = len(ov.DenyJobPrefixes)
	}
	if ov.DenyNodeNames != nil {
		snap.denyNodeNames = len(ov.DenyNodeNames)
	}
	if ov.DenyViewNames != nil {
		snap.denyViewNames = len(ov.DenyViewNames)
	}
	if ov.DenyArtifactPaths != nil {
		snap.denyArtPaths = len(ov.DenyArtifactPaths)
	}
	if ov.DenyBranchNames != nil {
		snap.denyBranchNms = len(ov.DenyBranchNames)
	}
	return snap
}

func samePolicyGeneration(a, b *reloadSnapshot) bool {
	if a == nil || b == nil {
		return false
	}
	if a.bundleSeq != b.bundleSeq || a.contentHash != b.contentHash {
		return false
	}
	if a.signatureState != b.signatureState || a.mode != b.mode || a.forceRO != b.forceRO ||
		a.fleetTelemetryForceOff != b.fleetTelemetryForceOff {
		return false
	}
	if a.denyTools != b.denyTools || a.denyJobPrefs != b.denyJobPrefs ||
		a.denyNodeNames != b.denyNodeNames || a.denyViewNames != b.denyViewNames ||
		a.denyArtPaths != b.denyArtPaths || a.denyBranchNms != b.denyBranchNms ||
		a.version != b.version {
		return false
	}
	// Deep compare deny sets via document fields when counts match.
	da, db := a.eval.Document(), b.eval.Document()
	if da.ForceReadOnly != db.ForceReadOnly || da.FleetTelemetryForceOff != db.FleetTelemetryForceOff ||
		da.Mode != db.Mode || da.MaxResultBytes != db.MaxResultBytes ||
		da.MaxToolsPerMinute != db.MaxToolsPerMinute || da.MaxToolsBurst != db.MaxToolsBurst {
		return false
	}
	if len(da.DenyTools) != len(db.DenyTools) {
		return false
	}
	for k := range da.DenyTools {
		if _, ok := db.DenyTools[k]; !ok {
			return false
		}
	}
	if len(da.DenyJobPrefixes) != len(db.DenyJobPrefixes) {
		return false
	}
	for i := range da.DenyJobPrefixes {
		if da.DenyJobPrefixes[i] != db.DenyJobPrefixes[i] {
			return false
		}
	}
	if len(da.DenyNodeNames) != len(db.DenyNodeNames) {
		return false
	}
	for i := range da.DenyNodeNames {
		if da.DenyNodeNames[i] != db.DenyNodeNames[i] {
			return false
		}
	}
	if len(da.DenyViewNames) != len(db.DenyViewNames) {
		return false
	}
	for i := range da.DenyViewNames {
		if da.DenyViewNames[i] != db.DenyViewNames[i] {
			return false
		}
	}
	if len(da.DenyArtifactPaths) != len(db.DenyArtifactPaths) {
		return false
	}
	for i := range da.DenyArtifactPaths {
		if da.DenyArtifactPaths[i] != db.DenyArtifactPaths[i] {
			return false
		}
	}
	if len(da.DenyBranchNames) != len(db.DenyBranchNames) {
		return false
	}
	for i := range da.DenyBranchNames {
		if da.DenyBranchNames[i] != db.DenyBranchNames[i] {
			return false
		}
	}
	return true
}
