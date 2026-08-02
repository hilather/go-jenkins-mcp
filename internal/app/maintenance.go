package app

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/archive"
	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
)

// Default maintenance intervals and packing bounds (ARC-007 / ARC-005 residual).
const (
	// DefaultMaintenanceInterval is the serve-time tick interval when flag/env unset.
	DefaultMaintenanceInterval = 5 * time.Minute
	// MinMaintenanceInterval is the shortest allowed operator tick interval.
	// Below this, serve start fails closed (ARC-007 Wave 49 Track C).
	MinMaintenanceInterval = 30 * time.Second
	// AbsoluteMaxMaintenanceInterval is the longest allowed operator tick interval.
	// Multi-day / absurd values fail closed at serve start (ARC-007 Wave 49 Track C).
	AbsoluteMaxMaintenanceInterval = 1 * time.Hour

	DefaultMaxPacksPerTick   = 2
	DefaultMaxMembersPerPack = 8
	DefaultMinSealedMembers  = 2
	DefaultForcePackAfter    = 24 * time.Hour
	// DefaultCompactionHeadroomFrac: skip L1→L2 when free quota fraction exceeds this
	// (usage well under quota). Packing grows disk until L1 release.
	DefaultCompactionHeadroomFrac = 0.25
	// DefaultReleaseMinAge: wait this long after packed_at before releasing L1
	// unless under high disk pressure or ReleaseAfterPack is set.
	DefaultReleaseMinAge = time.Hour
	// DefaultMaxReleasesPerTick caps L1 releases per maintenance tick.
	DefaultMaxReleasesPerTick = 8
	// DefaultReleasePressureHeadroomFrac: free/quota at or below this ⇒ high pressure
	// (release packed L1 immediately after verify, ignoring age).
	DefaultReleasePressureHeadroomFrac = 0.10
)

// EnvCacheMaintenanceInterval is the serve env for the maintenance tick interval.
// CLI --cache-maintenance-interval overrides when set. Empty → DefaultMaintenanceInterval.
// Resolve with ResolveMaintenanceInterval (min 30s, absolute max 1h fail-closed).
const EnvCacheMaintenanceInterval = "JENKINS_MCP_CACHE_MAINTENANCE_INTERVAL"

// MaintenanceConfig configures the serve-time cache maintenance worker.
type MaintenanceConfig struct {
	// Interval between ticks (0 ⇒ DefaultMaintenanceInterval).
	Interval time.Duration
	// EnableEviction runs RecoverEvictJournal + Plan/Evict when over quota (default true).
	EnableEviction bool
	// EnableCompaction runs optional L1→L2 packing of sealed unpinned gens (default true).
	EnableCompaction bool
	// EnableL1Release runs release journal recover + optional L1 purge after verified
	// L2 pack (default true with DefaultMaintenanceConfig).
	EnableL1Release bool
	// ReleaseAfterPack releases L1 immediately after successful pack mark (tests /
	// aggressive reclaim). When false, uses age and/or high disk pressure.
	ReleaseAfterPack bool
	// ReleaseMinAge is minimum time since packed_at before release when not under
	// pressure (0 ⇒ DefaultReleaseMinAge). Ignored when ReleaseAfterPack is true.
	ReleaseMinAge time.Duration
	// MaxReleasesPerTick caps L1 releases per tick (0 ⇒ DefaultMaxReleasesPerTick).
	MaxReleasesPerTick int
	// ReleasePressureHeadroomFrac: free/quota ≤ this triggers pressure-based release
	// of any verified packed gen (0 ⇒ default 0.10).
	ReleasePressureHeadroomFrac float64
	// MaxPacksPerTick caps packs published per tick (0 ⇒ DefaultMaxPacksPerTick).
	MaxPacksPerTick int
	// MaxMembersPerPack caps members per pack (0 ⇒ DefaultMaxMembersPerPack).
	MaxMembersPerPack int
	// MinSealedMembers requires this many candidates before packing unless force-aged
	// (0 ⇒ DefaultMinSealedMembers).
	MinSealedMembers int
	// ForcePackAfter packs even a single sealed gen after this age (0 ⇒ DefaultForcePackAfter).
	ForcePackAfter time.Duration
	// CompactionHeadroomFrac skips compaction when free/quota > this (0 ⇒ default 0.25).
	// Values outside (0,1) are clamped.
	CompactionHeadroomFrac float64
	// Now optional clock for tests.
	Now func() time.Time
}

// EffectiveInterval returns the configured or default tick interval.
func (c MaintenanceConfig) EffectiveInterval() time.Duration {
	if c.Interval > 0 {
		return c.Interval
	}
	return DefaultMaintenanceInterval
}

func (c MaintenanceConfig) effectiveMaxPacks() int {
	if c.MaxPacksPerTick > 0 {
		return c.MaxPacksPerTick
	}
	return DefaultMaxPacksPerTick
}

func (c MaintenanceConfig) effectiveMaxMembers() int {
	if c.MaxMembersPerPack > 0 {
		return c.MaxMembersPerPack
	}
	return DefaultMaxMembersPerPack
}

func (c MaintenanceConfig) effectiveMinMembers() int {
	if c.MinSealedMembers > 0 {
		return c.MinSealedMembers
	}
	return DefaultMinSealedMembers
}

func (c MaintenanceConfig) effectiveForceAfter() time.Duration {
	if c.ForcePackAfter > 0 {
		return c.ForcePackAfter
	}
	return DefaultForcePackAfter
}

func (c MaintenanceConfig) effectiveHeadroomFrac() float64 {
	f := c.CompactionHeadroomFrac
	if f <= 0 {
		f = DefaultCompactionHeadroomFrac
	}
	if f > 1 {
		f = 1
	}
	return f
}

func (c MaintenanceConfig) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c MaintenanceConfig) effectiveReleaseMinAge() time.Duration {
	if c.ReleaseMinAge > 0 {
		return c.ReleaseMinAge
	}
	return DefaultReleaseMinAge
}

func (c MaintenanceConfig) effectiveMaxReleases() int {
	if c.MaxReleasesPerTick > 0 {
		return c.MaxReleasesPerTick
	}
	return DefaultMaxReleasesPerTick
}

func (c MaintenanceConfig) effectiveReleasePressureFrac() float64 {
	f := c.ReleasePressureHeadroomFrac
	if f <= 0 {
		f = DefaultReleasePressureHeadroomFrac
	}
	if f > 1 {
		f = 1
	}
	return f
}

// DefaultMaintenanceConfig enables eviction + compaction + L1 release with production defaults.
func DefaultMaintenanceConfig() MaintenanceConfig {
	return MaintenanceConfig{
		Interval:         DefaultMaintenanceInterval,
		EnableEviction:   true,
		EnableCompaction: true,
		EnableL1Release:  true,
	}
}

// TickResult is a non-secret summary of one maintenance cycle (for tests/metrics).
type TickResult struct {
	JournalRecovered  int
	JournalReclaimed  int64
	Evicted           int
	EvictReclaimed    int64
	NeedsEviction     bool
	PacksCreated      int
	PackMembers       int
	CompactionSkipped string // empty or stable reason code
	// L1 release (ARC-005 residual).
	ReleaseJournalRecovered int
	L1Released              int
	L1ReleaseReclaimed      int64
	UsagePhysicalBytes      int64
	QuotaBytes              int64
}

// Maintainer runs periodic quota recovery/eviction, optional L1→L2 packing,
// and optional L1 release after verified L2 pack (ARC-007 / ARC-005 residual).
//
// Cancel the context passed to Run to stop the loop on serve shutdown.
type Maintainer struct {
	Quota   *store.QuotaManager
	Meta    *store.Meta
	DataDir string
	// ArchiveRoot is the L2 archives directory; default Quota.ArchiveRoot().
	ArchiveRoot string
	Config      MaintenanceConfig
	Logger      *telemetry.Logger
	Metrics     *telemetry.Metrics
	// Pack is optional override for tests (default: logmirror.PackGenerations + FSStore).
	Pack func(ctx context.Context, keys []store.LogKey) (logmirror.PackResult, error)
	// Release optional override for tests; default uses store.ReleaseManager + VerifyPackForRelease.
	Release func(ctx context.Context, generationID int64) (store.ReleaseResult, error)
	// FrameCrypto optional AEAD keys for encrypted L1 frames during L2 pack (ARC-009).
	FrameCrypto *store.FrameCrypto

	// mu serializes Tick for concurrent safety (tests may call Tick while Run loops).
	mu sync.Mutex
}

// NewMaintainer builds a worker for a profile store. Quota and Meta are required.
func NewMaintainer(qm *store.QuotaManager, meta *store.Meta, dataDir string, cfg MaintenanceConfig) (*Maintainer, error) {
	if qm == nil || meta == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "quota manager and meta are required")
	}
	if dataDir == "" {
		dataDir = qm.DataDir
	}
	root := qm.ArchiveRoot()
	return &Maintainer{
		Quota:       qm,
		Meta:        meta,
		DataDir:     dataDir,
		ArchiveRoot: root,
		Config:      cfg,
	}, nil
}

// Run ticks immediately once, then on Interval until ctx is cancelled.
func (m *Maintainer) Run(ctx context.Context) {
	if m == nil {
		return
	}
	interval := m.Config.EffectiveInterval()
	// First tick promptly so serve recovers journals without waiting a full interval.
	if _, err := m.Tick(ctx); err != nil && ctx.Err() == nil {
		m.logWarn("cache_maintenance_tick_error", "err", apperr.ModelMessage(err))
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.logInfo("cache_maintenance_stopped", "reason", "context_cancelled")
			return
		case <-t.C:
			if _, err := m.Tick(ctx); err != nil && ctx.Err() == nil {
				m.logWarn("cache_maintenance_tick_error", "err", apperr.ModelMessage(err))
			}
		}
	}
}

// Tick runs one maintenance cycle: journal recovery, optional eviction, optional compaction.
func (m *Maintainer) Tick(ctx context.Context) (TickResult, error) {
	var res TickResult
	if m == nil || m.Quota == nil || m.Meta == nil {
		return res, apperr.New(apperr.CodeInternal, "maintainer is not configured")
	}
	if err := ctx.Err(); err != nil {
		return res, apperr.Wrap(apperr.CodeCancelled, "maintenance cancelled", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.incMetric(telemetry.MetricCacheMaintTicks, 1)

	// 1) Recover incomplete eviction journal (startup / after interrupt).
	if m.Config.EnableEviction {
		jr, err := m.Quota.RecoverEvictJournal(ctx)
		if err != nil {
			return res, err
		}
		res.JournalRecovered = jr.Evicted
		res.JournalReclaimed = jr.ReclaimedBytes
		if jr.Evicted > 0 {
			m.incMetric(telemetry.MetricCacheEvictItems, int64(jr.Evicted))
			m.addBytes(telemetry.MetricCacheEvictBytes, jr.ReclaimedBytes)
			m.logInfo("cache_evict_journal_recovered",
				"items", strconv.Itoa(jr.Evicted),
				"bytes_reclaimed", strconv.FormatInt(jr.ReclaimedBytes, 10),
			)
		}
	}

	// 2) Evict when over quota / low-disk.
	if m.Config.EnableEviction {
		need, usage, err := m.Quota.NeedsEviction(ctx)
		if err != nil {
			return res, err
		}
		res.NeedsEviction = need
		res.UsagePhysicalBytes = usage.TotalPhysicalBytes
		res.QuotaBytes = usage.QuotaBytes
		m.setGauge(telemetry.MetricCacheUsageBytes, usage.TotalPhysicalBytes)
		m.setGauge(telemetry.MetricCacheQuotaBytes, usage.QuotaBytes)
		if need {
			plan, err := m.Quota.PlanEviction(ctx, 0)
			if err != nil {
				return res, err
			}
			if len(plan.Candidates) > 0 {
				er, err := m.Quota.Evict(ctx, plan)
				if err != nil && !er.Interrupted {
					// Partial progress may still be recorded on er.
					m.logWarn("cache_evict_error",
						"err", apperr.ModelMessage(err),
						"evicted", strconv.Itoa(er.Evicted),
						"bytes_reclaimed", strconv.FormatInt(er.ReclaimedBytes, 10),
					)
					if er.Evicted == 0 {
						return res, err
					}
				}
				res.Evicted = er.Evicted
				res.EvictReclaimed = er.ReclaimedBytes
				if er.Evicted > 0 {
					m.incMetric(telemetry.MetricCacheEvictItems, int64(er.Evicted))
					m.addBytes(telemetry.MetricCacheEvictBytes, er.ReclaimedBytes)
					m.logInfo("cache_evict_applied",
						"items", strconv.Itoa(er.Evicted),
						"bytes_reclaimed", strconv.FormatInt(er.ReclaimedBytes, 10),
						"failed", strconv.Itoa(er.Failed),
					)
				}
			}
		}
	} else {
		if u, err := m.Quota.Usage(ctx); err == nil {
			res.UsagePhysicalBytes = u.TotalPhysicalBytes
			res.QuotaBytes = u.QuotaBytes
		}
	}

	// 3) Optional L1→L2 compaction (marks packed; L1 retained until release step).
	if m.Config.EnableCompaction {
		cr, err := m.compactTick(ctx, res.UsagePhysicalBytes, res.QuotaBytes)
		if err != nil {
			return res, err
		}
		res.PacksCreated = cr.packs
		res.PackMembers = cr.members
		res.CompactionSkipped = cr.skipped
		if cr.packs > 0 {
			m.incMetric(telemetry.MetricCachePacksCreated, int64(cr.packs))
			m.logInfo("cache_compaction_packed",
				"packs", strconv.Itoa(cr.packs),
				"members", strconv.Itoa(cr.members),
			)
		} else if cr.skipped != "" {
			m.logInfo("cache_compaction_skipped", "reason", cr.skipped)
		}
	}

	// 4) L1 release after verified L2 pack (ARC-005 residual).
	if m.Config.EnableL1Release || m.Config.ReleaseAfterPack {
		// Refresh usage after packing for pressure decisions.
		if u, err := m.Quota.Usage(ctx); err == nil {
			res.UsagePhysicalBytes = u.TotalPhysicalBytes
			res.QuotaBytes = u.QuotaBytes
		}
		rr, err := m.releaseTick(ctx, res.UsagePhysicalBytes, res.QuotaBytes)
		if err != nil {
			return res, err
		}
		res.ReleaseJournalRecovered = rr.journalRecovered
		res.L1Released = rr.released
		res.L1ReleaseReclaimed = rr.reclaimed
		if rr.released > 0 {
			m.incMetric(telemetry.MetricCacheL1Released, int64(rr.released))
			m.addBytes(telemetry.MetricCacheL1ReleaseBytes, rr.reclaimed)
			m.logInfo("cache_l1_released",
				"items", strconv.Itoa(rr.released),
				"bytes_reclaimed", strconv.FormatInt(rr.reclaimed, 10),
			)
		}
	}

	return res, nil
}

type releaseOutcome struct {
	journalRecovered int
	released         int
	reclaimed        int64
}

func (m *Maintainer) releaseTick(ctx context.Context, usageBytes, quotaBytes int64) (releaseOutcome, error) {
	var out releaseOutcome
	if err := ctx.Err(); err != nil {
		return out, apperr.Wrap(apperr.CodeCancelled, "L1 release cancelled", err)
	}
	rm, err := m.releaseManager()
	if err != nil {
		return out, err
	}
	// Recover incomplete release journal first.
	rec, err := rm.RecoverReleaseJournal(ctx)
	if err != nil {
		return out, err
	}
	if rec.Released {
		out.journalRecovered = 1
		out.released++
		out.reclaimed += rec.ReclaimedBytes
	}

	releaseFn := m.Release
	if releaseFn == nil {
		releaseFn = func(ctx context.Context, generationID int64) (store.ReleaseResult, error) {
			return rm.ReleasePackedL1(ctx, generationID)
		}
	}

	// Pressure: free fraction of quota at or below threshold.
	highPressure := false
	if quotaBytes > 0 {
		free := quotaBytes - usageBytes
		frac := float64(free) / float64(quotaBytes)
		if free <= 0 || frac <= m.Config.effectiveReleasePressureFrac() {
			highPressure = true
		}
	}
	// Over-quota / NeedsEviction also counts as pressure.
	if !highPressure && m.Quota != nil {
		if need, _, nerr := m.Quota.NeedsEviction(ctx); nerr == nil && need {
			highPressure = true
		}
	}

	candidates, err := rm.ListReleaseCandidates(ctx)
	if err != nil {
		return out, err
	}
	now := m.Config.now()
	minAge := m.Config.effectiveReleaseMinAge()
	maxN := m.Config.effectiveMaxReleases()
	n := 0
	for _, g := range candidates {
		if n >= maxN {
			break
		}
		if err := ctx.Err(); err != nil {
			return out, apperr.Wrap(apperr.CodeCancelled, "L1 release cancelled", err)
		}
		if !m.Config.ReleaseAfterPack {
			// Age gate unless under high pressure.
			if !highPressure {
				packedAt := g.PackedAt
				if packedAt.IsZero() {
					packedAt = g.UpdatedAt
				}
				if now.Sub(packedAt) < minAge {
					continue
				}
			}
		}
		rr, rerr := releaseFn(ctx, g.ID)
		if rerr != nil {
			if apperr.IsCancelled(rerr) {
				return out, rerr
			}
			m.logWarn("cache_l1_release_error",
				"err", apperr.ModelMessage(rerr),
				"generation_id", strconv.FormatInt(g.ID, 10),
			)
			continue
		}
		if rr.Released && !rr.Already {
			out.released++
			out.reclaimed += rr.ReclaimedBytes
			n++
		}
	}
	return out, nil
}

func (m *Maintainer) releaseManager() (*store.ReleaseManager, error) {
	root := m.ArchiveRoot
	if root == "" && m.Quota != nil {
		root = m.Quota.ArchiveRoot()
	}
	rm, err := store.NewReleaseManager(m.Meta, m.DataDir, logmirror.VerifyPackForRelease(root), store.ReleaseConfig{
		Now: m.Config.Now,
	})
	if err != nil {
		return nil, err
	}
	rm.Leases = m.Quota
	return rm, nil
}

type compactOutcome struct {
	packs   int
	members int
	skipped string
}

func (m *Maintainer) compactTick(ctx context.Context, usageBytes, quotaBytes int64) (compactOutcome, error) {
	var out compactOutcome
	if err := ctx.Err(); err != nil {
		return out, apperr.Wrap(apperr.CodeCancelled, "compaction cancelled", err)
	}
	// Refresh usage if not already filled (eviction disabled path).
	if quotaBytes <= 0 {
		u, err := m.Quota.Usage(ctx)
		if err != nil {
			return out, err
		}
		usageBytes = u.TotalPhysicalBytes
		quotaBytes = u.QuotaBytes
	}

	// Skip when well under quota (plenty of headroom) — packing grows total until L1 release.
	free := quotaBytes - usageBytes
	headroom := m.Config.effectiveHeadroomFrac()
	if free > 0 && float64(free) > float64(quotaBytes)*headroom {
		// Still allow force-aged packs when any candidate is old enough.
		// We only skip the bulk path; force candidates still pack below.
		out.skipped = "under_quota_headroom"
		// Continue to check force-aged only.
	}

	candidates, err := m.listPackCandidates(ctx)
	if err != nil {
		return out, err
	}
	if len(candidates) == 0 {
		if out.skipped == "" {
			out.skipped = "no_candidates"
		}
		return out, nil
	}

	now := m.Config.now()
	forceAfter := m.Config.effectiveForceAfter()
	minMembers := m.Config.effectiveMinMembers()
	maxMembers := m.Config.effectiveMaxMembers()
	maxPacks := m.Config.effectiveMaxPacks()

	// Partition: force-aged always eligible; others only when not under headroom skip
	// and we have enough members overall (or in a batch).
	underHeadroom := out.skipped == "under_quota_headroom"
	var force, rest []store.LogGeneration
	for _, g := range candidates {
		age := now.Sub(g.UpdatedAt)
		if g.UpdatedAt.IsZero() || age >= forceAfter {
			force = append(force, g)
		} else if !underHeadroom {
			rest = append(rest, g)
		}
	}
	if underHeadroom && len(force) == 0 {
		return out, nil
	}
	if !underHeadroom {
		out.skipped = "" // will pack or set no_batch
	}

	// Collection map for Wave 31 pack affinity (genID → collection). Fail closed
	// on corrupt catalog (do not pack with untrusted membership). Empty map is fine.
	genToColl, err := m.Meta.ListGenerationCollections(ctx, "")
	if err != nil {
		return out, err
	}

	// Build pack batches preferring collection co-pack (profile|collection), else
	// job affinity (ARC-011 lite / Wave 31). Never mix profiles; maxMembers bounds apply.
	var batches [][]store.LogGeneration
	batches = append(batches, logmirror.SelectCollectionAwarePackBatches(force, genToColl, maxMembers, 1, maxPacks)...)
	if !underHeadroom && len(batches) < maxPacks {
		batches = append(batches, logmirror.SelectCollectionAwarePackBatches(rest, genToColl, maxMembers, minMembers, maxPacks-len(batches))...)
	}
	if len(batches) == 0 {
		if out.skipped == "" {
			if underHeadroom {
				out.skipped = "under_quota_headroom"
			} else {
				out.skipped = "below_min_members"
			}
		}
		return out, nil
	}

	packFn := m.Pack
	if packFn == nil {
		// Bind collection map so defaultPack can label packs with collection affinity.
		collMap := genToColl
		packFn = func(ctx context.Context, keys []store.LogKey) (logmirror.PackResult, error) {
			return m.defaultPackWithCollections(ctx, keys, collMap)
		}
	}

	for _, batch := range batches {
		if err := ctx.Err(); err != nil {
			return out, apperr.Wrap(apperr.CodeCancelled, "compaction cancelled", err)
		}
		keys := make([]store.LogKey, 0, len(batch))
		for _, g := range batch {
			keys = append(keys, store.LogKey{Profile: g.Profile, Job: g.Job, Build: g.Build})
		}
		pr, err := packFn(ctx, keys)
		if err != nil {
			m.logWarn("cache_compaction_pack_error",
				"err", apperr.ModelMessage(err),
				"members", strconv.Itoa(len(keys)),
			)
			// Continue other batches; do not fail the whole tick for one pack error.
			continue
		}
		out.packs++
		out.members += pr.MemberCount
		out.skipped = ""
	}
	if out.packs == 0 && out.skipped == "" {
		out.skipped = "pack_errors"
	}
	return out, nil
}

func (m *Maintainer) listPackCandidates(ctx context.Context) ([]store.LogGeneration, error) {
	gens, err := m.Meta.ListGenerations(ctx)
	if err != nil {
		return nil, err
	}
	pins, err := m.Meta.ListPins(ctx)
	if err != nil {
		return nil, err
	}
	pinned := make(map[string]struct{}, len(pins))
	for _, p := range pins {
		if p.Kind == store.PinKindGeneration {
			pinned[p.TargetID] = struct{}{}
		}
	}
	var out []store.LogGeneration
	for _, g := range gens {
		if !g.Sealed {
			continue
		}
		if g.PackedPackID != "" {
			continue
		}
		idStr := strconv.FormatInt(g.ID, 10)
		if _, ok := pinned[idStr]; ok {
			continue
		}
		// Skip active-reader leases when QuotaManager is present.
		if m.Quota != nil && m.Quota.IsLeased(g.ID) {
			continue
		}
		out = append(out, g)
	}
	return out, nil
}

func (m *Maintainer) defaultPack(ctx context.Context, keys []store.LogKey) (logmirror.PackResult, error) {
	return m.defaultPackWithCollections(ctx, keys, nil)
}

func (m *Maintainer) defaultPackWithCollections(
	ctx context.Context,
	keys []store.LogKey,
	genToColl map[int64]store.GenerationCollection,
) (logmirror.PackResult, error) {
	root := m.ArchiveRoot
	if root == "" && m.Quota != nil {
		root = m.Quota.ArchiveRoot()
	}
	if root == "" {
		return logmirror.PackResult{}, apperr.New(apperr.CodeInternal, "archive root is not configured")
	}
	dest, err := archive.NewFSStore(root)
	if err != nil {
		return logmirror.PackResult{}, err
	}
	// Prefer collection affinity when membership is known (Wave 31); Wave 32
	// adds optional |relation= when the batch shares one non-empty relation.
	// Else job keys.
	affinity := logmirror.AffinityGroupFromKeys(keys)
	if len(genToColl) > 0 && m.Meta != nil {
		gens := make([]store.LogGeneration, 0, len(keys))
		for _, k := range keys {
			g, gerr := m.Meta.GetLatestGeneration(ctx, k)
			if gerr != nil || g == nil {
				// Incomplete resolve → keep job-key affinity (no cross-profile invent).
				gens = nil
				break
			}
			gens = append(gens, *g)
		}
		if len(gens) == len(keys) {
			if collAff := logmirror.AffinityGroupFromGenerationsWithCollections(gens, genToColl); collAff != "" {
				affinity = collAff
			}
		}
	}
	return logmirror.PackGenerations(ctx, keys, m.Meta, m.DataDir, dest, logmirror.PackOptions{
		Marker:          m.Meta,
		DisableRollover: true,
		AffinityGroup:   affinity,
		Crypto:          m.FrameCrypto,
	})
}

func (m *Maintainer) logInfo(msg string, kvs ...string) {
	if m.Logger != nil {
		m.Logger.Info(msg, kvs...)
		return
	}
	if r := telemetry.Global(); r != nil {
		r.Info(msg, kvs...)
	}
}

func (m *Maintainer) logWarn(msg string, kvs ...string) {
	if m.Logger != nil {
		m.Logger.Warn(msg, kvs...)
		return
	}
	if r := telemetry.Global(); r != nil && r.Logger != nil {
		r.Logger.Warn(msg, kvs...)
	}
}

func (m *Maintainer) incMetric(name string, delta int64) {
	if m.Metrics != nil {
		m.Metrics.Inc(name, delta)
		return
	}
	if r := telemetry.Global(); r != nil {
		r.Inc(name, delta)
	}
}

func (m *Maintainer) addBytes(name string, n int64) {
	if n <= 0 {
		return
	}
	if m.Metrics != nil {
		m.Metrics.AddBytes(name, n)
		return
	}
	if r := telemetry.Global(); r != nil && r.Metrics != nil {
		r.Metrics.AddBytes(name, n)
	}
}

func (m *Maintainer) setGauge(name string, v int64) {
	if m.Metrics != nil {
		m.Metrics.SetGauge(name, v)
		return
	}
	if r := telemetry.Global(); r != nil && r.Metrics != nil {
		r.Metrics.SetGauge(name, v)
	}
}

// FormatTickSummary returns a short non-secret log line for operators.
func FormatTickSummary(r TickResult) string {
	return fmt.Sprintf("evicted=%d reclaim=%d packs=%d members=%d l1_released=%d skip=%s",
		r.Evicted, r.EvictReclaimed, r.PacksCreated, r.PackMembers, r.L1Released, r.CompactionSkipped)
}
