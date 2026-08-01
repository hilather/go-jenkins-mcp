package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

// ARC-007 eviction CLI:
//   - cache eviction-plan / cache evict (default): PlanEviction only (never Evict)
//   - cache evict --confirm|--yes: RecoverEvictJournal + re-plan + Evict
// Serve-time app.Maintainer remains the primary reclaim path; offline apply is an operator escape hatch.

// cacheOpContext returns the context for offline cache eviction apply.
// Tests may replace to inject cancellation; production uses Background.
var cacheOpContext = func() context.Context { return context.Background() }

// evictionPlanJSON is secret-free output for cache eviction-plan / cache evict --json.
type evictionPlanJSON struct {
	Profile           string                  `json:"profile"`
	NeedsEviction     bool                    `json:"needs_eviction"`
	Usage             store.UsageStats        `json:"usage"`
	BytesNeeded       int64                   `json:"bytes_needed"`
	TotalReclaimBytes int64                   `json:"total_reclaim_bytes"`
	DryRun            bool                    `json:"dry_run"`
	Applied           bool                    `json:"applied,omitempty"`
	PinsSkipped       int                     `json:"pins_skipped"`
	Candidates        []evictionCandidateJSON `json:"candidates"`
	PlannedAt         string                  `json:"planned_at,omitempty"`
	// Apply-only fields (secret-free counts / ids — never absolute paths or payloads).
	Evicted           int      `json:"evicted,omitempty"`
	Failed            int      `json:"failed,omitempty"`
	ReclaimedBytes    int64    `json:"reclaimed_bytes,omitempty"`
	Interrupted       bool     `json:"interrupted,omitempty"`
	JournalRecovered  int      `json:"journal_recovered,omitempty"`
	JournalReclaimed  int64    `json:"journal_reclaimed_bytes,omitempty"`
	JournalConsistent bool     `json:"journal_consistent,omitempty"`
	Errors            []string `json:"errors,omitempty"`
}

type evictionCandidateJSON struct {
	Kind   string `json:"kind"` // l1 | l2
	ID     string `json:"id"`
	Bytes  int64  `json:"bytes"`
	Age    string `json:"age,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// quotaUsageJSON is secret-free UsageStats for cache quota --json.
type quotaUsageJSON struct {
	Profile       string           `json:"profile"`
	NeedsEviction bool             `json:"needs_eviction"`
	Usage         store.UsageStats `json:"usage"`
}

func runCacheEvictionPlan(args []string) error {
	fs := flag.NewFlagSet("cache eviction-plan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	asJSON := fs.Bool("json", false, "Emit secret-free JSON plan")
	targetBytesFlag := fs.String("target-bytes", "", "Additional bytes to free beyond bringing usage under quota (optional)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"profile": true, "target-bytes": true})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	var targetBytes int64
	if raw := strings.TrimSpace(*targetBytesFlag); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			return apperr.New(apperr.CodeInvalidArgument, "--target-bytes must be a non-negative integer")
		}
		targetBytes = n
	}

	meta, p, dataDir, err := openProfileMetaAndDataDir(*profileFlag)
	if err != nil {
		return err
	}
	defer func() { _ = meta.Close() }()

	qm, err := store.NewQuotaManager(meta, dataDir, store.QuotaConfig{})
	if err != nil {
		return err
	}
	ctx := context.Background()

	need, _, err := qm.NeedsEviction(ctx)
	if err != nil {
		return err
	}
	plan, err := qm.PlanEviction(ctx, targetBytes)
	if err != nil {
		return err
	}
	// Prefer Usage from plan; fill profile id for operators.
	if plan.Usage.Profile == "" {
		plan.Usage.Profile = string(p.ID)
	}

	pinsSkipped, err := countPins(ctx, meta)
	if err != nil {
		return err
	}

	out := evictionPlanJSON{
		Profile:           string(p.ID),
		NeedsEviction:     need,
		Usage:             plan.Usage,
		BytesNeeded:       plan.BytesNeeded,
		TotalReclaimBytes: plan.TotalReclaimBytes,
		DryRun:            true,
		PinsSkipped:       pinsSkipped,
		Candidates:        make([]evictionCandidateJSON, 0, len(plan.Candidates)),
		PlannedAt:         time.Now().UTC().Format(time.RFC3339Nano),
	}
	for _, c := range plan.Candidates {
		out.Candidates = append(out.Candidates, evictionCandidateJSON{
			Kind:   c.Tier,
			ID:     c.ID,
			Bytes:  c.ReclaimBytes,
			Age:    c.Age,
			Reason: c.Reason,
		})
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return apperr.Wrap(apperr.CodeInternal, "encode eviction-plan JSON", err)
		}
		return nil
	}

	fmt.Fprintf(os.Stdout, "profile=%s needs_eviction=%v dry_run=true pins_skipped=%d\n",
		out.Profile, out.NeedsEviction, out.PinsSkipped)
	fmt.Fprintf(os.Stdout, "usage total_physical=%d l1_physical=%d l2_physical=%d generations=%d packs=%d quota=%d over_quota=%v\n",
		out.Usage.TotalPhysicalBytes, out.Usage.L1PhysicalBytes, out.Usage.L2PhysicalBytes,
		out.Usage.Generations, out.Usage.Packs, out.Usage.QuotaBytes, out.Usage.OverQuota)
	if out.Usage.FreeBytes > 0 || out.Usage.LowDisk {
		fmt.Fprintf(os.Stdout, "disk free_bytes=%d low_disk=%v\n", out.Usage.FreeBytes, out.Usage.LowDisk)
	}
	fmt.Fprintf(os.Stdout, "plan bytes_needed=%d total_reclaim_bytes=%d candidates=%d\n",
		out.BytesNeeded, out.TotalReclaimBytes, len(out.Candidates))
	for _, c := range out.Candidates {
		age := ""
		if c.Age != "" {
			age = " age=" + c.Age
		}
		reason := ""
		if c.Reason != "" {
			reason = " reason=" + c.Reason
		}
		fmt.Fprintf(os.Stdout, "  kind=%s id=%s bytes=%d%s%s\n", c.Kind, c.ID, c.Bytes, age, reason)
	}
	return nil
}

// runCacheEvict is the offline eviction operator path (ARC-007 Wave 29).
// Default is dry-run (identical to eviction-plan). Destructive apply requires
// --confirm or --yes and always re-plans immediately before Evict.
func runCacheEvict(args []string) error {
	fs := flag.NewFlagSet("cache evict", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	asJSON := fs.Bool("json", false, "Emit secret-free JSON plan/result")
	targetBytesFlag := fs.String("target-bytes", "", "Additional bytes to free beyond bringing usage under quota (optional)")
	confirm := fs.Bool("confirm", false, "Required to apply eviction (destructive)")
	yes := fs.Bool("yes", false, "Alias for --confirm (destructive)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"profile": true, "target-bytes": true})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	var targetBytes int64
	if raw := strings.TrimSpace(*targetBytesFlag); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			return apperr.New(apperr.CodeInvalidArgument, "--target-bytes must be a non-negative integer")
		}
		targetBytes = n
	}
	apply := *confirm || *yes
	if !apply {
		// Default dry-run: never call Evict. Strip apply-only flags so plan parser accepts args.
		// Alias name "eviction-apply" still requires --confirm/--yes (safety); warn on stderr.
		fmt.Fprintln(os.Stderr, "cache evict: dry-run only (no deletes); pass --confirm or --yes to apply")
		return runCacheEvictionPlan(stripEvictApplyFlags(args))
	}

	meta, p, dataDir, err := openProfileMetaAndDataDir(*profileFlag)
	if err != nil {
		return err
	}
	defer func() { _ = meta.Close() }()

	qm, err := store.NewQuotaManager(meta, dataDir, store.QuotaConfig{})
	if err != nil {
		return err
	}
	ctx := cacheOpContext()
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "eviction cancelled", err)
	}

	// Recover incomplete journal first (same order as serve-time Maintainer).
	jr, err := qm.RecoverEvictJournal(ctx)
	if err != nil {
		return err
	}

	need, _, err := qm.NeedsEviction(ctx)
	if err != nil {
		return err
	}
	// Always re-plan immediately before apply so pins/leases/usage are current.
	plan, err := qm.PlanEviction(ctx, targetBytes)
	if err != nil {
		return err
	}
	if plan.Usage.Profile == "" {
		plan.Usage.Profile = string(p.ID)
	}
	pinsSkipped, err := countPins(ctx, meta)
	if err != nil {
		return err
	}

	out := evictionPlanJSON{
		Profile:           string(p.ID),
		NeedsEviction:     need,
		Usage:             plan.Usage,
		BytesNeeded:       plan.BytesNeeded,
		TotalReclaimBytes: plan.TotalReclaimBytes,
		DryRun:            false,
		Applied:           false,
		PinsSkipped:       pinsSkipped,
		Candidates:        planToCandidateJSON(plan),
		PlannedAt:         time.Now().UTC().Format(time.RFC3339Nano),
		JournalRecovered:  jr.Evicted,
		JournalReclaimed:  jr.ReclaimedBytes,
		JournalConsistent: jr.JournalConsistent,
	}

	if len(plan.Candidates) == 0 {
		// Confirm path completed: nothing to reclaim after recover+replan.
		out.Applied = true
		return emitEvictResult(out, *asJSON, nil)
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
	// Refresh usage after apply (best-effort; ignore secondary errors for output).
	if need2, usage2, uerr := qm.NeedsEviction(ctx); uerr == nil {
		out.NeedsEviction = need2
		if usage2.Profile == "" {
			usage2.Profile = string(p.ID)
		}
		out.Usage = usage2
	}
	return emitEvictResult(out, *asJSON, err)
}

func planToCandidateJSON(plan store.EvictPlan) []evictionCandidateJSON {
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

func emitEvictResult(out evictionPlanJSON, asJSON bool, applyErr error) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return apperr.Wrap(apperr.CodeInternal, "encode evict JSON", err)
		}
		return applyErr
	}

	fmt.Fprintf(os.Stdout, "profile=%s needs_eviction=%v dry_run=false applied=%v pins_skipped=%d\n",
		out.Profile, out.NeedsEviction, out.Applied, out.PinsSkipped)
	fmt.Fprintf(os.Stdout, "usage total_physical=%d l1_physical=%d l2_physical=%d generations=%d packs=%d quota=%d over_quota=%v\n",
		out.Usage.TotalPhysicalBytes, out.Usage.L1PhysicalBytes, out.Usage.L2PhysicalBytes,
		out.Usage.Generations, out.Usage.Packs, out.Usage.QuotaBytes, out.Usage.OverQuota)
	if out.Usage.FreeBytes > 0 || out.Usage.LowDisk {
		fmt.Fprintf(os.Stdout, "disk free_bytes=%d low_disk=%v\n", out.Usage.FreeBytes, out.Usage.LowDisk)
	}
	if out.JournalRecovered > 0 {
		fmt.Fprintf(os.Stdout, "journal_recovered items=%d reclaimed_bytes=%d\n",
			out.JournalRecovered, out.JournalReclaimed)
	}
	fmt.Fprintf(os.Stdout, "plan bytes_needed=%d total_reclaim_bytes=%d candidates=%d\n",
		out.BytesNeeded, out.TotalReclaimBytes, len(out.Candidates))
	for _, c := range out.Candidates {
		age := ""
		if c.Age != "" {
			age = " age=" + c.Age
		}
		reason := ""
		if c.Reason != "" {
			reason = " reason=" + c.Reason
		}
		fmt.Fprintf(os.Stdout, "  kind=%s id=%s bytes=%d%s%s\n", c.Kind, c.ID, c.Bytes, age, reason)
	}
	fmt.Fprintf(os.Stdout, "result evicted=%d failed=%d reclaimed_bytes=%d interrupted=%v journal_consistent=%v\n",
		out.Evicted, out.Failed, out.ReclaimedBytes, out.Interrupted, out.JournalConsistent)
	for _, e := range out.Errors {
		fmt.Fprintf(os.Stdout, "  error=%s\n", e)
	}
	return applyErr
}

func runCacheQuota(args []string) error {
	fs := flag.NewFlagSet("cache quota", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	asJSON := fs.Bool("json", false, "Emit secret-free JSON usage stats")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"profile": true})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}

	meta, p, dataDir, err := openProfileMetaAndDataDir(*profileFlag)
	if err != nil {
		return err
	}
	defer func() { _ = meta.Close() }()

	qm, err := store.NewQuotaManager(meta, dataDir, store.QuotaConfig{})
	if err != nil {
		return err
	}
	ctx := context.Background()
	need, usage, err := qm.NeedsEviction(ctx)
	if err != nil {
		return err
	}
	if usage.Profile == "" {
		usage.Profile = string(p.ID)
	}

	if *asJSON {
		out := quotaUsageJSON{
			Profile:       string(p.ID),
			NeedsEviction: need,
			Usage:         usage,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return apperr.Wrap(apperr.CodeInternal, "encode quota JSON", err)
		}
		return nil
	}

	fmt.Fprintf(os.Stdout, "profile=%s needs_eviction=%v\n", p.ID, need)
	fmt.Fprintf(os.Stdout, "usage total_physical=%d l1_physical=%d l2_physical=%d generations=%d packs=%d quota=%d over_quota=%v\n",
		usage.TotalPhysicalBytes, usage.L1PhysicalBytes, usage.L2PhysicalBytes,
		usage.Generations, usage.Packs, usage.QuotaBytes, usage.OverQuota)
	if usage.FreeBytes > 0 || usage.LowDisk {
		fmt.Fprintf(os.Stdout, "disk free_bytes=%d low_disk=%v\n", usage.FreeBytes, usage.LowDisk)
	}
	return nil
}

// openProfileMetaAndDataDir loads profile + opens meta, returning the data dir path.
// Fail closed: missing profile, missing/invalid data directory (does not create).
func openProfileMetaAndDataDir(profileID string) (*store.Meta, *profile.Profile, string, error) {
	meta, p, err := openProfileMetaForPins(profileID)
	if err != nil {
		return nil, nil, "", err
	}
	dataDir, err := resolveProfileDataDirPath(p)
	if err != nil {
		_ = meta.Close()
		return nil, nil, "", err
	}
	return meta, p, dataDir, nil
}

func countPins(ctx context.Context, meta *store.Meta) (int, error) {
	if meta == nil {
		return 0, nil
	}
	pins, err := meta.ListPins(ctx)
	if err != nil {
		return 0, err
	}
	return len(pins), nil
}

// stripEvictApplyFlags removes --confirm/--yes so dry-run can reuse eviction-plan parsing.
func stripEvictApplyFlags(args []string) []string {
	if len(args) == 0 {
		return args
	}
	out := make([]string, 0, len(args))
	for _, a := range args {
		switch {
		case a == "--confirm", a == "-confirm", a == "--yes", a == "-yes":
			continue
		case strings.HasPrefix(a, "--confirm="), strings.HasPrefix(a, "--yes="):
			continue
		default:
			out = append(out, a)
		}
	}
	return out
}
