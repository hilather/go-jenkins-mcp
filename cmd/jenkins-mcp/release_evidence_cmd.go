package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway/qualify"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
	"github.com/simonfxr/go-jenkins-mcp/internal/update"
)

// releaseEvidenceSchemaV2 is the offline REL-002 lite JSON schema id (Wave 21 expand).
const releaseEvidenceSchemaV2 = "jenkins-mcp.release-evidence.v2"

// mcpSDKModule is the official MCP Go SDK module path (ADR 0006).
const mcpSDKModule = "github.com/modelcontextprotocol/go-sdk"

// releaseEvidence is a secret-free offline summary for REL-002 lite gates.
// Never include tokens, cookies, Authorization material, or private keys.
type releaseEvidence struct {
	Schema            string                 `json:"schema"`
	GeneratedAt       string                 `json:"generated_at"`
	Offline           bool                   `json:"offline"`
	Overall           string                 `json:"overall"` // pass | fail | warn | incomplete
	Version           versionInfo            `json:"version"`
	Runtime           releaseRuntime         `json:"runtime"`
	ProfileID         string                 `json:"profile_id,omitempty"`
	MCPSDK            *mcpSDKPin             `json:"mcp_sdk,omitempty"`
	SecuritySelfCheck *securitySelfCheckSnap `json:"security_self_check,omitempty"`
	UpdateLKG         *updateLKGSnap         `json:"update_lkg,omitempty"`
	GatewayQualify    *gatewayQualifySnap    `json:"gateway_qualify,omitempty"`
	Doctor            *doctorSnap            `json:"doctor,omitempty"`
	CacheStatus       *cacheSnap             `json:"cache_status,omitempty"`
	Checks            []releaseCheck         `json:"checks"`
	Notes             []string               `json:"notes,omitempty"`
	// Residual is structured known residuals (never claim production GO from lite alone).
	Residual []releaseResidual `json:"residual"`
}

type releaseRuntime struct {
	GOOS     string `json:"goos"`
	GOARCH   string `json:"goarch"`
	NumCPU   int    `json:"num_cpu"`
	Compiler string `json:"compiler"`
}

// releaseCheck is one offline gate row. GateID maps to docs/release/gates.md.
type releaseCheck struct {
	ID      string `json:"id"`
	GateID  string `json:"gate_id,omitempty"`
	Status  string `json:"status"` // pass | fail | warn | skip
	Message string `json:"message,omitempty"`
	// Optional marks doctor/cache when --profile is omitted (does not force incomplete).
	Optional bool `json:"optional,omitempty"`
}

// releaseResidual is a structured residual that lite evidence does not close.
type releaseResidual struct {
	ID      string   `json:"id"`
	GateIDs []string `json:"gate_ids,omitempty"`
	Message string   `json:"message"`
}

// mcpSDKPin records the pinned MCP Go SDK version (secret-free).
type mcpSDKPin struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Source  string `json:"source"` // build_info | go.mod | residual
}

// securitySelfCheckSnap is a compact embed of QA-005 self-check (no full item dump required).
type securitySelfCheckSnap struct {
	Overall                   string `json:"overall"`
	ItemCount                 int    `json:"item_count"`
	FailCount                 int    `json:"fail_count"`
	WarnCount                 int    `json:"warn_count"`
	IndependentReviewRequired bool   `json:"independent_review_required"`
}

// updateLKGSnap notes LKG present/absent without secret paths.
type updateLKGSnap struct {
	Present        bool   `json:"present"`
	Version        string `json:"version,omitempty"`
	Channel        string `json:"channel,omitempty"`
	ArtifactSHA256 string `json:"artifact_sha256,omitempty"` // content hash only
	Note           string `json:"note,omitempty"`
}

// gatewayQualifySnap is optional offline GWY-003 suite summary.
type gatewayQualifySnap struct {
	Suite  string `json:"suite"`
	OK     bool   `json:"ok"`
	Passed int    `json:"passed"`
	Failed int    `json:"failed"`
}

// releaseEvidenceOptions configures offline evidence collection (testable).
type releaseEvidenceOptions struct {
	// ProfileID optional; enables doctor + cache status.
	ProfileID string
	// Now overrides clock (tests).
	Now func() time.Time
	// SkipGatewayQualify skips gateway offline suite (tests).
	SkipGatewayQualify bool
	// GoModPath optional path to go.mod for MCP SDK pin parse (tests / workspace).
	GoModPath string
	// GoModContent when set is used instead of reading GoModPath (pure tests).
	GoModContent string
	// Paths optional XDG paths; when nil, config.Resolve is used.
	Paths *config.Paths
	// Version/Commit/BuildTime override package ldflags vars when non-empty (tests set via package vars).
}

// knownReleaseResiduals returns structured residuals for Wave 21 production readiness lite.
// These are never closed by offline release-evidence alone.
func knownReleaseResiduals() []releaseResidual {
	return []releaseResidual{
		{
			ID:      "full_suite",
			GateIDs: []string{"REL-002.rel.unit", "REL-002.rel.fuzz"},
			Message: "MVP lite does not run make test, fuzz-smoke, or package-linux (see docs/release/gates.md)",
		},
		{
			ID:      "production_signoff",
			GateIDs: []string{"REL-002.own.signoff"},
			Message: "Full REL-002 go/no-go requires docs/release/gates.md + evidence-template.md named owner sign-offs; this JSON is not production sign-off",
		},
		{
			ID:      "live_entra",
			GateIDs: []string{"REL-002.compat.auth", "REL-002.sec.oauth"},
			Message: "Live Entra / jwt-auth-filter / AgentCore Obtain network qualification remains residual",
		},
		{
			// REL-001/002 honesty: offline gateway qualify is not live mode A/B/C GO.
			ID:      "gateway_modes_live",
			GateIDs: []string{"REL-002.compat.modes", "REL-002.compat.gateway", "REL-002.compat.auth"},
			Message: "Live multi-user gateway modes A/B/C remain residual unless operator mode matrix records live pilot cohorts; offline gateway qualify + unit contracts are foundation only (see docs/pilot/checklist.md §0)",
		},
		{
			// Multi-user Obtain foundation offline; not production multi-user GO.
			ID:      "multi_user_offline",
			GateIDs: []string{"REL-002.compat.modes", "REL-002.compat.gateway"},
			Message: "Done*: JENKINS_MCP_GATEWAY_MULTI_USER opt-in + doctor/admin secret-free residual fields offline; not production multi-user GO or multi-replica HA (see docs/pilot/checklist.md §0, deploy/gateway/.env.example)",
		},
		{
			// OAUTH-009 offline Bearer matrix / qualify case; live Entra pin open.
			ID:      "oauth009_offline",
			GateIDs: []string{"REL-002.compat.auth", "REL-002.sec.oauth", "REL-002.compat.modes"},
			Message: "Done*: oauth009_offline_bearer_matrix + Mode B offline vault foundation; live Entra/jwt-auth-filter production pin residual (OAUTH-009; docs/auth/jwt-auth-filter-qualification.md)",
		},
		{
			// OAUTH-010 offline Mode C prototype matrix; live Entra 3LO/OBO + AgentCore pin open.
			ID:      "oauth010_offline",
			GateIDs: []string{"REL-002.compat.auth", "REL-002.sec.oauth", "REL-002.compat.modes", "REL-002.compat.gateway"},
			Message: "Done*: oauth010_mode_c_offline_matrix + Mode C offline Live=false/mock Fetcher foundation; live Entra 3LO/OBO + AgentCore Identity vault production pin residual (OAUTH-010 / GWY-003; docs/auth/oauth-capability-matrix.md §4) — offline only, not live Entra Done",
		},
		{
			// Progressive consent metadata path Done*; browser 3LO not automated (OAUTH-010 / GWY-001).
			ID:      "progressive_consent_offline",
			GateIDs: []string{"REL-002.compat.auth", "REL-002.sec.oauth", "REL-002.compat.modes", "REL-002.compat.gateway"},
			Message: "Done*: progressive consent metadata path (authorization_url + session_id only; qualify progressive_consent_residual); process-local consent metadata store Done* (optional file; never tokens; same-host reload-before-persist flock lite; not multi-replica); browser 3LO not automated; multi-pod consent correlation residual (OAUTH-010 / GWY-001 / HOST-008) — offline only, not live consent UX GO",
		},
		{
			// HOST-008 Tier A single-replica honesty (scaffold replicas:1).
			ID:      "host008_single_replica",
			GateIDs: []string{"REL-002.compat.gateway", "REL-002.ops.doctor"},
			Message: "HOST-008 Tier A: single-replica default (deploy/gateway kustomize replicas:1; doctor/admin ha_multi_replica=false); Service sessionAffinity ClientIP Done* scaffold (residual runtime); session_affinity_recommended when multi_user; file vault flock + optional FileTokenCache + optional FileSubjectRateLimiter (JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH) multi-process Done* lite (same host/shared FS only — multi-pod needs shared FS/external vault/rate/cache); multi-replica HA residual until multi-pod durable vault + multi-pod shared rate/cache",
		},
		{
			// Done* inventory: offline binary smoke exists (Wave 25 make + Wave 26 optional CI job).
			// Not merge-gate; does not close Cursor host CI — keep listed for honesty.
			ID:      "stdio_binary_smoke",
			GateIDs: []string{"REL-002.rel.mcp-matrix"},
			Message: "Done*: make stdio-smoke offline binary MCP over stdio (Wave 25) + optional CI job stdio-smoke (Wave 26, continue-on-error, not merge-gate); does not close Cursor host CI",
		},
		{
			ID:      "cursor_host_ci",
			GateIDs: []string{"REL-002.rel.mcp-matrix", "REL-002.compat.mcp-sdk"},
			Message: "Cursor host stdio lifecycle CI remains residual (offline protocol matrix + stdio_binary_smoke Done* are not real Cursor)",
		},
		{
			ID:      "install_operator",
			GateIDs: []string{"REL-002.compat.os", "REL-002.use.install"},
			Message: "Live Rocky/Ubuntu install + pilot-check evidence remains operator-owned (REL-001)",
		},
		{
			ID:      "update_install",
			GateIDs: []string{"REL-002.ops.lkg"},
			Message: "UPD-001 auto-install and binary rollback remain residual (prefer package manager)",
		},
	}
}

// runReleaseEvidence implements REL-002 lite offline evidence collection.
// Heavy suites (make test) are intentionally not invoked; see docs/release/gates.md.
func runReleaseEvidence(args []string) error {
	fs := flag.NewFlagSet("release-evidence", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	offline := fs.Bool("offline", true, "Local checks only (default true; network never required for MVP lite)")
	profileFlag := fs.String("profile", "", "Optional profile id for doctor + cache status")
	outPath := fs.String("output", "", "Write JSON to this path (default: stdout; use dist/release-evidence.json for release kits)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"profile": true, "output": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	// --offline is accepted for CLI symmetry; network is never used in this lite path.
	_ = offline

	opts := releaseEvidenceOptions{
		ProfileID: strings.TrimSpace(*profileFlag),
		GoModPath: findGoModPath(),
	}
	ev, err := buildReleaseEvidence(context.Background(), opts)
	if err != nil {
		return err
	}

	// Scrub any accidental secret-shaped content (defense in depth).
	scrubReleaseEvidence(ev)

	payload, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "encode release evidence", err)
	}
	payload = append(payload, '\n')

	// Final secret canary: never emit planted-looking Authorization material.
	if err := assertReleaseEvidenceSecretFree(payload); err != nil {
		return err
	}

	out := strings.TrimSpace(*outPath)
	if out == "" {
		_, err := os.Stdout.Write(payload)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil && filepath.Dir(out) != "." {
		return apperr.Wrap(apperr.CodeInternal, "create output dir", err)
	}
	if err := os.WriteFile(out, payload, 0o600); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "write release evidence", err)
	}
	fmt.Fprintf(os.Stderr, "wrote release evidence to %s (overall=%s schema=%s)\n", out, ev.Overall, ev.Schema)
	return nil
}

// buildReleaseEvidence assembles the v2 offline evidence document (pure builder + in-process checks).
func buildReleaseEvidence(ctx context.Context, opts releaseEvidenceOptions) (*releaseEvidence, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "release evidence cancelled", err)
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	ev := &releaseEvidence{
		Schema:      releaseEvidenceSchemaV2,
		GeneratedAt: now().UTC().Format(time.RFC3339),
		Offline:     true,
		Version:     buildVersionInfo(),
		Runtime: releaseRuntime{
			GOOS:     runtime.GOOS,
			GOARCH:   runtime.GOARCH,
			NumCPU:   runtime.NumCPU(),
			Compiler: runtime.Compiler,
		},
		Residual: knownReleaseResiduals(),
		Notes: []string{
			"REL-002 lite offline evidence only — not production sign-off",
			"Map check.gate_id and residual.gate_ids to docs/release/gates.md",
		},
	}

	// --- Always-on offline checks ---
	appendVersionChecks(ev)
	appendMCPSDKPin(ev, opts)
	appendPolicyEngineSelfTest(ev)
	appendSecuritySelfCheck(ctx, ev, opts)
	appendUpdateLKG(ev, opts)
	if !opts.SkipGatewayQualify {
		appendGatewayQualify(ctx, ev)
	}

	// Optional profile-bound checks.
	profID := strings.TrimSpace(opts.ProfileID)
	if profID == "" {
		ev.Checks = append(ev.Checks, releaseCheck{
			ID:       "doctor_offline",
			GateID:   "REL-002.ops.doctor",
			Status:   "skip",
			Optional: true,
			Message:  "--profile not set; doctor not run",
		})
		ev.Checks = append(ev.Checks, releaseCheck{
			ID:       "cache_status",
			GateID:   "REL-002.ops.cache",
			Status:   "skip",
			Optional: true,
			Message:  "--profile not set; cache status not run",
		})
		ev.Notes = append(ev.Notes, "Pass --profile <id> to include doctor --offline and cache status")
	} else {
		ev.ProfileID = profID
		if err := fillReleaseEvidenceProfile(ev, profID); err != nil {
			return nil, err
		}
	}

	ev.Overall = aggregateReleaseOverall(ev.Checks)
	return ev, nil
}

func appendVersionChecks(ev *releaseEvidence) {
	ver := strings.TrimSpace(ev.Version.Version)
	cmt := strings.TrimSpace(ev.Version.Commit)
	st := "pass"
	msg := fmt.Sprintf("version=%s commit=%s", ver, cmt)
	if ver == "" || ver == "unknown" {
		st = "warn"
		msg = "version metadata empty or unknown (build without -ldflags -X version?)"
	}
	ev.Checks = append(ev.Checks, releaseCheck{
		ID:      "version_metadata",
		GateID:  "REL-002.compat.version",
		Status:  st,
		Message: msg,
	})
	// Separate commit field presence (release artifact identity).
	cst := "pass"
	cmsg := "commit field present"
	if cmt == "" || cmt == "unknown" || cmt == "none" {
		cst = "warn"
		cmsg = "commit empty or unknown (build without -ldflags -X commit?)"
	}
	ev.Checks = append(ev.Checks, releaseCheck{
		ID:      "version_commit",
		GateID:  "REL-002.compat.version",
		Status:  cst,
		Message: cmsg,
	})
}

func appendMCPSDKPin(ev *releaseEvidence, opts releaseEvidenceOptions) {
	pin, src, ok := resolveMCPSDKPin(opts)
	if !ok {
		ev.MCPSDK = &mcpSDKPin{Module: mcpSDKModule, Version: "", Source: "residual"}
		ev.Checks = append(ev.Checks, releaseCheck{
			ID:      "mcp_sdk_pin",
			GateID:  "REL-002.compat.mcp-sdk",
			Status:  "warn",
			Message: "MCP Go SDK version not resolved from build info or go.mod (ADR 0006 residual)",
		})
		return
	}
	ev.MCPSDK = &mcpSDKPin{Module: mcpSDKModule, Version: pin, Source: src}
	ev.Checks = append(ev.Checks, releaseCheck{
		ID:      "mcp_sdk_pin",
		GateID:  "REL-002.compat.mcp-sdk",
		Status:  "pass",
		Message: fmt.Sprintf("%s %s (source=%s)", mcpSDKModule, pin, src),
	})
}

// resolveMCPSDKPin prefers go.mod parse, then runtime/debug build info.
func resolveMCPSDKPin(opts releaseEvidenceOptions) (version, source string, ok bool) {
	content := opts.GoModContent
	if content == "" && strings.TrimSpace(opts.GoModPath) != "" {
		if b, err := os.ReadFile(opts.GoModPath); err == nil {
			content = string(b)
		}
	}
	if content != "" {
		if v, found := parseGoModRequire(content, mcpSDKModule); found {
			return v, "go.mod", true
		}
	}
	if v, found := mcpSDKFromBuildInfo(); found {
		return v, "build_info", true
	}
	return "", "residual", false
}

// parseGoModRequire extracts the version for a require module path from go.mod text.
// Handles both block and single-line require forms. Returns ("", false) if missing.
func parseGoModRequire(goMod string, modulePath string) (string, bool) {
	modulePath = strings.TrimSpace(modulePath)
	if modulePath == "" || goMod == "" {
		return "", false
	}
	inRequire := false
	for _, raw := range strings.Split(goMod, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		// Strip trailing line comments.
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire {
			if line == ")" {
				inRequire = false
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == modulePath {
				return fields[1], true
			}
			continue
		}
		// Single-line: require module version
		if strings.HasPrefix(line, "require ") {
			fields := strings.Fields(line)
			// require path version
			if len(fields) >= 3 && fields[1] == modulePath {
				return fields[2], true
			}
		}
	}
	return "", false
}

func mcpSDKFromBuildInfo() (string, bool) {
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi == nil {
		return "", false
	}
	for _, d := range bi.Deps {
		if d != nil && d.Path == mcpSDKModule && strings.TrimSpace(d.Version) != "" {
			return d.Version, true
		}
	}
	return "", false
}

func findGoModPath() string {
	// Walk up from cwd looking for go.mod (workspace / developer tree).
	// Installed binaries without a nearby go.mod fall back to build_info for the pin.
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	dir := wd
	for i := 0; i < 12; i++ {
		p := filepath.Join(dir, "go.mod")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func appendPolicyEngineSelfTest(ev *releaseEvidence) {
	// Deny-only empty document: valid subject + known read tool + empty target → Allow.
	evl := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	sub := policy.NewSubject("release-evidence-self-test", "jenkins-user", true)
	d := evl.Evaluate(sub, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if !d.Allowed() {
		ev.Checks = append(ev.Checks, releaseCheck{
			ID:      "policy_engine_self_test",
			GateID:  "REL-002.sec.policy",
			Status:  "fail",
			Message: fmt.Sprintf("expected Allow on empty deny-only doc + empty target; got effect=%s reason=%s", d.Effect, d.ReasonCode),
		})
		return
	}
	// Sanity: empty subject must still deny (fail closed).
	dEmpty := evl.Evaluate(policy.Subject{}, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if !dEmpty.Denied() {
		ev.Checks = append(ev.Checks, releaseCheck{
			ID:      "policy_engine_self_test",
			GateID:  "REL-002.sec.policy",
			Status:  "fail",
			Message: "expected Deny for empty subject on deny-only evaluator",
		})
		return
	}
	ev.Checks = append(ev.Checks, releaseCheck{
		ID:      "policy_engine_self_test",
		GateID:  "REL-002.sec.policy",
		Status:  "pass",
		Message: "deny-only empty document: empty target allows valid subject; empty subject denied",
	})
}

func appendSecuritySelfCheck(ctx context.Context, ev *releaseEvidence, opts releaseEvidenceOptions) {
	paths := opts.Paths
	if paths == nil {
		if p, err := config.Resolve(); err == nil {
			paths = &p
		}
	}
	var polPtr *policy.LoadResult
	if polRes, polErr := policy.LoadFromEnviron(); polErr == nil {
		polPtr = &polRes
	}
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{
		Paths:        paths,
		PolicyResult: polPtr,
		Version:      version,
		Commit:       commit,
		// Bundle canary is offline and cheap; keep it for production-readiness lite.
	})
	if err != nil {
		ev.Checks = append(ev.Checks, releaseCheck{
			ID:      "security_self_check",
			GateID:  "REL-002.sec.self-check",
			Status:  "fail",
			Message: apperr.ModelMessage(err),
		})
		return
	}
	failN, warnN := 0, 0
	for _, it := range rep.Items {
		switch it.Status {
		case diagnostics.SelfCheckFail:
			failN++
		case diagnostics.SelfCheckWarn:
			warnN++
		}
	}
	ev.SecuritySelfCheck = &securitySelfCheckSnap{
		Overall:                   string(rep.Overall),
		ItemCount:                 len(rep.Items),
		FailCount:                 failN,
		WarnCount:                 warnN,
		IndependentReviewRequired: rep.IndependentReviewRequired,
	}
	st := "pass"
	switch rep.Overall {
	case diagnostics.SelfCheckFail:
		st = "fail"
	case diagnostics.SelfCheckWarn:
		st = "warn"
	}
	ev.Checks = append(ev.Checks, releaseCheck{
		ID:     "security_self_check",
		GateID: "REL-002.sec.self-check",
		Status: st,
		Message: fmt.Sprintf("security self-check overall=%s items=%d fail=%d warn=%d independent_review_required=%v",
			rep.Overall, len(rep.Items), failN, warnN, rep.IndependentReviewRequired),
	})
}

func appendUpdateLKG(ev *releaseEvidence, opts releaseEvidenceOptions) {
	rec, _, err := update.LoadLKGFromEnviron(opts.Paths)
	if err != nil {
		// Corrupt LKG fails closed as warn for lite evidence (operator must repair).
		ev.UpdateLKG = &updateLKGSnap{
			Present: false,
			Note:    "LKG unreadable or corrupt (fail closed; remove or repair last_known_good.json)",
		}
		ev.Checks = append(ev.Checks, releaseCheck{
			ID:      "update_lkg",
			GateID:  "REL-002.ops.lkg",
			Status:  "warn",
			Message: "update LKG present but unreadable: " + apperr.ModelMessage(err),
		})
		return
	}
	if rec == nil {
		ev.UpdateLKG = &updateLKGSnap{
			Present: false,
			Note:    "no last-known-good update record (absent is OK before first verified download)",
		}
		ev.Checks = append(ev.Checks, releaseCheck{
			ID:      "update_lkg",
			GateID:  "REL-002.ops.lkg",
			Status:  "pass",
			Message: "LKG absent (note only; not a release blocker for offline lite)",
		})
		return
	}
	ev.UpdateLKG = &updateLKGSnap{
		Present:        true,
		Version:        rec.Version,
		Channel:        rec.Channel,
		ArtifactSHA256: rec.ArtifactSHA256,
		Note:           "LKG present after verified download; auto-install residual",
	}
	ev.Checks = append(ev.Checks, releaseCheck{
		ID:      "update_lkg",
		GateID:  "REL-002.ops.lkg",
		Status:  "pass",
		Message: fmt.Sprintf("LKG present version=%s channel=%s", rec.Version, rec.Channel),
	})
}

func appendGatewayQualify(ctx context.Context, ev *releaseEvidence) {
	sum := qualify.RunOffline(ctx)
	ev.GatewayQualify = &gatewayQualifySnap{
		Suite:  sum.Suite,
		OK:     sum.OK,
		Passed: sum.Passed,
		Failed: sum.Failed,
	}
	st := "pass"
	msg := fmt.Sprintf("gateway offline qualify ok=%v passed=%d failed=%d", sum.OK, sum.Passed, sum.Failed)
	if !sum.OK {
		st = "fail"
	}
	ev.Checks = append(ev.Checks, releaseCheck{
		ID:      "gateway_qualify_offline",
		GateID:  "REL-002.compat.gateway",
		Status:  st,
		Message: msg,
	})
}

func fillReleaseEvidenceProfile(ev *releaseEvidence, profileID string) error {
	ps, err := profileStore()
	if err != nil {
		return err
	}
	p, err := ps.Load(profileID)
	if err != nil {
		return err
	}
	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	var polPtr *policy.LoadResult
	if polRes, polErr := policy.LoadFromEnviron(); polErr == nil {
		polPtr = &polRes
	}
	docOpts := diagnostics.DoctorOptions{
		Profile:      p,
		Paths:        &paths,
		Keyring:      keyringStore(),
		Version:      version,
		Commit:       commit,
		BuildTime:    buildTime,
		SkipNetwork:  true,
		PolicyResult: polPtr,
	}
	rep, err := diagnostics.RunDoctor(context.Background(), docOpts)
	if err != nil {
		ev.Checks = append(ev.Checks, releaseCheck{
			ID:       "doctor_offline",
			GateID:   "REL-002.ops.doctor",
			Status:   "fail",
			Message:  apperr.ModelMessage(err),
			Optional: true,
		})
		// Do not force overall fail via early return without cache; still try cache.
	} else {
		snap := doctorSnap{Overall: string(rep.Overall), Checks: rep.Checks}
		ev.Doctor = &snap
		st := "pass"
		switch rep.Overall {
		case diagnostics.StatusFail:
			st = "fail"
		case diagnostics.StatusWarn:
			st = "warn"
		}
		ev.Checks = append(ev.Checks, releaseCheck{
			ID:       "doctor_offline",
			GateID:   "REL-002.ops.doctor",
			Status:   st,
			Message:  "doctor overall=" + string(rep.Overall),
			Optional: true,
		})
	}

	cs, csErr := diagnostics.RunCacheStatus(context.Background(), diagnostics.CacheStatusOptions{
		Profile: p,
		Paths:   &paths,
	})
	if csErr != nil {
		ev.Checks = append(ev.Checks, releaseCheck{
			ID:       "cache_status",
			GateID:   "REL-002.ops.cache",
			Status:   "fail",
			Message:  apperr.ModelMessage(csErr),
			Optional: true,
		})
	} else {
		c := cacheSnap{
			DataDirOK:     cs.DataDirOK,
			StoreOpen:     cs.StoreOpen,
			SchemaOK:      cs.SchemaOK,
			SchemaVersion: cs.SchemaVersion,
			Generations:   cs.Generations,
			Chunks:        cs.Chunks,
			Message:       redact.Secrets(cs.StoreMessage),
		}
		ev.CacheStatus = &c
		cst := "pass"
		if !cs.DataDirOK || !cs.StoreOpen || !cs.SchemaOK {
			cst = "warn"
		}
		msg := cs.StoreMessage
		if msg == "" {
			msg = cs.DataDirMessage
		}
		ev.Checks = append(ev.Checks, releaseCheck{
			ID:       "cache_status",
			GateID:   "REL-002.ops.cache",
			Status:   cst,
			Message:  redact.Secrets(msg),
			Optional: true,
		})
	}
	return nil
}

// aggregateReleaseOverall computes overall for lite evidence.
// Optional skips (doctor/cache without profile) do not force incomplete when core checks pass.
func aggregateReleaseOverall(checks []releaseCheck) string {
	hasFail, hasWarn := false, false
	coreSeen, corePass := 0, 0
	for _, c := range checks {
		if c.Optional && c.Status == "skip" {
			continue
		}
		switch c.Status {
		case "fail":
			hasFail = true
		case "warn":
			hasWarn = true
		case "pass":
			if !c.Optional {
				coreSeen++
				corePass++
			}
		case "skip":
			if !c.Optional {
				// Unexpected skip of a core check.
				coreSeen++
			}
		}
	}
	if hasFail {
		return "fail"
	}
	if hasWarn {
		return "warn"
	}
	if corePass > 0 && coreSeen == corePass {
		return "pass"
	}
	if corePass == 0 {
		return "incomplete"
	}
	return "incomplete"
}

func scrubReleaseEvidence(ev *releaseEvidence) {
	if ev == nil {
		return
	}
	for i := range ev.Checks {
		ev.Checks[i].Message = redact.Secrets(ev.Checks[i].Message)
	}
	for i := range ev.Notes {
		ev.Notes[i] = redact.Secrets(ev.Notes[i])
	}
	for i := range ev.Residual {
		ev.Residual[i].Message = redact.Secrets(ev.Residual[i].Message)
		ev.Residual[i].ID = redact.Secrets(ev.Residual[i].ID)
	}
	if ev.UpdateLKG != nil {
		ev.UpdateLKG.Note = redact.Secrets(ev.UpdateLKG.Note)
		ev.UpdateLKG.Version = redact.Secrets(ev.UpdateLKG.Version)
		ev.UpdateLKG.Channel = redact.Secrets(ev.UpdateLKG.Channel)
	}
	if ev.MCPSDK != nil {
		ev.MCPSDK.Version = redact.Secrets(ev.MCPSDK.Version)
		ev.MCPSDK.Source = redact.Secrets(ev.MCPSDK.Source)
	}
}

// assertReleaseEvidenceSecretFree is a last-line canary before writing output.
func assertReleaseEvidenceSecretFree(payload []byte) error {
	lower := strings.ToLower(string(payload))
	// Hard-fail on classic secret headers in evidence JSON.
	if strings.Contains(lower, "authorization: bearer ") ||
		strings.Contains(lower, "basic ") && strings.Contains(lower, "authorization") {
		return apperr.New(apperr.CodeInternal, "release evidence output failed secret canary (authorization material)")
	}
	// Private key markers must never appear.
	if strings.Contains(string(payload), "BEGIN PRIVATE KEY") ||
		strings.Contains(string(payload), "BEGIN RSA PRIVATE KEY") {
		return apperr.New(apperr.CodeInternal, "release evidence output failed secret canary (private key material)")
	}
	return nil
}
