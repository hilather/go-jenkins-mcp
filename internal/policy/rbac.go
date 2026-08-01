package policy

import (
	"fmt"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// DecisionEffect is the allow/deny outcome of MCP policy evaluation (POL-002).
// MCP RBAC is deny-only: Allow means "MCP does not further restrict"; it never
// grants Jenkins access that Jenkins itself denied.
type DecisionEffect string

const (
	// EffectAllow means MCP policy does not deny this request.
	// Jenkins permissions and read-only/budgets still apply.
	EffectAllow DecisionEffect = "allow"
	// EffectDeny means MCP policy denies this request.
	EffectDeny DecisionEffect = "deny"
)

// Reason codes for Decision (stable, non-secret, model-safe).
const (
	ReasonOK                = "ok"
	ReasonExplicitDeny      = "explicit_deny"
	ReasonUnknownTool       = "unknown_tool"
	ReasonSubjectEmpty      = "subject_empty"
	ReasonSubjectAnon       = "subject_anonymous"
	ReasonSubjectUnverified = "subject_unverified"
	ReasonSubjectInvalid    = "subject_invalid"
	ReasonNoEvaluator       = "no_evaluator"
	ReasonJobPatternDeny    = "job_pattern_deny"
	// ReasonResourcePatternDeny is used for non-job resource denies
	// (deny_node_names / deny_view_names / deny_artifact_paths / deny_branch_names;
	// Wave 35/36/37).
	ReasonResourcePatternDeny = "resource_pattern_deny"
)

// Action identifies what the caller is attempting (tool / effect class).
type Action struct {
	// ToolName is the MCP tool name (e.g. jenkins_get_jobs).
	ToolName string
	// Class is the side-effect class (read/mutate/auth).
	Class EffectClass
}

// Target is an optional resource scope for evaluation (POL-002 / POL-004 lite).
// JobName is the concrete job; JobPattern is reserved for rule patterns.
// BuildNumber is optional call-time scope (populated when args include it);
// job deny rules key on JobName (glob-lite pattern match).
// NodeName / ViewName / ArtifactPath / BranchName are optional non-job resources
// (Wave 35/36/37).
type Target struct {
	// JobName is the concrete Jenkins job full name when known.
	JobName string
	// JobPattern is reserved for future rule-side patterns; empty = any.
	// Call-time denials use Document.DenyJobPrefixes against JobName.
	JobPattern string
	// BuildNumber is the concrete build number when known (>0). Informational
	// for MVP denials; evaluator job rules match JobName only.
	BuildNumber int64
	// NodeName is the concrete Jenkins node/agent name when known (Wave 35).
	// Call-time denials use Document.DenyNodeNames against this field
	// (same pattern language as deny_job_prefixes).
	NodeName string
	// ViewName is the concrete Jenkins view name when known (Wave 35).
	// Call-time denials use Document.DenyViewNames against this field.
	ViewName string
	// ArtifactPath is the relative build artifact path when known (Wave 36).
	// Call-time denials use Document.DenyArtifactPaths against this field
	// (same pattern language as deny_job_prefixes; '/' separators).
	ArtifactPath string
	// BranchName is the multibranch/matrix branch leaf or relative name when
	// known (Wave 37). Call-time denials use Document.DenyBranchNames against
	// this field (same pattern language as deny_job_prefixes). When empty,
	// Wave 38–39 also match DenyBranchNames against multi-segment JobName
	// candidates (leaf, intermediate segments, path suffixes, full JobName) —
	// see BranchDenyCandidates and DenyOnlyEvaluator.Evaluate.
	BranchName string
}

// Decision is the evaluator outcome (POL-002).
type Decision struct {
	Effect     DecisionEffect
	ReasonCode string
	// MatchedRule is a short rule id (e.g. deny_tools:jenkins_get_job).
	MatchedRule string
	// Explanation is a safe, short, model-visible message (no secrets).
	Explanation string
}

// Allowed reports whether Effect is Allow.
func (d Decision) Allowed() bool { return d.Effect == EffectAllow }

// Denied reports whether Effect is Deny.
func (d Decision) Denied() bool { return d.Effect == EffectDeny }

// Err converts a deny decision into a policy_denial apperr.
// Allow decisions return nil.
func (d Decision) Err() error {
	if d.Allowed() {
		return nil
	}
	msg := d.Explanation
	if msg == "" {
		msg = "denied by MCP policy"
	}
	return apperr.New(apperr.CodePolicyDenial, msg)
}

// Document is the in-memory deny-only policy used by the evaluator (POL-002).
// Built from Overlay or test fixtures. Cannot grant privileges.
type Document struct {
	// Mode is pilot (default allow reads) or strict (deny unknown tools).
	Mode PolicyMode
	// DenyTools is an exact-match deny set of tool names.
	DenyTools map[string]struct{}
	// DenyJobPrefixes optionally denies when Target.JobName matches a pattern
	// (exact, folder children, trailing /**, single-segment * — see MatchDenyJobPattern).
	// Empty means no job-pattern restriction from this document.
	DenyJobPrefixes []string
	// DenyNodeNames optionally denies when Target.NodeName matches a pattern
	// (same language as DenyJobPrefixes via MatchDenyJobPattern). Wave 35.
	DenyNodeNames []string
	// DenyViewNames optionally denies when Target.ViewName matches a pattern
	// (same language as DenyJobPrefixes via MatchDenyJobPattern). Wave 35.
	DenyViewNames []string
	// DenyArtifactPaths optionally denies when Target.ArtifactPath matches a
	// pattern (same language as DenyJobPrefixes via MatchDenyJobPattern). Wave 36.
	DenyArtifactPaths []string
	// DenyBranchNames optionally denies when Target.BranchName matches a
	// pattern (same language as DenyJobPrefixes via MatchDenyJobPattern). Wave 37.
	// Wave 38–39: when BranchName is empty and JobName has ≥2 path segments,
	// also matches BranchDenyCandidates (leaf, intermediate segments from
	// index 1, multi-segment suffixes, full JobName). Single-segment JobName
	// alone does not apply branch deny (avoids freestyle job "main"). Slashy
	// BranchName (≥2 segments) also matches its leaf (and other candidates).
	DenyBranchNames []string
	// MaxResultBytes optionally lowers result hard max (0 = unset).
	MaxResultBytes int
	// MaxToolsPerMinute optionally lowers per-subject tool rate (0 = unset; HOST-006).
	MaxToolsPerMinute int
	// MaxToolsBurst optionally lowers per-subject burst (0 = unset; HOST-006).
	MaxToolsBurst int
	// ForceReadOnly mirrors overlay force_read_only for status.
	ForceReadOnly bool
	// FleetTelemetryForceOff mirrors overlay fleet_telemetry_force_off (MGR-002).
	FleetTelemetryForceOff bool
	// Version is the source overlay version (0 if synthetic).
	Version int
	// RequireVerifiedSubject when true denies subjects with Verified=false.
	// Pilot default is false so provisional session usernames can be used until AUTH-004.
	// Set true in enterprise mode when identity verification is mandatory.
	RequireVerifiedSubject bool
}

// DocumentFromOverlay builds a Document from a loaded overlay.
// nil overlay → empty pilot document (no denials).
func DocumentFromOverlay(o *Overlay) Document {
	if o == nil {
		return Document{Mode: ModePilot}
	}
	doc := Document{
		Mode:                   o.NormalizeMode(),
		DenyTools:              o.DenyToolSet(),
		DenyJobPrefixes:        o.DenyJobPrefixList(),
		DenyNodeNames:          o.DenyNodeNameList(),
		DenyViewNames:          o.DenyViewNameList(),
		DenyArtifactPaths:      o.DenyArtifactPathList(),
		DenyBranchNames:        o.DenyBranchNameList(),
		ForceReadOnly:          o.ForceReadOnly,
		FleetTelemetryForceOff: o.FleetTelemetryForceOff,
		Version:                o.Version,
	}
	if n, ok := o.EffectiveMaxResultBytes(); ok {
		doc.MaxResultBytes = n
	}
	if n, ok := o.EffectiveMaxToolsPerMinute(); ok {
		doc.MaxToolsPerMinute = n
	}
	if n, ok := o.EffectiveMaxToolsBurst(); ok {
		doc.MaxToolsBurst = n
	}
	return doc
}

// PolicyEvaluator is the MCP deny-only decision point (architecture §5.2).
// Implementations must never elevate Jenkins allow.
type PolicyEvaluator interface {
	// Evaluate returns Allow or Deny for subject/action/target.
	// Subject must come from verified process identity, not tool args.
	Evaluate(subject Subject, action Action, target Target) Decision
}

// DenyOnlyEvaluator is the pilot implementation of PolicyEvaluator (POL-002).
//
// Rules (deterministic, no network, no code execution):
//  1. Invalid/empty/anonymous subject → Deny (POL-003).
//  2. RequireVerifiedSubject && !subject.Verified → Deny.
//  3. Explicit deny_tools match → Deny.
//  4. Optional deny job-prefix match → Deny.
//  5. Optional deny_node_names / deny_view_names match → Deny (Wave 35).
//  6. Optional deny_artifact_paths match → Deny (Wave 36).
//  7. Optional deny_branch_names match → Deny (Wave 37 BranchName; Wave 38
//     multi-segment JobName leaf / full when BranchName empty).
//  8. ModeStrict && tool not a known seed/classified tool → Deny.
//  9. Otherwise → Allow (MCP does not further restrict).
//
// Jenkins remains authoritative: Allow here still requires Jenkins allow.
type DenyOnlyEvaluator struct {
	doc Document
}

// NewDenyOnlyEvaluator constructs an evaluator from a Document.
func NewDenyOnlyEvaluator(doc Document) *DenyOnlyEvaluator {
	if doc.Mode == "" {
		doc.Mode = ModePilot
	}
	return &DenyOnlyEvaluator{doc: doc}
}

// NewDenyOnlyFromOverlay is a convenience constructor.
func NewDenyOnlyFromOverlay(o *Overlay) *DenyOnlyEvaluator {
	return NewDenyOnlyEvaluator(DocumentFromOverlay(o))
}

// Document returns a copy of the underlying document (for status/tests).
func (e *DenyOnlyEvaluator) Document() Document {
	if e == nil {
		return Document{Mode: ModePilot}
	}
	return e.doc
}

// Evaluate implements PolicyEvaluator.
func (e *DenyOnlyEvaluator) Evaluate(subject Subject, action Action, target Target) Decision {
	// Fail closed on nil receiver (missing policy evaluator when required).
	if e == nil {
		return Decision{
			Effect:      EffectDeny,
			ReasonCode:  ReasonNoEvaluator,
			Explanation: "MCP policy evaluator is not configured (fail closed)",
		}
	}

	if d := checkSubject(subject, e.doc.RequireVerifiedSubject); d.Denied() {
		return d
	}

	tool := strings.TrimSpace(action.ToolName)
	if tool == "" {
		return Decision{
			Effect:      EffectDeny,
			ReasonCode:  ReasonUnknownTool,
			Explanation: "tool name is required for policy evaluation",
		}
	}

	// Explicit deny by tool name (works for any Jenkins role, including admin).
	if e.doc.DenyTools != nil {
		if _, denied := e.doc.DenyTools[tool]; denied {
			return Decision{
				Effect:      EffectDeny,
				ReasonCode:  ReasonExplicitDeny,
				MatchedRule: "deny_tools:" + tool,
				Explanation: fmt.Sprintf("tool %q denied by MCP policy", tool),
			}
		}
	}

	// Optional job pattern denials (restrict targets further).
	// Glob-lite: exact / folder children, trailing /**, single-segment *, mid-path **/
	// (Wave 26/29), limited {a,b} brace expansion (Wave 30). Not bare string prefixes
	// (avoids "secret-folder" matching "secret-folder-other").
	job := strings.TrimSpace(target.JobName)
	if job != "" {
		for _, prefix := range e.doc.DenyJobPrefixes {
			prefix = strings.TrimSpace(prefix)
			if prefix == "" {
				continue
			}
			if MatchDenyJobPattern(prefix, job) {
				return Decision{
					Effect:      EffectDeny,
					ReasonCode:  ReasonJobPatternDeny,
					MatchedRule: "deny_job_prefix:" + prefix,
					Explanation: fmt.Sprintf("job %q denied by MCP policy", job),
				}
			}
		}
	}

	// Wave 35/36: non-job resource patterns (same MatchDenyJobPattern language).
	// Checked after job prefixes when Target carries NodeName / ViewName / ArtifactPath.
	node := strings.TrimSpace(target.NodeName)
	if node != "" {
		for _, pat := range e.doc.DenyNodeNames {
			pat = strings.TrimSpace(pat)
			if pat == "" {
				continue
			}
			if MatchDenyJobPattern(pat, node) {
				return Decision{
					Effect:      EffectDeny,
					ReasonCode:  ReasonResourcePatternDeny,
					MatchedRule: "deny_node_name:" + pat,
					Explanation: fmt.Sprintf("node %q denied by MCP policy", node),
				}
			}
		}
	}
	view := strings.TrimSpace(target.ViewName)
	if view != "" {
		for _, pat := range e.doc.DenyViewNames {
			pat = strings.TrimSpace(pat)
			if pat == "" {
				continue
			}
			if MatchDenyJobPattern(pat, view) {
				return Decision{
					Effect:      EffectDeny,
					ReasonCode:  ReasonResourcePatternDeny,
					MatchedRule: "deny_view_name:" + pat,
					Explanation: fmt.Sprintf("view %q denied by MCP policy", view),
				}
			}
		}
	}
	// Wave 36: artifact path patterns (relative paths with '/' separators).
	art := strings.TrimSpace(target.ArtifactPath)
	if art != "" {
		for _, pat := range e.doc.DenyArtifactPaths {
			pat = strings.TrimSpace(pat)
			if pat == "" {
				continue
			}
			if MatchDenyJobPattern(pat, art) {
				return Decision{
					Effect:      EffectDeny,
					ReasonCode:  ReasonResourcePatternDeny,
					MatchedRule: "deny_artifact_path:" + pat,
					Explanation: fmt.Sprintf("artifact path %q denied by MCP policy", art),
				}
			}
		}
	}
	// Wave 37/38/39: multibranch/matrix branch name patterns (deny-only).
	// 1. Target.BranchName non-empty → match BranchName (Wave 37); when slashy
	//    (≥2 segments), also match leaf and other BranchDenyCandidates (Wave 39).
	// 2. Else multi-segment JobName (≥2 segments after normalize): match
	//    BranchDenyCandidates (leaf, intermediate segs[1..], path suffixes,
	//    full) so tools that only pass job_name still fail closed — including
	//    nested slashy leaves like team/mb/release/1.2 vs release/* (Wave 38–39).
	// Single-segment JobName does not apply branch deny via candidates — a root
	// freestyle job named "main" is not treated as a multibranch leaf unless
	// BranchName is set explicitly. Explicit non-empty BranchName does not
	// fall through to JobName candidates.
	branch := strings.TrimSpace(target.BranchName)
	if branch != "" {
		cands := branchNameDenyCandidates(branch)
		for _, pat := range e.doc.DenyBranchNames {
			pat = strings.TrimSpace(pat)
			if pat == "" {
				continue
			}
			for _, cand := range cands {
				if MatchDenyJobPattern(pat, cand) {
					return Decision{
						Effect:      EffectDeny,
						ReasonCode:  ReasonResourcePatternDeny,
						MatchedRule: "deny_branch_name:" + pat,
						Explanation: fmt.Sprintf("branch %q denied by MCP policy", cand),
					}
				}
			}
		}
	} else if len(e.doc.DenyBranchNames) > 0 && job != "" {
		jobNorm, ok := NormalizeJobFullName(job)
		if ok && jobNorm != "" {
			cands := BranchDenyCandidates(jobNorm)
			if len(cands) > 0 {
				leaf := cands[0] // BranchDenyCandidates puts leaf first
				for _, pat := range e.doc.DenyBranchNames {
					pat = strings.TrimSpace(pat)
					if pat == "" {
						continue
					}
					for _, cand := range cands {
						if !MatchDenyJobPattern(pat, cand) {
							continue
						}
						return Decision{
							Effect:      EffectDeny,
							ReasonCode:  ReasonResourcePatternDeny,
							MatchedRule: "deny_branch_name:" + pat,
							Explanation: branchDenyJobExplanation(cand, leaf, jobNorm),
						}
					}
				}
			}
		}
	}

	// Strict mode: unknown/unclassified tools default deny.
	if e.doc.Mode == ModeStrict {
		if !IsKnownSeedTool(tool) {
			return Decision{
				Effect:      EffectDeny,
				ReasonCode:  ReasonUnknownTool,
				MatchedRule: "mode:strict",
				Explanation: fmt.Sprintf("tool %q denied: unknown tool under strict MCP policy", tool),
			}
		}
	}

	// Pilot (and strict known tools): default allow unless denied above.
	// Mutations remain gated by ReadOnlyGate separately.
	return Decision{
		Effect:     EffectAllow,
		ReasonCode: ReasonOK,
	}
}

// ToolDenied is a convenience for registry filtering (tool name only).
func (e *DenyOnlyEvaluator) ToolDenied(subject Subject, toolName string) Decision {
	class := ToolEffect(toolName)
	return e.Evaluate(subject, Action{ToolName: toolName, Class: class}, Target{})
}

// BranchDenyCandidates returns path fragments of a multi-segment normalized
// JobName to match against deny_branch_names (Wave 38–39). Single-segment and
// empty inputs return nil (caller must not apply JobName-based branch deny).
//
// For jobNorm "a/b/c/d" the candidates are (order, de-duplicated):
//
//	d              — leaf (last segment)
//	b, c           — intermediate single segments segs[1..n-2] (not segs[0])
//	c/d, b/c/d     — multi-segment suffixes starting at i=1..n-2
//	a/b/c/d        — full path
//
// segs[0] alone is never a candidate (folder root is not treated as a branch).
// Pure helper for testability.
func BranchDenyCandidates(jobNorm string) []string {
	jobNorm = strings.TrimSpace(jobNorm)
	if jobNorm == "" {
		return nil
	}
	segs := strings.Split(jobNorm, "/")
	if len(segs) < 2 {
		return nil
	}
	seen := make(map[string]struct{}, len(segs)*2)
	out := make([]string, 0, len(segs)*2)
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	// 1. Leaf first (Wave 38).
	add(segs[len(segs)-1])

	// 2. Intermediate single segments segs[1..n-2] (not first folder, not leaf).
	for i := 1; i < len(segs)-1; i++ {
		add(segs[i])
	}

	// 3. Multi-segment suffixes starting at i for i=1..n-2 (length ≥ 2, not full).
	//    e.g. a/b/c/d → c/d, b/c/d
	for i := len(segs) - 2; i >= 1; i-- {
		add(strings.Join(segs[i:], "/"))
	}

	// 4. Full normalized path.
	add(jobNorm)
	return out
}

// branchNameDenyCandidates returns match candidates for an explicit BranchName
// (Wave 37/39). Always includes at least the trimmed input. When the name is
// multi-segment after normalize, uses BranchDenyCandidates (leaf + suffixes +
// intermediates + full) so release/* matches BranchName "release/1.2" and leaf
// patterns match the last segment.
func branchNameDenyCandidates(branch string) []string {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return nil
	}
	branchNorm, ok := NormalizeJobFullName(branch)
	if !ok || branchNorm == "" {
		return []string{branch}
	}
	if cands := BranchDenyCandidates(branchNorm); len(cands) > 0 {
		return cands
	}
	return []string{branchNorm}
}

// branchDenyJobExplanation builds the model-safe explanation for a JobName-path
// branch deny. Preserves Wave 38 wording for leaf and full-path matches.
func branchDenyJobExplanation(cand, leaf, jobNorm string) string {
	switch cand {
	case leaf:
		return fmt.Sprintf("branch leaf %q of job %q denied by MCP policy", leaf, jobNorm)
	case jobNorm:
		return fmt.Sprintf("job %q denied by MCP branch policy", jobNorm)
	default:
		return fmt.Sprintf("branch path %q of job %q denied by MCP policy", cand, jobNorm)
	}
}

func checkSubject(subject Subject, requireVerified bool) Decision {
	if subject.IsEmpty() {
		return Decision{
			Effect:      EffectDeny,
			ReasonCode:  ReasonSubjectEmpty,
			Explanation: "MCP policy requires a bound subject (empty identity)",
		}
	}
	if subject.IsAnonymous() {
		return Decision{
			Effect:      EffectDeny,
			ReasonCode:  ReasonSubjectAnon,
			Explanation: "MCP policy rejects anonymous Jenkins identity",
		}
	}
	if strings.TrimSpace(string(subject.ProfileID)) == "" {
		return Decision{
			Effect:      EffectDeny,
			ReasonCode:  ReasonSubjectInvalid,
			Explanation: "MCP policy requires a profile-bound subject",
		}
	}
	if requireVerified && !subject.Verified {
		return Decision{
			Effect:      EffectDeny,
			ReasonCode:  ReasonSubjectUnverified,
			Explanation: "MCP policy requires a verified Jenkins principal",
		}
	}
	return Decision{Effect: EffectAllow, ReasonCode: ReasonOK}
}

// Known seed tool names for strict-mode classification (POL-002).
// Keep in sync with tools.Register inventory.
// StoreReadAction is a synthetic POL-004 store PEP action (not an MCP tool).
var knownSeedTools = map[string]struct{}{
	"jenkins_get_jobs":               {},
	"jenkins_get_job":                {},
	"jenkins_get_running_builds":     {},
	"jenkins_get_build":              {},
	"jenkins_get_build_logs":         {},
	"jenkins_get_build_log_tail":     {},
	"jenkins_get_queue_item":         {},
	"jenkins_wait_for_queue_item":    {},
	"jenkins_search_builds":          {},
	"jenkins_wait_for_running_build": {},
	"jenkins_list_jobs":              {},
	"jenkins_list_builds":            {},
	"jenkins_resolve_baseline":       {},
	"jenkins_get_build_graph":        {},
	"jenkins_get_stage_log":          {},
	"jenkins_analyze_tests":          {},
	"jenkins_list_artifacts":         {},
	"jenkins_get_artifact_text":      {},
	"jenkins_inspect_artifact":       {}, // ART-002
	"jenkins_get_build_changes":      {}, // SCM-001
	"jenkins_mirror_logs":            {}, // LOG-004 multi-log collection
	"jenkins_search_logs":            {}, // SEARCH-001/002
	"jenkins_get_trace_refs":         {}, // INT-002
	"jenkins_export_trace_refs":      {}, // INT-002 export stub
	"jenkins_query_external_logs":    {}, // INT-003
	"jenkins_get_change_correlation": {}, // INT-004
	"jenkins_diagnose_build":         {},
	"jenkins_survey_recent_failures": {}, // DIAG-006
	"jenkins_compare_builds":         {}, // DIAG-003
	"jenkins_find_regression_window": {}, // DIAG-004
	"jenkins_trace_failure_graph":    {}, // DIAG-005
	"jenkins_explain_queue_delay":    {}, // DIAG-007
	"jenkins_controller_health":      {}, // HEALTH-002
	"jenkins_doctor":                 {},
	"jenkins_queue_pressure":         {},
	"jenkins_get_nodes":              {},
	"jenkins_get_node":               {}, // Wave 36 named-node (deny_node_names)
	"jenkins_list_views":             {}, // Wave 38 list-all views + deny_view_names filter
	"jenkins_get_test_report":        {},
	"jenkins_get_pipeline_stages":    {},
	"jenkins_get_capabilities":       {},

	ToolStartJob:               {},
	ToolStopBuild:              {},
	ToolCancelQueueItem:        {},
	ToolInterruptBuild:         {},
	ToolRebuildBuild:           {},
	ToolReplayPipeline:         {},
	ToolSetJobBuildable:        {},
	ToolSetBuildKeepForever:    {},
	ToolSetBuildDescription:    {},
	ToolCancelQueueItemsForJob: {},
	StoreReadAction:            {},
}

// IsKnownSeedTool reports whether name is in the pilot seed tool inventory.
func IsKnownSeedTool(name string) bool {
	_, ok := knownSeedTools[strings.TrimSpace(name)]
	return ok
}

// AllowAllEvaluator always allows (tests only when no overlay denials).
// Still enforces subject validity so empty subjects fail closed.
type AllowAllEvaluator struct {
	RequireVerified bool
}

// Evaluate implements PolicyEvaluator.
func (a AllowAllEvaluator) Evaluate(subject Subject, action Action, target Target) Decision {
	if d := checkSubject(subject, a.RequireVerified); d.Denied() {
		return d
	}
	_ = action
	_ = target
	return Decision{Effect: EffectAllow, ReasonCode: ReasonOK}
}
