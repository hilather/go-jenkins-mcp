package tools

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// Wave 42: configurable jenkins_list_artifacts hard cap when deny_artifact_paths
// force a hard-cap fetch (Wave 40) and as the upper bound for caller max_artifacts.
// Wave 43: configurable ListArtifacts JSON body bound (default 2 MiB, absolute 8 MiB).
const (
	// EnvArtifactsHardCap is the serve env for the artifacts list hard cap.
	// CLI --artifacts-hard-cap overrides when set. Empty/0 →
	// jenkins.DefaultArtifactsHardCap. Invalid values and values above
	// jenkins.AbsoluteMaxArtifactsHardCap fail closed at serve start.
	EnvArtifactsHardCap = "JENKINS_MCP_ARTIFACTS_HARD_CAP"
	// EnvArtifactsListBodyBytes is the serve env for the ListArtifacts JSON
	// body bound. CLI --artifacts-list-body-bytes overrides when set. Empty/0 →
	// jenkins.DefaultArtifactListBodyBytes. Invalid values and values above
	// jenkins.AbsoluteMaxArtifactListBodyBytes fail closed at serve start.
	EnvArtifactsListBodyBytes = "JENKINS_MCP_ARTIFACTS_LIST_BODY_BYTES"
)

// artifactsHardCap is the live process artifacts list hard cap (package-level
// so tests can override and serve can set once from ResolveArtifactsHardCap).
// Defaults to jenkins.DefaultArtifactsHardCap (500).
var artifactsHardCap = jenkins.DefaultArtifactsHardCap

// SetArtifactsHardCap sets the process artifacts list hard cap after a
// successful ResolveArtifactsHardCap (serve start). Non-positive n uses
// jenkins.DefaultArtifactsHardCap. Oversize values are clamped to
// AbsoluteMaxArtifactsHardCap as belt-and-suspenders (resolve already fail-closed).
func SetArtifactsHardCap(n int) {
	if n <= 0 {
		n = jenkins.DefaultArtifactsHardCap
	}
	if n > jenkins.AbsoluteMaxArtifactsHardCap {
		n = jenkins.AbsoluteMaxArtifactsHardCap
	}
	artifactsHardCap = n
}

// ArtifactsHardCap returns the live process artifacts list hard cap
// (diagnostics/tests and listArtifactsWithPolicyFilter).
func ArtifactsHardCap() int {
	return artifactsHardCap
}

// ResolveArtifactsHardCap resolves the jenkins_list_artifacts process hard cap
// (Wave 42). Operators of large builds may raise the hard-stop used when
// deny_artifact_paths force a hard-cap fetch, up to AbsoluteMax.
//
// Precedence (later wins): jenkins.DefaultArtifactsHardCap → envVal → flagVal.
// Empty / whitespace means unset at that layer. Positive integers are accepted.
// Zero (explicit "0") at the winning layer means DefaultArtifactsHardCap.
// Negative or non-integer values fail closed (error); never clamp silently.
// After resolve, n must be ≤ jenkins.AbsoluteMaxArtifactsHardCap; oversize
// values error (no secrets).
func ResolveArtifactsHardCap(flagVal, envVal string) (int, error) {
	n := jenkins.DefaultArtifactsHardCap
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseArtifactsHardCapValue(raw, "env "+EnvArtifactsHardCap)
		if err != nil {
			return 0, err
		}
		n = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseArtifactsHardCapValue(raw, "flag --artifacts-hard-cap")
		if err != nil {
			return 0, err
		}
		n = v
	}
	if n > jenkins.AbsoluteMaxArtifactsHardCap {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"artifacts hard cap exceeds absolute maximum bound ("+
				strconv.Itoa(jenkins.AbsoluteMaxArtifactsHardCap)+")")
	}
	return n, nil
}

func parseArtifactsHardCapValue(raw, source string) (int, error) {
	v, err := strconv.ParseInt(raw, 10, 0)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid artifacts hard cap from "+source+" (positive integer, or 0 for default): "+raw)
	}
	if v < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"artifacts hard cap from "+source+" must not be negative")
	}
	if v == 0 {
		return jenkins.DefaultArtifactsHardCap, nil
	}
	return int(v), nil
}

// ResolveArtifactsListBodyBytes resolves the ListArtifacts JSON body bound
// (Wave 43). Operators of large builds with long paths near
// AbsoluteMaxArtifactsHardCap may raise the raw list JSON budget up to
// AbsoluteMaxArtifactListBodyBytes so the count hard cap is reached before
// the body limit truncates invalid JSON.
//
// Precedence (later wins): jenkins.DefaultArtifactListBodyBytes → envVal → flagVal.
// Empty / whitespace means unset at that layer. Positive integers are accepted.
// Zero (explicit "0") at the winning layer means DefaultArtifactListBodyBytes.
// Negative or non-integer values fail closed (error); never clamp silently.
// After resolve, n must be ≤ jenkins.AbsoluteMaxArtifactListBodyBytes; oversize
// values error (no secrets).
func ResolveArtifactsListBodyBytes(flagVal, envVal string) (int, error) {
	n := jenkins.DefaultArtifactListBodyBytes
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseArtifactsListBodyBytesValue(raw, "env "+EnvArtifactsListBodyBytes)
		if err != nil {
			return 0, err
		}
		n = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseArtifactsListBodyBytesValue(raw, "flag --artifacts-list-body-bytes")
		if err != nil {
			return 0, err
		}
		n = v
	}
	if n > jenkins.AbsoluteMaxArtifactListBodyBytes {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"artifacts list body bytes exceeds absolute maximum bound ("+
				strconv.Itoa(jenkins.AbsoluteMaxArtifactListBodyBytes)+")")
	}
	return n, nil
}

func parseArtifactsListBodyBytesValue(raw, source string) (int, error) {
	v, err := strconv.ParseInt(raw, 10, 0)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid artifacts list body bytes from "+source+" (positive integer, or 0 for default): "+raw)
	}
	if v < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"artifacts list body bytes from "+source+" must not be negative")
	}
	if v == 0 {
		return jenkins.DefaultArtifactListBodyBytes, nil
	}
	return int(v), nil
}

// FilterDeniedArtifacts drops ArtifactMeta rows whose Path matches any
// deny_artifact_paths pattern (MatchDenyJobPattern). Paths are matched raw and,
// when different, after the same "." / empty-segment collapse used for
// Target.ArtifactPath (normalizeArtifactPathForTarget) so list rows cannot
// bypass exact denies with exact/./file forms.
//
// Deny-only: never invents artifacts. Empty patterns returns a shallow copy of
// arts and omitted=0.
//
// Regression: Wave 37 list-row privacy for jenkins_list_artifacts.
func FilterDeniedArtifacts(patterns []string, arts []jenkins.ArtifactMeta) (kept []jenkins.ArtifactMeta, omitted int) {
	if len(patterns) == 0 {
		if arts == nil {
			return nil, 0
		}
		out := make([]jenkins.ArtifactMeta, len(arts))
		copy(out, arts)
		return out, 0
	}
	kept = make([]jenkins.ArtifactMeta, 0, len(arts))
	for _, a := range arts {
		if artifactPathDeniedByPatterns(patterns, a.Path) {
			omitted++
			continue
		}
		kept = append(kept, a)
	}
	return kept, omitted
}

// artifactPathDeniedByPatterns reports whether path matches any deny pattern
// either as listed or after Target-style path clean (collapse ".").
func artifactPathDeniedByPatterns(patterns []string, path string) bool {
	path = strings.TrimSpace(path)
	if path == "" || len(patterns) == 0 {
		return false
	}
	if policy.NameDeniedByPatterns(patterns, path) {
		return true
	}
	cleaned := normalizeArtifactPathForTarget(path)
	if cleaned != "" && cleaned != path {
		return policy.NameDeniedByPatterns(patterns, cleaned)
	}
	return false
}

// FilterDeniedArtifactDiffs drops CompareArtifactDiff entries whose Path matches
// any deny_artifact_paths pattern (same raw + cleaned match as FilterDeniedArtifacts).
// Deny-only privacy for jenkins_compare_builds artifact_path_diffs (Wave 39).
// Empty patterns returns a shallow copy of diffs and omitted=0.
func FilterDeniedArtifactDiffs(patterns []string, diffs []CompareArtifactDiff) (kept []CompareArtifactDiff, omitted int) {
	if len(patterns) == 0 {
		if diffs == nil {
			return nil, 0
		}
		out := make([]CompareArtifactDiff, len(diffs))
		copy(out, diffs)
		return out, 0
	}
	kept = make([]CompareArtifactDiff, 0, len(diffs))
	for _, d := range diffs {
		if artifactPathDeniedByPatterns(patterns, d.Path) {
			omitted++
			continue
		}
		kept = append(kept, d)
	}
	return kept, omitted
}

// normalizeMaxArtifacts applies ListArtifacts defaults and the live process
// hard cap (default 200 user default; user max ≤ ArtifactsHardCap(), Wave 42).
// Never exceeds AbsoluteMax (ArtifactsHardCap is already ≤ AbsoluteMax).
func normalizeMaxArtifacts(maxArtifacts int) int {
	if maxArtifacts <= 0 {
		return jenkins.DefaultMaxArtifacts
	}
	capN := ArtifactsHardCap()
	if capN <= 0 {
		capN = jenkins.DefaultArtifactsHardCap
	}
	if maxArtifacts > capN {
		return capN
	}
	return maxArtifacts
}

// listArtifactsWithPolicyFilter fetches artifact metadata and applies live
// deny_artifact_paths (Wave 37/40/42).
//
// When deny patterns are empty: single ListArtifacts with the caller's
// max_artifacts (default/cap via jenkins client AbsoluteMax clamp).
//
// When deny patterns are live: fetch up to ArtifactsHardCap() (live process
// hard cap; default DefaultArtifactsHardCap, operator-raisable ≤ AbsoluteMax)
// so denied paths do not consume the user max_artifacts page slots, filter,
// recompute Count / policy flags, then re-slice to the normalized user max.
// Truncated is forced true when the hard-cap raw list was full or already
// truncated (honesty: more artifacts may exist beyond the hard cap), or when
// kept after filter exceeds user max.
//
// Deny-only: never invents artifacts. No Message field on ArtifactList.
func listArtifactsWithPolicyFilter(ctx context.Context, client *jenkins.Client, st regState, job string, build, maxArtifacts int) (*jenkins.ArtifactList, error) {
	subj := effectiveSubject(st, ctx)
	patterns := policy.DenyArtifactPathsForSubject(st.policy, subj)
	userMax := normalizeMaxArtifacts(maxArtifacts)
	if len(patterns) == 0 {
		// Pass normalized user max so client AbsoluteMax clamp still applies
		// if live cap were ever mis-set; empty-policy path uses caller intent.
		return client.ListArtifacts(ctx, job, build, userMax)
	}

	hardCap := ArtifactsHardCap()
	if hardCap <= 0 {
		hardCap = jenkins.DefaultArtifactsHardCap
	}
	list, err := client.ListArtifacts(ctx, job, build, hardCap)
	if err != nil {
		return nil, err
	}
	// Hard-cap honesty: Truncated from client, or raw length hit the live cap
	// (Jenkins returned exactly hardCap — unknown if more exist).
	hardCapHit := list.Truncated || len(list.Artifacts) >= hardCap

	applyArtifactListPolicyFilterForSubject(st, subj, list)

	if len(list.Artifacts) > userMax {
		list.Artifacts = list.Artifacts[:userMax]
		list.Count = len(list.Artifacts)
		list.Truncated = true
	}
	if hardCapHit {
		list.Truncated = true
	}
	return list, nil
}

// applyArtifactListPolicyFilter mutates list in place when live
// deny_artifact_paths is non-empty: drops matching rows, recomputes Count,
// and sets policy_filtered / policy_omitted_count when omitted > 0.
// Truncated is left unchanged here; listArtifactsWithPolicyFilter re-slices
// and sets Truncated honesty after filter (Wave 40).
// Empty evaluator / empty patterns → no change.
func applyArtifactListPolicyFilter(st regState, list *jenkins.ArtifactList) {
	// Process-bound subject (unit tests / no request ctx).
	applyArtifactListPolicyFilterForSubject(st, st.subject, list)
}

func applyArtifactListPolicyFilterForSubject(st regState, subj policy.Subject, list *jenkins.ArtifactList) {
	if list == nil {
		return
	}
	patterns := policy.DenyArtifactPathsForSubject(st.policy, subj)
	if len(patterns) == 0 {
		return
	}
	kept, omitted := FilterDeniedArtifacts(patterns, list.Artifacts)
	list.Artifacts = kept
	list.Count = len(kept)
	if omitted > 0 {
		list.PolicyFiltered = true
		list.PolicyOmittedCount = omitted
	}
}

// ArtifactPolicyFingerprintMaterial returns stable non-secret strings for
// FetchCache keys when deny_artifact_paths is live (Wave 41). Sorted so Document
// order does not change the key. Namespace-labeled so job/branch material cannot
// collide if ever composed. Empty when no artifact deny patterns are live.
//
// Never includes credentials or raw secrets — only operator-configured deny
// pattern strings (already non-secret policy material).
// Uses process-bound subject; prefer ArtifactPolicyFingerprintMaterialForSubject
// when a request subject is available (POL-006).
func ArtifactPolicyFingerprintMaterial(st regState) []string {
	return ArtifactPolicyFingerprintMaterialForSubject(st, st.subject)
}

// ArtifactPolicyFingerprintMaterialForSubject is ArtifactPolicyFingerprintMaterial
// for a concrete subject (POL-006 effective patterns).
func ArtifactPolicyFingerprintMaterialForSubject(st regState, subj policy.Subject) []string {
	pats := policy.DenyArtifactPathsForSubject(st.policy, subj)
	if len(pats) == 0 {
		return nil
	}
	sorted := append([]string(nil), pats...)
	sort.Strings(sorted)
	out := make([]string, 0, 1+len(sorted))
	out = append(out, "deny_artifact_paths")
	out = append(out, sorted...)
	return out
}

// artifactListCacheExtra builds FetchCache extras for artifact lists (Wave 41):
// normalized max_artifacts plus sorted deny_artifact_paths fingerprint so
// entries are not reused across different deny policies (or page sizes).
func artifactListCacheExtra(st regState, maxArts int) []string {
	extra := []string{fmt.Sprintf("max=%d", normalizeMaxArtifacts(maxArts))}
	if fp := ArtifactPolicyFingerprintMaterial(st); len(fp) > 0 {
		extra = append(extra, fp...)
	}
	return extra
}

// cloneArtifactList returns a shallow copy of list and its Artifacts slice so
// callers / post-filters cannot mutate shared FetchCache entries.
func cloneArtifactList(list *jenkins.ArtifactList) *jenkins.ArtifactList {
	if list == nil {
		return nil
	}
	out := *list
	if list.Artifacts != nil {
		out.Artifacts = make([]jenkins.ArtifactMeta, len(list.Artifacts))
		copy(out.Artifacts, list.Artifacts)
	} else {
		out.Artifacts = nil
	}
	return &out
}

// filterCachedArtifactListLive clones list and applies live deny_artifact_paths
// (Wave 41 dual approach). Ensures process-cache hits never return denied paths
// after policy tighten even when a stale/wider entry is present under the key.
// Empty patterns → clone only (deny-only; no invented rows).
func filterCachedArtifactListLive(st regState, list *jenkins.ArtifactList) *jenkins.ArtifactList {
	out := cloneArtifactList(list)
	if out == nil {
		return nil
	}
	applyArtifactListPolicyFilter(st, out)
	return out
}
