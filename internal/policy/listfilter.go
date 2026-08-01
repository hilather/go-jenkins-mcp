package policy

import "strings"

// documentProvider is implemented by DenyOnlyEvaluator and ReloadableDenyOnly
// so list tools can read live deny patterns without elevating access.
type documentProvider interface {
	Document() Document
}

// DenyNodeNamesFromEvaluator returns a copy of live deny_node_names when the
// evaluator exposes Document() (DenyOnlyEvaluator, ReloadableDenyOnly).
// Nil evaluator, unknown implementation, or empty list → nil (no filter).
func DenyNodeNamesFromEvaluator(ev PolicyEvaluator) []string {
	if ev == nil {
		return nil
	}
	dp, ok := ev.(documentProvider)
	if !ok {
		return nil
	}
	names := dp.Document().DenyNodeNames
	if len(names) == 0 {
		return nil
	}
	out := make([]string, len(names))
	copy(out, names)
	return out
}

// DenyViewNamesFromEvaluator returns a copy of live deny_view_names when the
// evaluator exposes Document() (DenyOnlyEvaluator, ReloadableDenyOnly).
// Nil evaluator, unknown implementation, or empty list → nil (no filter).
// Used by jenkins_list_views list-row privacy (Wave 38).
func DenyViewNamesFromEvaluator(ev PolicyEvaluator) []string {
	if ev == nil {
		return nil
	}
	dp, ok := ev.(documentProvider)
	if !ok {
		return nil
	}
	names := dp.Document().DenyViewNames
	if len(names) == 0 {
		return nil
	}
	out := make([]string, len(names))
	copy(out, names)
	return out
}

// DenyJobPrefixesFromEvaluator returns a copy of live deny_job_prefixes when the
// evaluator exposes Document() (DenyOnlyEvaluator, ReloadableDenyOnly).
// Nil evaluator, unknown implementation, or empty list → nil (no filter).
// Used by jenkins_list_jobs list-row privacy (Wave 37).
func DenyJobPrefixesFromEvaluator(ev PolicyEvaluator) []string {
	if ev == nil {
		return nil
	}
	dp, ok := ev.(documentProvider)
	if !ok {
		return nil
	}
	prefs := dp.Document().DenyJobPrefixes
	if len(prefs) == 0 {
		return nil
	}
	out := make([]string, len(prefs))
	copy(out, prefs)
	return out
}

// DenyArtifactPathsFromEvaluator returns a copy of live deny_artifact_paths when
// the evaluator exposes Document() (DenyOnlyEvaluator, ReloadableDenyOnly).
// Nil evaluator, unknown implementation, or empty list → nil (no filter).
// Wave 37: used by jenkins_list_artifacts list-row privacy.
func DenyArtifactPathsFromEvaluator(ev PolicyEvaluator) []string {
	if ev == nil {
		return nil
	}
	dp, ok := ev.(documentProvider)
	if !ok {
		return nil
	}
	paths := dp.Document().DenyArtifactPaths
	if len(paths) == 0 {
		return nil
	}
	out := make([]string, len(paths))
	copy(out, paths)
	return out
}

// DenyBranchNamesFromEvaluator returns a copy of live deny_branch_names when the
// evaluator exposes Document() (DenyOnlyEvaluator, ReloadableDenyOnly).
// Nil evaluator, unknown implementation, or empty list → nil (no filter).
func DenyBranchNamesFromEvaluator(ev PolicyEvaluator) []string {
	if ev == nil {
		return nil
	}
	dp, ok := ev.(documentProvider)
	if !ok {
		return nil
	}
	names := dp.Document().DenyBranchNames
	if len(names) == 0 {
		return nil
	}
	out := make([]string, len(names))
	copy(out, names)
	return out
}

// NameDeniedByPatterns reports whether name matches any deny pattern using
// MatchDenyJobPattern (same language as deny_job_prefixes / deny_node_names /
// deny_branch_names / deny_artifact_paths). Empty patterns or empty name → false
// (deny-only; never invent matches).
func NameDeniedByPatterns(patterns []string, name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(patterns) == 0 {
		return false
	}
	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if MatchDenyJobPattern(pat, name) {
			return true
		}
	}
	return false
}
