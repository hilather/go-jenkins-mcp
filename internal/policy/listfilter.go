package policy

import "strings"

// documentProvider is implemented by DenyOnlyEvaluator and ReloadableDenyOnly
// so list tools can read live deny patterns without elevating access.
type documentProvider interface {
	Document() Document
}

// effectiveDocumentProvider is implemented by evaluators that merge POL-006
// per-user/group bindings for a subject (DenyOnlyEvaluator, ReloadableDenyOnly).
type effectiveDocumentProvider interface {
	EffectiveDocument(subject Subject) Document
}

// documentForList returns the most-restrictive document for list-row privacy.
// When the evaluator supports EffectiveDocument, subject bindings (POL-006) are
// merged. Otherwise falls back to Document() (global only).
func documentForList(ev PolicyEvaluator, subject Subject) Document {
	if ev == nil {
		return Document{Mode: ModePilot}
	}
	if edp, ok := ev.(effectiveDocumentProvider); ok {
		return edp.EffectiveDocument(subject)
	}
	if dp, ok := ev.(documentProvider); ok {
		return dp.Document()
	}
	return Document{Mode: ModePilot}
}

// copyDenyList returns a defensive copy of patterns (nil when empty).
func copyDenyList(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, len(names))
	copy(out, names)
	return out
}

// DenyNodeNamesFromEvaluator returns a copy of live deny_node_names when the
// evaluator exposes Document() (DenyOnlyEvaluator, ReloadableDenyOnly).
// Nil evaluator, unknown implementation, or empty list → nil (no filter).
// Global overlay only — prefer DenyNodeNamesForSubject for list privacy (POL-006).
func DenyNodeNamesFromEvaluator(ev PolicyEvaluator) []string {
	if ev == nil {
		return nil
	}
	dp, ok := ev.(documentProvider)
	if !ok {
		return nil
	}
	return copyDenyList(dp.Document().DenyNodeNames)
}

// DenyNodeNamesForSubject returns effective deny_node_names for subject (POL-006).
func DenyNodeNamesForSubject(ev PolicyEvaluator, subject Subject) []string {
	return copyDenyList(documentForList(ev, subject).DenyNodeNames)
}

// DenyViewNamesFromEvaluator returns a copy of live deny_view_names when the
// evaluator exposes Document() (DenyOnlyEvaluator, ReloadableDenyOnly).
// Nil evaluator, unknown implementation, or empty list → nil (no filter).
// Used by jenkins_list_views list-row privacy (Wave 38).
// Global overlay only — prefer DenyViewNamesForSubject for list privacy (POL-006).
func DenyViewNamesFromEvaluator(ev PolicyEvaluator) []string {
	if ev == nil {
		return nil
	}
	dp, ok := ev.(documentProvider)
	if !ok {
		return nil
	}
	return copyDenyList(dp.Document().DenyViewNames)
}

// DenyViewNamesForSubject returns effective deny_view_names for subject (POL-006).
func DenyViewNamesForSubject(ev PolicyEvaluator, subject Subject) []string {
	return copyDenyList(documentForList(ev, subject).DenyViewNames)
}

// DenyJobPrefixesFromEvaluator returns a copy of live deny_job_prefixes when the
// evaluator exposes Document() (DenyOnlyEvaluator, ReloadableDenyOnly).
// Nil evaluator, unknown implementation, or empty list → nil (no filter).
// Used by jenkins_list_jobs list-row privacy (Wave 37).
// Global overlay only — prefer DenyJobPrefixesForSubject for list privacy (POL-006).
func DenyJobPrefixesFromEvaluator(ev PolicyEvaluator) []string {
	if ev == nil {
		return nil
	}
	dp, ok := ev.(documentProvider)
	if !ok {
		return nil
	}
	return copyDenyList(dp.Document().DenyJobPrefixes)
}

// DenyJobPrefixesForSubject returns effective deny_job_prefixes for subject (POL-006).
func DenyJobPrefixesForSubject(ev PolicyEvaluator, subject Subject) []string {
	return copyDenyList(documentForList(ev, subject).DenyJobPrefixes)
}

// DenyArtifactPathsFromEvaluator returns a copy of live deny_artifact_paths when
// the evaluator exposes Document() (DenyOnlyEvaluator, ReloadableDenyOnly).
// Nil evaluator, unknown implementation, or empty list → nil (no filter).
// Wave 37: used by jenkins_list_artifacts list-row privacy.
// Global overlay only — prefer DenyArtifactPathsForSubject for list privacy (POL-006).
func DenyArtifactPathsFromEvaluator(ev PolicyEvaluator) []string {
	if ev == nil {
		return nil
	}
	dp, ok := ev.(documentProvider)
	if !ok {
		return nil
	}
	return copyDenyList(dp.Document().DenyArtifactPaths)
}

// DenyArtifactPathsForSubject returns effective deny_artifact_paths for subject (POL-006).
func DenyArtifactPathsForSubject(ev PolicyEvaluator, subject Subject) []string {
	return copyDenyList(documentForList(ev, subject).DenyArtifactPaths)
}

// DenyBranchNamesFromEvaluator returns a copy of live deny_branch_names when the
// evaluator exposes Document() (DenyOnlyEvaluator, ReloadableDenyOnly).
// Nil evaluator, unknown implementation, or empty list → nil (no filter).
// Global overlay only — prefer DenyBranchNamesForSubject for list privacy (POL-006).
func DenyBranchNamesFromEvaluator(ev PolicyEvaluator) []string {
	if ev == nil {
		return nil
	}
	dp, ok := ev.(documentProvider)
	if !ok {
		return nil
	}
	return copyDenyList(dp.Document().DenyBranchNames)
}

// DenyBranchNamesForSubject returns effective deny_branch_names for subject (POL-006).
func DenyBranchNamesForSubject(ev PolicyEvaluator, subject Subject) []string {
	return copyDenyList(documentForList(ev, subject).DenyBranchNames)
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
