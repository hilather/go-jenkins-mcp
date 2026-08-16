package policy_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// Regression: a legal Jenkins job name containing the substring ".." (but no
// exact "." / ".." path segment) must still be deniable. Previously
// NormalizeJobFullName rejected any name containing ".." and every deny
// matcher treated that as "no match" — so "secret..x" could never be denied
// by any deny_job_prefixes pattern (fail-open on a deny-only boundary).
func TestMatchDenyJobPattern_DotDotSubstringJobStillDeniable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pattern string
		job     string
		want    bool
	}{
		{"secret*", "secret..x", true},
		{"prod/**", "prod/a..b/job", true},
		{"release..2024", "release..2024", true},
		{"release..2024", "release..2025", false},
		{"team/*", "team/a..b", true},
		{"team/*", "other/a..b", false},
	}
	for _, tc := range cases {
		if got := policy.MatchDenyJobPattern(tc.pattern, tc.job); got != tc.want {
			t.Errorf("MatchDenyJobPattern(%q, %q) = %v, want %v", tc.pattern, tc.job, got, tc.want)
		}
	}
}

// Regression: NormalizeJobFullName accepts ".." substrings inside legal
// segment names while still rejecting genuine traversal segments (exact ".."
// or "." segments), aligning with contracts.ParseJobFullName.
func TestNormalizeJobFullName_DotDotSubstringVsTraversalSegment(t *testing.T) {
	t.Parallel()
	okCases := []struct{ in, want string }{
		{"release..2024", "release..2024"},
		{"prod/a..b/job", "prod/a..b/job"},
		{"a/b", "a/b"},
		{"prod//secret", "prod/secret"}, // empty-segment collapse preserved
	}
	for _, tc := range okCases {
		got, ok := policy.NormalizeJobFullName(tc.in)
		if !ok || got != tc.want {
			t.Errorf("NormalizeJobFullName(%q) = %q,%v; want %q,true", tc.in, got, ok, tc.want)
		}
	}
	badCases := []string{"a/../b", "../x", "a/./b", "./a", "..", "."}
	for _, in := range badCases {
		if got, ok := policy.NormalizeJobFullName(in); ok {
			t.Errorf("NormalizeJobFullName(%q) = %q,true; want _,false (traversal segment)", in, got)
		}
	}
}

// Regression: deny evaluation end-to-end — a job named with a ".." substring
// must be denied by an overlay deny_job_prefixes rule.
func TestEvaluate_DenyJobPrefix_DotDotSubstringJob(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret*"},
	})
	subj := policy.NewSubject("corp", "alice", true)
	d := ev.Evaluate(subj,
		policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead},
		policy.Target{JobName: "secret..x"})
	if !d.Denied() {
		t.Fatalf("job with .. substring must still be denied by secret*: %+v", d)
	}
}
