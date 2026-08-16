package policy_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// Regression: allow_mutation_job_prefixes must match on segment boundaries,
// like the deny-side pattern language ("secret-folder" must not match
// "secret-folder-other"). A bare prefix "team-a" previously also allowed
// "team-audit/job" and "team-a-other/...".
func TestCheckMutationJobAllowed_SegmentBoundary(t *testing.T) {
	t.Parallel()
	p := &policy.MutationPolicy{AllowJobPrefixes: []string{"team-a"}}

	allowed := []string{"team-a", "team-a/job", "team-a/sub/job"}
	for _, job := range allowed {
		if err := policy.CheckMutationJobAllowed(p, job); err != nil {
			t.Errorf("job %q must be allowed by prefix team-a: %v", job, err)
		}
	}
	denied := []string{"team-audit/job", "team-a-other/x", "team-b/job", "team-aX"}
	for _, job := range denied {
		if err := policy.CheckMutationJobAllowed(p, job); err == nil {
			t.Errorf("job %q must NOT be allowed by bare prefix team-a", job)
		}
	}
}

// Regression: an operator-written trailing-slash prefix keeps working and
// still matches only that folder subtree.
func TestCheckMutationJobAllowed_TrailingSlashPrefix(t *testing.T) {
	t.Parallel()
	p := &policy.MutationPolicy{AllowJobPrefixes: []string{"team/"}}
	if err := policy.CheckMutationJobAllowed(p, "team/job"); err != nil {
		t.Fatalf("team/ prefix must allow team/job: %v", err)
	}
	if err := policy.CheckMutationJobAllowed(p, "team"); err != nil {
		t.Fatalf("team/ prefix must allow the folder itself: %v", err)
	}
	if err := policy.CheckMutationJobAllowed(p, "teamwork/job"); err == nil {
		t.Fatal("team/ prefix must not allow teamwork/job")
	}
}
