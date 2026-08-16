package tools

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// artifactSubjectSlot is an internal-package subject injector for multi-user
// cache tests (the external test package has its own subjectSlot).
type artifactSubjectSlot struct {
	v atomic.Value // policy.Subject
}

func (s *artifactSubjectSlot) set(subj policy.Subject) { s.v.Store(subj) }

func (s *artifactSubjectSlot) fromContext(ctx context.Context) (policy.Subject, bool) {
	_ = ctx
	v := s.v.Load()
	if v == nil {
		return policy.Subject{}, false
	}
	subj, ok := v.(policy.Subject)
	return subj, ok
}

// Regression (POL-006): the artifact-list FetchCache key fingerprint and the
// clone-and-post-filter on the return path both used the process-bound
// subject, so per-user/group deny_artifact_paths were bypassed on cache hits
// in multi-user serve. A user whose group binding denies secrets/** must not
// receive those rows even when another subject's unfiltered list is cached.
func TestGetCachedArtifactList_PerSubjectDenyOnCacheHit(t *testing.T) {
	body := `{"timestamp":1700000000000,"artifacts":[
		{"fileName":"creds.txt","relativePath":"secrets/creds.txt"},
		{"fileName":"out.txt","relativePath":"reports/out.txt"}
	]}`
	client, closeFn := artifactListClient(t, body)
	defer closeFn()

	cache := NewFetchCache(FetchCacheConfig{TTL: time.Minute, MaxEntries: 16})
	// No global artifact denies; the contractors group binding adds one.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		GroupBindings: []policy.GroupBinding{
			{GroupID: "contractors", DenyArtifactPaths: []string{"secrets/**"}},
		},
	})
	processSubject := policy.NewSubject("corp", "process-user", true)
	bob := policy.NewSubject("corp", "bob", true).WithExternal("bob-sub")
	bob.Groups = []string{"contractors"}

	// Multi-user wiring: per-request subject comes from context.
	slot := &artifactSubjectSlot{}
	st := regState{
		fetchCache:         cache,
		policy:             ev,
		subject:            processSubject,
		subjectFromContext: slot.fromContext,
	}

	// 1) Process subject (no binding) fills the cache unfiltered.
	ctx := withDiagSession(context.Background(), newDiagSession(st, compareBudgetDefault()))
	list, err := getCachedArtifactList(ctx, st, client, "demo", 7, 50)
	if err != nil {
		t.Fatal(err)
	}
	if list.Count != 2 {
		t.Fatalf("process subject must see both rows, got %d (%v)", list.Count, artifactPaths(list))
	}

	// 2) Bob (contractors binding) requests the same build's artifacts.
	//    Before the fix the cache key and the hit-path filter both used the
	//    process subject, so Bob received the denied secrets/** row.
	slot.set(bob)
	listB, err := getCachedArtifactList(ctx, st, client, "demo", 7, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range listB.Artifacts {
		if strings.Contains(a.Path, "secrets/") {
			t.Fatalf("denied artifact path leaked to bound subject on cache path: %q", a.Path)
		}
	}
	if listB.Count != 1 || listB.Artifacts[0].Path != "reports/out.txt" {
		t.Fatalf("bob must see only reports/out.txt, got %d (%v)", listB.Count, artifactPaths(listB))
	}
	if !listB.PolicyFiltered || listB.PolicyOmittedCount != 1 {
		t.Fatalf("bob list must report policy omission: %+v", listB)
	}

	// 3) A second Bob request is served from his own policy-scoped cache entry
	//    and stays filtered.
	listB2, err := getCachedArtifactList(ctx, st, client, "demo", 7, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range listB2.Artifacts {
		if strings.Contains(a.Path, "secrets/") {
			t.Fatalf("denied artifact path leaked on repeat hit: %q", a.Path)
		}
	}
	if cache.Stats().Hits < 1 {
		t.Fatalf("expected at least one cache hit across the three calls: %+v", cache.Stats())
	}
}
