package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wave 41: ArtifactPolicyFingerprintMaterial is sorted, namespaced, empty when no denies.
func TestArtifactPolicyFingerprintMaterial(t *testing.T) {
	if got := ArtifactPolicyFingerprintMaterial(regState{}); got != nil {
		t.Fatalf("empty policy: got %v", got)
	}
	st := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"z/**", "a/*.pem", "secrets/**"},
	})}
	got := ArtifactPolicyFingerprintMaterial(st)
	want := []string{"deny_artifact_paths", "a/*.pem", "secrets/**", "z/**"}
	if len(got) != len(want) {
		t.Fatalf("len=%d got=%v want=%v", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("part[%d]=%q want %q full=%v", i, got[i], want[i], got)
		}
	}
	// Document order change must not change material.
	st2 := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**", "z/**", "a/*.pem"},
	})}
	got2 := ArtifactPolicyFingerprintMaterial(st2)
	for i := range want {
		if got2[i] != want[i] {
			t.Fatalf("order-insensitive fail: got2=%v", got2)
		}
	}
	// Job/branch denials alone do not contribute artifact fingerprint.
	stJobs := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret-job"},
	})}
	if got := ArtifactPolicyFingerprintMaterial(stJobs); got != nil {
		t.Fatalf("job-only denials must not fingerprint artifacts: %v", got)
	}
}

// Regression: getCachedArtifactList omits deny_artifact_paths (fetch path + cache).
func TestGetCachedArtifactList_DenyPatternsOmit(t *testing.T) {
	body := `{"timestamp":1700000000000,"artifacts":[
		{"fileName":"creds.txt","relativePath":"secrets/creds.txt"},
		{"fileName":"out.txt","relativePath":"reports/out.txt"},
		{"fileName":"key.pem","relativePath":"key.pem"}
	]}`
	client, closeFn := artifactListClient(t, body)
	defer closeFn()

	cache := NewFetchCache(FetchCacheConfig{TTL: time.Minute, MaxEntries: 16})
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**", "*.pem"},
	})
	st := regState{fetchCache: cache, policy: ev}

	ctx := withDiagSession(context.Background(), newDiagSession(st, compareBudgetDefault()))
	list, err := getCachedArtifactList(ctx, st, client, "demo", 7, 50)
	if err != nil {
		t.Fatal(err)
	}
	if list == nil {
		t.Fatal("nil list")
	}
	if !list.PolicyFiltered {
		t.Fatalf("policy_filtered want true: %+v", list)
	}
	if list.PolicyOmittedCount != 2 {
		t.Fatalf("policy_omitted_count=%d want 2", list.PolicyOmittedCount)
	}
	if list.Count != 1 || len(list.Artifacts) != 1 {
		t.Fatalf("want 1 allowed artifact, got count=%d paths=%v", list.Count, artifactPaths(list))
	}
	if list.Artifacts[0].Path != "reports/out.txt" {
		t.Fatalf("path=%q want reports/out.txt", list.Artifacts[0].Path)
	}
	// Canary: denied path strings never appear in returned paths.
	for _, a := range list.Artifacts {
		if strings.Contains(a.Path, "secrets/") || strings.HasSuffix(a.Path, ".pem") {
			t.Fatalf("denied path leaked: %q", a.Path)
		}
	}

	// Second call hits cache; still omit denied.
	list2, err := getCachedArtifactList(ctx, st, client, "demo", 7, 50)
	if err != nil {
		t.Fatal(err)
	}
	if list2.Count != 1 || list2.Artifacts[0].Path != "reports/out.txt" {
		t.Fatalf("cache hit: want 1 allowed, got %+v", list2)
	}
	if cache.Stats().Hits < 1 {
		t.Fatalf("expected cache hit, stats=%+v", cache.Stats())
	}
	// Mutating returned list must not corrupt cache (clone on return).
	list2.Artifacts[0].Path = "mutated"
	list3, err := getCachedArtifactList(ctx, st, client, "demo", 7, 50)
	if err != nil {
		t.Fatal(err)
	}
	if list3.Artifacts[0].Path != "reports/out.txt" {
		t.Fatalf("cache entry mutated via return value: %q", list3.Artifacts[0].Path)
	}
}

// Wave 41: empty deny_artifact_paths → full list, no policy flags (unchanged).
func TestGetCachedArtifactList_EmptyPatternsUnchanged(t *testing.T) {
	body := `{"timestamp":1700000000000,"artifacts":[
		{"fileName":"creds.txt","relativePath":"secrets/creds.txt"},
		{"fileName":"out.txt","relativePath":"reports/out.txt"}
	]}`
	client, closeFn := artifactListClient(t, body)
	defer closeFn()

	cache := NewFetchCache(FetchCacheConfig{TTL: time.Minute, MaxEntries: 16})
	st := regState{
		fetchCache: cache,
		policy:     policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot}),
	}
	ctx := withDiagSession(context.Background(), newDiagSession(st, compareBudgetDefault()))
	list, err := getCachedArtifactList(ctx, st, client, "demo", 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if list.PolicyFiltered || list.PolicyOmittedCount != 0 {
		t.Fatalf("empty patterns: filtered=%v omitted=%d", list.PolicyFiltered, list.PolicyOmittedCount)
	}
	if list.Count != 2 || len(list.Artifacts) != 2 {
		t.Fatalf("want full list of 2, got count=%d paths=%v", list.Count, artifactPaths(list))
	}
}

// Regression: after policy tighten, previously cached full list does not return
// denied paths (post-filter + policy fingerprint key).
func TestGetCachedArtifactList_PolicyTightenPostFilter(t *testing.T) {
	body := `{"timestamp":1700000000000,"artifacts":[
		{"fileName":"creds.txt","relativePath":"secrets/creds.txt"},
		{"fileName":"out.txt","relativePath":"reports/out.txt"},
		{"fileName":"key.pem","relativePath":"key.pem"}
	]}`
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/json") {
			hits++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	client := &jenkins.Client{
		URL: srv.URL, User: "u", Token: "t",
		Client: srv.Client(), LogsClient: srv.Client(),
	}

	cache := NewFetchCache(FetchCacheConfig{TTL: time.Minute, MaxEntries: 16})
	// 1) Empty deny patterns — cache full list under no-policy key.
	st := regState{
		fetchCache: cache,
		policy:     policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot}),
	}
	ctx := withDiagSession(context.Background(), newDiagSession(st, compareBudgetDefault()))
	full, err := getCachedArtifactList(ctx, st, client, "demo", 3, 50)
	if err != nil {
		t.Fatal(err)
	}
	if full.Count != 3 {
		t.Fatalf("pre-tighten want 3 paths, got %d", full.Count)
	}
	if hits != 1 {
		t.Fatalf("hits=%d want 1 after first fetch", hits)
	}

	// 2) Policy tighten: new fingerprint key → miss + filtered fetch.
	// Also cover post-filter: seed a full list under the *new* policy key
	// (simulates stale wider payload under the tightened key).
	st.policy = policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**", "*.pem"},
	})
	extra := artifactListCacheExtra(st, 50)
	// Poison cache under tightened key with unfiltered full list.
	cache.PutAny("demo", 3, FetchKindArtifacts, &jenkins.ArtifactList{
		JobName: "demo", BuildNumber: 3,
		Artifacts: []jenkins.ArtifactMeta{
			{Path: "secrets/creds.txt", FileName: "creds.txt"},
			{Path: "reports/out.txt", FileName: "out.txt"},
			{Path: "key.pem", FileName: "key.pem"},
		},
		Count: 3,
	}, 512, extra...)

	list, err := getCachedArtifactList(ctx, st, client, "demo", 3, 50)
	if err != nil {
		t.Fatal(err)
	}
	// Post-filter must drop denied paths even from poisoned cache hit (no extra HTTP required).
	if list.Count != 1 || len(list.Artifacts) != 1 || list.Artifacts[0].Path != "reports/out.txt" {
		t.Fatalf("after tighten want only reports/out.txt, got paths=%v filtered=%v omitted=%d",
			artifactPaths(list), list.PolicyFiltered, list.PolicyOmittedCount)
	}
	if !list.PolicyFiltered || list.PolicyOmittedCount != 2 {
		t.Fatalf("want policy_filtered + omitted=2, got filtered=%v omitted=%d",
			list.PolicyFiltered, list.PolicyOmittedCount)
	}
	for _, a := range list.Artifacts {
		if strings.Contains(a.Path, "secrets/") || strings.HasSuffix(a.Path, ".pem") {
			t.Fatalf("Regression: denied path after policy tighten: %q", a.Path)
		}
	}
	// Poisoned hit should not re-fetch; hits still 1.
	if hits != 1 {
		t.Fatalf("post-filter hit should not re-fetch: hits=%d", hits)
	}

	// 3) Different policy fingerprint → separate cache slot; empty patterns still full.
	stLoose := regState{
		fetchCache: cache,
		policy:     policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot}),
	}
	loose, err := getCachedArtifactList(ctx, stLoose, client, "demo", 3, 50)
	if err != nil {
		t.Fatal(err)
	}
	if loose.Count != 3 {
		t.Fatalf("empty patterns cache key should still return full list, got %d paths=%v",
			loose.Count, artifactPaths(loose))
	}
}
