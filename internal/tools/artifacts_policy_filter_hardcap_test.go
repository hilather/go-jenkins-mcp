package tools

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// buildArtifactsListJSON returns Jenkins list JSON: first nDenied under secrets/,
// then nAllowed under reports/. Order matters: denied first would steal slots
// under pre-Wave-40 page-level filter.
func buildArtifactsListJSON(nDenied, nAllowed int) string {
	var b strings.Builder
	b.WriteString(`{"timestamp":1700000000000,"artifacts":[`)
	first := true
	for i := 0; i < nDenied; i++ {
		if !first {
			b.WriteByte(',')
		}
		first = false
		name := fmt.Sprintf("secret-%04d.txt", i)
		fmt.Fprintf(&b, `{"fileName":%q,"relativePath":"secrets/%s"}`, name, name)
	}
	for i := 0; i < nAllowed; i++ {
		if !first {
			b.WriteByte(',')
		}
		first = false
		name := fmt.Sprintf("out-%04d.txt", i)
		fmt.Fprintf(&b, `{"fileName":%q,"relativePath":"reports/%s"}`, name, name)
	}
	b.WriteString(`]}`)
	return b.String()
}

func artifactListClient(t *testing.T, listBody string) (*jenkins.Client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/json") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(listBody))
			return
		}
		http.NotFound(w, r)
	}))
	c := &jenkins.Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	return c, srv.Close
}

// Regression: denied paths must not consume max_artifacts slots before filter
// (Wave 40 hard-cap fetch when deny_artifact_paths live).
func TestListArtifactsWithPolicyFilter_DeniedDoNotStealUserMaxSlots(t *testing.T) {
	// 8 denied first + 6 allowed; user max 5.
	// Pre-Wave-40: ListArtifacts(max=5) would return only secrets/* → after filter empty.
	// Wave 40: fetch hard cap, filter, slice → 5 allowed reports/*.
	const nDenied, nAllowed, userMax = 8, 6, 5
	body := buildArtifactsListJSON(nDenied, nAllowed)
	client, closeFn := artifactListClient(t, body)
	defer closeFn()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**"},
	})
	st := regState{policy: ev}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	list, err := listArtifactsWithPolicyFilter(ctx, client, st, "demo", 7, userMax)
	if err != nil {
		t.Fatal(err)
	}
	if list == nil {
		t.Fatal("nil list")
	}
	if !list.PolicyFiltered {
		t.Fatalf("policy_filtered want true: %+v", list)
	}
	if list.PolicyOmittedCount != nDenied {
		t.Fatalf("policy_omitted_count=%d want %d", list.PolicyOmittedCount, nDenied)
	}
	if list.Count != userMax || len(list.Artifacts) != userMax {
		t.Fatalf("want user page of %d allowed, got count=%d arts=%d paths=%v",
			userMax, list.Count, len(list.Artifacts), artifactPaths(list))
	}
	for _, a := range list.Artifacts {
		if strings.HasPrefix(a.Path, "secrets/") {
			t.Fatalf("denied path leaked: %q", a.Path)
		}
		if !strings.HasPrefix(a.Path, "reports/") {
			t.Fatalf("unexpected path: %q", a.Path)
		}
	}
	// 6 allowed > userMax 5 → Truncated after re-slice.
	if !list.Truncated {
		t.Fatal("truncated want true (more allowed than user max after filter)")
	}
}

// Empty deny patterns: single fetch at user max (no hard-cap expansion).
func TestListArtifactsWithPolicyFilter_EmptyPatternsUsesUserMax(t *testing.T) {
	// 10 artifacts, no denies, max=3 → 3 returned, truncated.
	body := buildArtifactsListJSON(0, 10)
	client, closeFn := artifactListClient(t, body)
	defer closeFn()

	st := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	list, err := listArtifactsWithPolicyFilter(ctx, client, st, "demo", 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if list.Count != 3 || len(list.Artifacts) != 3 {
		t.Fatalf("empty policy user max: count=%d arts=%d", list.Count, len(list.Artifacts))
	}
	if list.PolicyFiltered || list.PolicyOmittedCount != 0 {
		t.Fatalf("no filter flags: filtered=%v omitted=%d", list.PolicyFiltered, list.PolicyOmittedCount)
	}
	if !list.Truncated {
		t.Fatal("truncated want true when more than user max without filter")
	}
}

// Nil evaluator same as empty patterns.
func TestListArtifactsWithPolicyFilter_NilPolicyUsesUserMax(t *testing.T) {
	body := buildArtifactsListJSON(2, 2)
	client, closeFn := artifactListClient(t, body)
	defer closeFn()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	list, err := listArtifactsWithPolicyFilter(ctx, client, regState{}, "demo", 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	// Secrets still visible without policy patterns.
	if list.Count != 4 {
		t.Fatalf("want all 4, got %d", list.Count)
	}
	if list.PolicyFiltered {
		t.Fatal("nil policy must not set policy_filtered")
	}
}

// PolicyFiltered counts from hard-cap raw set (not only user page).
func TestListArtifactsWithPolicyFilter_PolicyOmittedCountFromHardCapSet(t *testing.T) {
	// 4 denied + 2 allowed; user max 1 → page has 1 allowed, omitted still 4.
	body := buildArtifactsListJSON(4, 2)
	client, closeFn := artifactListClient(t, body)
	defer closeFn()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**"},
	})
	st := regState{policy: ev}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	list, err := listArtifactsWithPolicyFilter(ctx, client, st, "demo", 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	if list.PolicyOmittedCount != 4 {
		t.Fatalf("omitted=%d want 4 (from full hard-cap fetch before re-slice)", list.PolicyOmittedCount)
	}
	if list.Count != 1 || !strings.HasPrefix(list.Artifacts[0].Path, "reports/") {
		t.Fatalf("page: %+v", list.Artifacts)
	}
	if !list.PolicyFiltered {
		t.Fatal("policy_filtered want true")
	}
	if !list.Truncated {
		t.Fatal("truncated want true (2 allowed > user max 1)")
	}
}

// Raw hard-cap full page forces Truncated honesty even if kept fits user max.
func TestListArtifactsWithPolicyFilter_HardCapHitForcesTruncated(t *testing.T) {
	// Exactly live hard cap denied-first + a few allowed that fit after filter.
	// userMax large enough for all kept; still Truncated because raw hit hard cap.
	// Uses ArtifactsHardCap() (default DefaultArtifactsHardCap / MaxArtifactsHardCap alias).
	hardCap := ArtifactsHardCap()
	nDenied := hardCap - 3
	nAllowed := 3
	body := buildArtifactsListJSON(nDenied, nAllowed)
	client, closeFn := artifactListClient(t, body)
	defer closeFn()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**"},
	})
	st := regState{policy: ev}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	list, err := listArtifactsWithPolicyFilter(ctx, client, st, "demo", 9, 200)
	if err != nil {
		t.Fatal(err)
	}
	if list.Count != nAllowed {
		t.Fatalf("count=%d want %d paths=%v", list.Count, nAllowed, artifactPaths(list))
	}
	if list.PolicyOmittedCount != nDenied {
		t.Fatalf("omitted=%d want %d", list.PolicyOmittedCount, nDenied)
	}
	if !list.Truncated {
		t.Fatal("truncated want true (raw list length == live ArtifactsHardCap honesty)")
	}
}

// Wave 42: listArtifactsWithPolicyFilter uses SetArtifactsHardCap live value
// (not a fixed 500) when deny patterns force hard-cap fetch.
func TestListArtifactsWithPolicyFilter_UsesSetArtifactsHardCap(t *testing.T) {
	// Not parallel: mutates package-level artifactsHardCap.
	prev := ArtifactsHardCap()
	defer SetArtifactsHardCap(prev)

	// Live hard cap 12 ≥ nDenied+nAllowed so the hard-cap fetch sees every
	// denied + allowed row (proves filter uses live cap, not a fixed 500-only
	// path). userMax 3 → page of 3 allowed after filter.
	const liveCap, nDenied, nAllowed, userMax = 12, 7, 5, 3
	SetArtifactsHardCap(liveCap)
	if ArtifactsHardCap() != liveCap {
		t.Fatalf("live cap: got %d", ArtifactsHardCap())
	}
	if nDenied+nAllowed > liveCap {
		t.Fatalf("fixture must fit under live hard cap: denied+allowed=%d cap=%d", nDenied+nAllowed, liveCap)
	}

	body := buildArtifactsListJSON(nDenied, nAllowed)
	client, closeFn := artifactListClient(t, body)
	defer closeFn()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**"},
	})
	st := regState{policy: ev}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	list, err := listArtifactsWithPolicyFilter(ctx, client, st, "demo", 1, userMax)
	if err != nil {
		t.Fatal(err)
	}
	if list.PolicyOmittedCount != nDenied {
		t.Fatalf("omitted=%d want %d (hard-cap fetch must see all denied under live cap)", list.PolicyOmittedCount, nDenied)
	}
	if list.Count != userMax {
		t.Fatalf("count=%d want userMax %d paths=%v", list.Count, userMax, artifactPaths(list))
	}
	for _, a := range list.Artifacts {
		if strings.HasPrefix(a.Path, "secrets/") {
			t.Fatalf("denied path leaked: %q", a.Path)
		}
	}
	// 5 allowed > userMax 3 → Truncated.
	if !list.Truncated {
		t.Fatal("truncated want true")
	}

	// Raised hard cap: normalizeMaxArtifacts allows user max up to live cap.
	if got := normalizeMaxArtifacts(liveCap); got != liveCap {
		t.Fatalf("normalize at live cap: got %d", got)
	}
	if got := normalizeMaxArtifacts(liveCap + 50); got != liveCap {
		t.Fatalf("normalize over live cap: got %d want %d", got, liveCap)
	}

	// Lower live hard cap so hard-cap fetch truncates before all allowed:
	// 7 denied + only first 3 of 5 allowed fit under liveCap=10 → after filter
	// omitted=7, kept=3, Truncated=true (hard-cap honesty even if kept==userMax).
	SetArtifactsHardCap(10)
	list2, err := listArtifactsWithPolicyFilter(ctx, client, st, "demo", 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if list2.PolicyOmittedCount != nDenied {
		t.Fatalf("low hard cap omitted=%d want %d", list2.PolicyOmittedCount, nDenied)
	}
	if list2.Count != 3 { // only 3 allowed fit under hard-cap window of 10
		t.Fatalf("low hard cap count=%d want 3 paths=%v", list2.Count, artifactPaths(list2))
	}
	if !list2.Truncated {
		t.Fatal("low hard cap must set truncated (raw hit live hard cap)")
	}
}

func artifactPaths(list *jenkins.ArtifactList) []string {
	if list == nil {
		return nil
	}
	out := make([]string, len(list.Artifacts))
	for i, a := range list.Artifacts {
		out[i] = a.Path
	}
	return out
}

func TestNormalizeMaxArtifacts(t *testing.T) {
	// Not parallel if we touch live cap; default path uses process default.
	if got := normalizeMaxArtifacts(0); got != jenkins.DefaultMaxArtifacts {
		t.Fatalf("0 → %d want default %d", got, jenkins.DefaultMaxArtifacts)
	}
	if got := normalizeMaxArtifacts(-1); got != jenkins.DefaultMaxArtifacts {
		t.Fatalf("-1 → %d", got)
	}
	if got := normalizeMaxArtifacts(50); got != 50 {
		t.Fatalf("50 → %d", got)
	}
	// Over live hard cap (default = DefaultArtifactsHardCap / MaxArtifactsHardCap alias).
	live := ArtifactsHardCap()
	if got := normalizeMaxArtifacts(live + 10); got != live {
		t.Fatalf("over hard cap → %d want live %d", got, live)
	}
}
