package tools

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// Wave 40 / POL-005 tools-layer conformance for Wave 39–40 list privacy.
// Hard-asserts (Wave 40 Done* — must pass on main):
//   - FilterDeniedArtifacts / FilterDeniedBranchJobs composition is deny-only
//   - list_jobs incomplete collect forces Truncated + non-secret Message
//   - listArtifactsWithPolicyFilter hard-cap fetch-then-filter (denied rows
//     do not steal max_artifacts slots)
//   - PolicyFingerprintMaterial sorted/namespaced for page-token binding

// TestWave40_FilterDeniedComposition_DenyOnly proves FilterDeniedArtifacts and
// FilterDeniedBranchJobs compose as deny-only (AND of keeps; never invent rows;
// empty patterns preserve input). Exported helpers only.
func TestWave40_FilterDeniedComposition_DenyOnly(t *testing.T) {
	t.Parallel()

	arts := []jenkins.ArtifactMeta{
		{Path: "reports/out.txt", FileName: "out.txt"},
		{Path: "secrets/creds.txt", FileName: "creds.txt"},
		{Path: "dist/app.jar", FileName: "app.jar"},
		{Path: "key.pem", FileName: "key.pem"},
		{Path: "exact/./creds.txt", FileName: "creds.txt"},
	}
	// Deny-only: omit secrets + pem + exact path after clean; never invent.
	keptA, omA := FilterDeniedArtifacts([]string{"secrets/**", "*.pem", "exact/creds.txt"}, arts)
	if omA != 3 {
		t.Fatalf("artifacts omitted=%d want 3", omA)
	}
	if len(keptA) != 2 {
		t.Fatalf("artifacts kept=%d want 2: %+v", len(keptA), keptA)
	}
	for _, a := range keptA {
		if strings.HasPrefix(a.Path, "secrets/") || strings.HasSuffix(a.Path, ".pem") ||
			a.Path == "exact/./creds.txt" || a.Path == "exact/creds.txt" {
			t.Fatalf("denied artifact leaked: %q", a.Path)
		}
	}
	// Empty patterns → shallow copy, omitted=0 (no elevation / no drop).
	allA, om0 := FilterDeniedArtifacts(nil, arts)
	if om0 != 0 || len(allA) != len(arts) {
		t.Fatalf("empty artifact patterns: kept=%d omitted=%d", len(allA), om0)
	}
	// Nil + empty → nil, 0.
	nilA, omNil := FilterDeniedArtifacts(nil, nil)
	if nilA != nil || omNil != 0 {
		t.Fatalf("nil arts: kept=%v omitted=%d", nilA, omNil)
	}

	jobs := []jenkins.JobSummary{
		{FullName: "team/mb/release/1.2", Name: "1.2", Kind: jenkins.JobKindBranch},
		{FullName: "team/mb/main", Name: "main", Kind: jenkins.JobKindBranch},
		{FullName: "team/mb/feature-x", Name: "feature-x", Kind: jenkins.JobKindBranch},
		{FullName: "team/app", Name: "app", Kind: jenkins.JobKindJob},
		{FullName: "main", Name: "main", Kind: jenkins.JobKindFolder}, // folder leaf main kept
		{FullName: "team/matrix/axis-a", Name: "axis-a", Kind: jenkins.JobKindMatrixChild},
	}
	// Slashy release/* + leaf main + matrix axis-* (Wave 39 BranchDenyCandidates).
	keptB, omB := FilterDeniedBranchJobs([]string{"release/*", "main", "axis-*"}, jobs)
	if omB != 3 {
		t.Fatalf("branch omitted=%d want 3 (release/1.2, main branch, axis-a)", omB)
	}
	for _, j := range keptB {
		if j.FullName == "team/mb/release/1.2" ||
			(j.Kind == jenkins.JobKindBranch && j.Name == "main") ||
			(j.Kind == jenkins.JobKindMatrixChild && j.Name == "axis-a") {
			t.Fatalf("denied branch row leaked: %+v", j)
		}
	}
	// Folder named main retained (kind gate).
	foundFolder := false
	for _, j := range keptB {
		if j.Kind == jenkins.JobKindFolder && j.Name == "main" {
			foundFolder = true
		}
	}
	if !foundFolder {
		t.Fatal("folder named main must be kept under deny_branch_names")
	}
	// Empty branch patterns → full copy.
	allB, omB0 := FilterDeniedBranchJobs(nil, jobs)
	if omB0 != 0 || len(allB) != len(jobs) {
		t.Fatalf("empty branch patterns: kept=%d omitted=%d", len(allB), omB0)
	}

	// Compose via ApplyJobPolicyFilters: job-prefix AND branch deny (intersection).
	// secret-folder jobs + denied branches drop; public job + feature branch keep.
	mixed := []jenkins.JobSummary{
		{FullName: "public/app", Name: "app", Kind: jenkins.JobKindJob},
		{FullName: "secret-folder/job-a", Name: "job-a", Kind: jenkins.JobKindJob},
		{FullName: "mb/main", Name: "main", Kind: jenkins.JobKindBranch},
		{FullName: "mb/feature", Name: "feature", Kind: jenkins.JobKindBranch},
		{FullName: "team/mb/release/1.2", Name: "1.2", Kind: jenkins.JobKindBranch},
	}
	keptC, omC := ApplyJobPolicyFilters(mixed,
		KeepUnlessJobPrefixDenied([]string{"secret-folder"}),
		KeepUnlessBranchDenied([]string{"main", "release/*"}),
	)
	if omC != 3 {
		t.Fatalf("composed omitted=%d want 3: kept=%+v", omC, keptC)
	}
	if len(keptC) != 2 {
		t.Fatalf("composed kept=%d want 2: %+v", len(keptC), keptC)
	}
	names := map[string]bool{}
	for _, j := range keptC {
		names[j.FullName] = true
	}
	if !names["public/app"] || !names["mb/feature"] {
		t.Fatalf("expected public/app + mb/feature, got %v", names)
	}
	if names["secret-folder/job-a"] || names["mb/main"] || names["team/mb/release/1.2"] {
		t.Fatalf("denied rows must be omitted: %v", names)
	}

	// Deny-only: filters never invent jobs not in the input set.
	for _, j := range keptC {
		found := false
		for _, in := range mixed {
			if in.FullName == j.FullName {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("filter invented job not in input: %q", j.FullName)
		}
	}
}

// TestWave40_ListJobsIncompleteMessage hard-asserts Wave 40 Done*: incomplete
// collect forces truncated=true and a non-secret Message (collection capped).
func TestWave40_ListJobsIncompleteMessage(t *testing.T) {
	// MaxListJobsLimit=200 → 201 jobs need 2 collect pages; cap at 1 page.
	const nJobs = 201
	var b strings.Builder
	b.WriteString(`{"jobs":[`)
	for i := 0; i < nJobs; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		name := fmt.Sprintf("job-%04d", i)
		fmt.Fprintf(&b, `{"name":%q,"fullName":%q,"_class":"hudson.model.FreeStyleProject","url":"http://jenkins/job/%s/","color":"blue","buildable":true}`,
			name, name, name)
	}
	b.WriteString(`]}`)
	body := b.String()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/json" && !strings.HasPrefix(r.URL.Path, "/api/json") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := &jenkins.Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}

	old := maxJobsCollectPages
	maxJobsCollectPages = 1
	defer func() { maxJobsCollectPages = old }()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"job-0000"}, // omit one so collect path is active
	})
	st := regState{policy: ev}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := listJobsWithPolicyFilter(ctx, client, st, jenkins.ListJobsToolArgs{
		Offset: 0,
		Limit:  10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("nil response")
	}
	// Wave 39 hard: incomplete collect forces truncated=true.
	if !out.Truncated {
		t.Fatalf("incomplete collect must force truncated=true; total=%d jobs=%d next=%q",
			out.Total, len(out.Jobs), out.NextPageToken)
	}
	if !out.PolicyFiltered || out.PolicyOmittedCount < 1 {
		t.Fatalf("policy: filtered=%v omitted=%d", out.PolicyFiltered, out.PolicyOmittedCount)
	}
	for _, j := range out.Jobs {
		if j.FullName == "job-0000" {
			t.Fatalf("denied job leaked: %q", j.FullName)
		}
	}

	// Wave 40 Done*: non-secret Message on incomplete collect (hard assert).
	msg := strings.TrimSpace(out.Message)
	if msg == "" {
		t.Fatal("Wave 40 Done*: ListJobsToolResponse.Message must be set on incomplete collect")
	}
	low := strings.ToLower(msg)
	if !strings.Contains(low, "incomplete") &&
		!strings.Contains(low, "capped") &&
		!strings.Contains(low, "collection") &&
		!strings.Contains(low, "truncated") {
		t.Fatalf("incomplete Message should be non-secret honesty text, got %q", msg)
	}
	// Denied names / tokens must never appear in Message.
	if strings.Contains(msg, "job-0000") || strings.Contains(low, "bearer") ||
		strings.Contains(msg, "Token") || strings.Contains(msg, srv.URL) {
		t.Fatalf("Message must not leak secrets, URLs, or denied names: %q", msg)
	}
}

// TestWave40_ListArtifactsHardCapFetch hard-asserts Wave 40 Done*:
// listArtifactsWithPolicyFilter fetches beyond user max when deny patterns live,
// filters, then re-slices so denied leading rows do not steal max_artifacts slots.
func TestWave40_ListArtifactsHardCapFetch(t *testing.T) {
	// secrets first (would steal page under pre-Wave-40 page-level filter), then reports.
	body := buildArtifactsListJSON(8, 6)
	client, closeFn := artifactListClient(t, body)
	defer closeFn()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**"},
	})
	st := regState{policy: ev}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const userMax = 2
	list, err := listArtifactsWithPolicyFilter(ctx, client, st, "demo", 7, userMax)
	if err != nil {
		t.Fatal(err)
	}
	if list == nil {
		t.Fatal("nil list")
	}
	if !list.PolicyFiltered || list.PolicyOmittedCount != 8 {
		t.Fatalf("policy flags: filtered=%v omitted=%d want true/8", list.PolicyFiltered, list.PolicyOmittedCount)
	}
	if list.Count != userMax || len(list.Artifacts) != userMax {
		t.Fatalf("want user page of %d allowed, got count=%d arts=%d paths=%v",
			userMax, list.Count, len(list.Artifacts), artifactPaths(list))
	}
	if list.Artifacts[0].Path != "reports/out-0000.txt" || list.Artifacts[1].Path != "reports/out-0001.txt" {
		t.Fatalf("hard-cap re-slice paths: %+v want reports/out-0000 + out-0001", list.Artifacts)
	}
	for _, a := range list.Artifacts {
		if strings.HasPrefix(a.Path, "secrets/") {
			t.Fatalf("denied path leaked: %q", a.Path)
		}
	}
	// 6 allowed > userMax 2 → Truncated after re-slice.
	if !list.Truncated {
		t.Fatal("truncated want true (more allowed than user max after filter)")
	}

	// Empty patterns: no hard-cap expansion required for unit foundation.
	stEmpty := regState{}
	listEmpty, err := listArtifactsWithPolicyFilter(ctx, client, stEmpty, "demo", 7, userMax)
	if err != nil {
		t.Fatal(err)
	}
	if listEmpty.PolicyFiltered || listEmpty.PolicyOmittedCount != 0 {
		t.Fatalf("empty patterns must not set policy flags: %+v", listEmpty)
	}
	if len(listEmpty.Artifacts) != userMax {
		t.Fatalf("empty patterns user max: got %d", len(listEmpty.Artifacts))
	}
}

// TestWave40_PolicyFingerprintMaterial hard-asserts Wave 40 Done*: sorted,
// namespaced deny material for page-token fingerprints; empty when no denies.
func TestWave40_PolicyFingerprintMaterial(t *testing.T) {
	t.Parallel()

	if got := PolicyFingerprintMaterial(regState{}); got != nil {
		t.Fatalf("empty policy: got %v", got)
	}
	st := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"z-job", "a-job"},
		DenyBranchNames: []string{"main", "dev"},
	})}
	got := PolicyFingerprintMaterial(st)
	// Expected: deny_job_prefixes, a-job, z-job, deny_branch_names, dev, main
	want := []string{"deny_job_prefixes", "a-job", "z-job", "deny_branch_names", "dev", "main"}
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
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"a-job", "z-job"},
		DenyBranchNames: []string{"dev", "main"},
	})}
	got2 := PolicyFingerprintMaterial(st2)
	for i := range want {
		if got2[i] != want[i] {
			t.Fatalf("order-insensitive fail: got2=%v", got2)
		}
	}
	// Material must never look like a credential / bearer token.
	for _, p := range got {
		low := strings.ToLower(p)
		if strings.Contains(low, "bearer") || strings.Contains(low, "authorization") {
			t.Fatalf("fingerprint material looks secret-like: %q", p)
		}
	}
}
