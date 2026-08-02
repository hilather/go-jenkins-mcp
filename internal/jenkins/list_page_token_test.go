package jenkins

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// MCP-001 opaque list pagination: get_jobs, list_jobs, list_builds.

func TestGetJobs_PageTokenFlow(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()

	// Default fixture has a single root job ("demo"); inject many root jobs.
	f.jobsJSON = multiRootJobsJSON(5)

	page1, err := f.opts().GetJobs(context.Background(), GetJobsToolArgs{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page1.JobList) != 2 {
		t.Fatalf("page1 len=%d total=%d", len(page1.JobList), page1.Total)
	}
	if page1.Total != 5 {
		t.Fatalf("total=%d", page1.Total)
	}
	if page1.NextPageToken == "" {
		t.Fatal("expected next_page_token when truncated")
	}

	page2, err := f.opts().GetJobs(context.Background(), GetJobsToolArgs{
		PageToken: page1.NextPageToken,
		// Conflicting offset/limit must be ignored (page_token wins).
		Offset: 0,
		Limit:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page2.JobList) != 2 {
		t.Fatalf("page2 len=%d (token limit should win)", len(page2.JobList))
	}
	if page2.Offset != 2 {
		t.Fatalf("page2 offset=%d want 2", page2.Offset)
	}
	if page1.JobList[0].Name == page2.JobList[0].Name {
		t.Fatal("pages should not overlap first element")
	}

	// Drain remaining pages.
	tok := page2.NextPageToken
	seen := map[string]struct{}{}
	for _, j := range page1.JobList {
		seen[j.Name] = struct{}{}
	}
	for _, j := range page2.JobList {
		seen[j.Name] = struct{}{}
	}
	for tok != "" {
		p, err := f.opts().GetJobs(context.Background(), GetJobsToolArgs{PageToken: tok})
		if err != nil {
			t.Fatal(err)
		}
		for _, j := range p.JobList {
			if _, dup := seen[j.Name]; dup {
				t.Fatalf("duplicate job %q across pages", j.Name)
			}
			seen[j.Name] = struct{}{}
		}
		tok = p.NextPageToken
	}
	if len(seen) != 5 {
		t.Fatalf("collected %d jobs want 5", len(seen))
	}
}

func TestGetJobs_BadPageTokenRejects(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()

	_, err := f.opts().GetJobs(context.Background(), GetJobsToolArgs{PageToken: "not-a-token!!!"})
	if err == nil {
		t.Fatal("expected invalid_argument")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
}

func TestGetJobs_TokenCannotRaiseHardMax(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.jobsJSON = multiRootJobsJSON(10)

	// Craft a token with limit above maxGetJobsLimit.
	fp := FilterFingerprint("get_jobs")
	tok := EncodePageToken(0, maxGetJobsLimit+500, fp)
	res, err := f.opts().GetJobs(context.Background(), GetJobsToolArgs{PageToken: tok})
	if err != nil {
		t.Fatal(err)
	}
	if res.Limit > maxGetJobsLimit {
		t.Fatalf("limit=%d exceeds hard max %d", res.Limit, maxGetJobsLimit)
	}
	if res.Limit != maxGetJobsLimit {
		t.Fatalf("limit=%d want hard max %d", res.Limit, maxGetJobsLimit)
	}
}

func TestListJobs_PageTokenFlow(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setNestedJobsFixture()

	page1, err := f.opts().ListJobs(context.Background(), ListJobsToolArgs{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page1.Jobs) != 2 || page1.NextPageToken == "" {
		t.Fatalf("page1=%+v", page1)
	}

	page2, err := f.opts().ListJobs(context.Background(), ListJobsToolArgs{
		PageToken: page1.NextPageToken,
		Offset:    0, // ignored
		Limit:     99,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page2.Offset != 2 {
		t.Fatalf("offset=%d", page2.Offset)
	}
	if len(page2.Jobs) == 0 {
		t.Fatal("empty page2")
	}
	if page1.Jobs[0].FullName == page2.Jobs[0].FullName {
		t.Fatal("overlap")
	}

	// Complete collection without skip/dup.
	names := []string{}
	for _, j := range page1.Jobs {
		names = append(names, j.FullName)
	}
	tok := page1.NextPageToken
	for tok != "" {
		p, err := f.opts().ListJobs(context.Background(), ListJobsToolArgs{PageToken: tok})
		if err != nil {
			t.Fatal(err)
		}
		for _, j := range p.Jobs {
			names = append(names, j.FullName)
		}
		tok = p.NextPageToken
	}
	if len(names) != page1.Total {
		t.Fatalf("collected %d want total %d", len(names), page1.Total)
	}
	seen := map[string]struct{}{}
	for _, n := range names {
		if _, ok := seen[n]; ok {
			t.Fatalf("duplicate %q", n)
		}
		seen[n] = struct{}{}
	}
}

func TestListJobs_PageTokenFilterMismatch(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setNestedJobsFixture()

	page1, err := f.opts().ListJobs(context.Background(), ListJobsToolArgs{
		NameContains: "PR-",
		Limit:        1,
	})
	if err != nil {
		t.Fatal(err)
	}
	// With filter, may or may not have next page; force a token for the filter.
	fp := FilterFingerprint("list_jobs", "", "pr-", "", FormatFilterInt(DefaultListJobsDepth), FormatFilterBool(false))
	tok := page1.NextPageToken
	if tok == "" {
		tok = EncodePageToken(0, 1, fp)
	}

	// Same token with different NameContains → reject.
	_, err = f.opts().ListJobs(context.Background(), ListJobsToolArgs{
		PageToken:    tok,
		NameContains: "other",
	})
	if err == nil {
		t.Fatal("expected filter mismatch")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s msg=%v", apperr.CodeOf(err), err)
	}
	if !strings.Contains(err.Error(), "filter") {
		t.Fatalf("expected filter message: %v", err)
	}
}

func TestListJobs_BadPageTokenRejects(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	_, err := f.opts().ListJobs(context.Background(), ListJobsToolArgs{PageToken: "%%%bad"})
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("err=%v", err)
	}
}

func TestListBuilds_PageTokenFlow(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()

	page1, err := f.opts().ListBuilds(context.Background(), ListBuildsToolArgs{
		JobName: "demo",
		Limit:   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page1.Builds) != 2 {
		t.Fatalf("page1 len=%d matched=%d", len(page1.Builds), page1.Matched)
	}
	if page1.Matched < 3 {
		t.Fatalf("fixture should have >=3 builds, matched=%d", page1.Matched)
	}
	if page1.NextPageToken == "" {
		t.Fatal("expected next_page_token")
	}
	if page1.Offset != 0 {
		t.Fatalf("offset=%d", page1.Offset)
	}

	page2, err := f.opts().ListBuilds(context.Background(), ListBuildsToolArgs{
		JobName:   "demo",
		PageToken: page1.NextPageToken,
		Offset:    0,
		Limit:     1, // ignored
	})
	if err != nil {
		t.Fatal(err)
	}
	if page2.Offset != 2 {
		t.Fatalf("page2 offset=%d", page2.Offset)
	}
	if len(page2.Builds) == 0 {
		t.Fatal("empty page2")
	}
	if page1.Builds[0].Number == page2.Builds[0].Number {
		t.Fatal("pages should not overlap")
	}

	// Bad token
	_, err = f.opts().ListBuilds(context.Background(), ListBuildsToolArgs{
		JobName:   "demo",
		PageToken: "nope",
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("bad token err=%v", err)
	}

	// Filter fingerprint: token for demo cannot be reused with different result filter.
	_, err = f.opts().ListBuilds(context.Background(), ListBuildsToolArgs{
		JobName:   "demo",
		Result:    "FAILURE",
		PageToken: page1.NextPageToken,
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("filter mismatch err=%v", err)
	}
}

func TestListBuilds_TokenHardCap(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	fp := FilterFingerprint(
		"list_builds", "demo", FormatFilterInt(0), "",
		FormatFilterInt(defaultListBuildsLookback), FormatFilterBool(false),
	)
	tok := EncodePageToken(0, maxListBuildsLimit+100, fp)
	res, err := f.opts().ListBuilds(context.Background(), ListBuildsToolArgs{
		JobName:   "demo",
		PageToken: tok,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Limit != maxListBuildsLimit {
		t.Fatalf("limit=%d want %d", res.Limit, maxListBuildsLimit)
	}
}

// multiRootJobsJSON returns a root /api/json jobs payload with n free-style jobs.
func multiRootJobsJSON(n int) string {
	var b strings.Builder
	b.WriteString(`{"jobs":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		name := "job-" + strconv.Itoa(i)
		b.WriteString(`{"name":"` + name + `","url":"http://jenkins/job/` + name + `/","color":"blue","buildable":true,"description":"","lastBuild":null}`)
	}
	b.WriteString(`]}`)
	return b.String()
}
