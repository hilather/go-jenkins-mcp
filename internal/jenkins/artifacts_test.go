package jenkins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

func TestListArtifacts_NoDownload(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	jobPath := BuildJobPath("demo")
	f.setBuildArtifactsJSON(jobPath, 7, `{
	  "timestamp": 1700000000000,
	  "artifacts": [
	    {"fileName": "out.txt", "relativePath": "reports/out.txt"},
	    {"fileName": "app.jar", "relativePath": "dist/app.jar"}
	  ]
	}`)
	// Register downloadable body — list must not touch it.
	f.setArtifact(jobPath, 7, "reports/out.txt", []byte("secret-should-not-download"))

	list, err := f.opts().ListArtifacts(context.Background(), "demo", 7, 50)
	if err != nil {
		t.Fatal(err)
	}
	if list.Count != 2 || list.BytesDownloaded != 0 {
		t.Fatalf("list = %+v", list)
	}
	if f.artifactHits.Load() != 0 {
		t.Fatalf("list-only must not hit artifact download; hits=%d", f.artifactHits.Load())
	}
	if list.Artifacts[0].Path != "reports/out.txt" {
		t.Fatalf("path = %q", list.Artifacts[0].Path)
	}
}

func TestGetArtifactText_Bounded(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	jobPath := BuildJobPath("demo")
	body := []byte("hello artifact text\nline2\n")
	f.setArtifact(jobPath, 7, "reports/out.txt", body)

	at, err := f.opts().GetArtifactText(context.Background(), "demo", 7, "reports/out.txt", 0)
	if err != nil {
		t.Fatal(err)
	}
	if at.Content != string(body) {
		t.Fatalf("content = %q", at.Content)
	}
	sum := sha256.Sum256(body)
	if at.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha = %s", at.SHA256)
	}
	if f.artifactHits.Load() != 1 {
		t.Fatalf("hits = %d", f.artifactHits.Load())
	}
	if !strings.Contains(at.Ref, "artifact:reports/out.txt") {
		t.Fatalf("ref = %q", at.Ref)
	}
}

func TestGetArtifactText_SizeCap(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	big := []byte(strings.Repeat("a", 1000))
	f.setArtifact(BuildJobPath("demo"), 1, "big.txt", big)

	at, err := f.opts().GetArtifactText(context.Background(), "demo", 1, "big.txt", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(at.Content) != 100 || !at.Truncated {
		t.Fatalf("len=%d trunc=%v", len(at.Content), at.Truncated)
	}
}

func TestGetArtifactText_RefuseBinaryExt(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setArtifact(BuildJobPath("demo"), 1, "lib/app.so", []byte{0x7f, 'E', 'L', 'F'})

	_, err := f.opts().GetArtifactText(context.Background(), "demo", 1, "lib/app.so", 100)
	if err == nil {
		t.Fatal("expected refuse")
	}
	if !apperr.IsCode(err, apperr.CodeInvalidArgument) {
		t.Fatalf("code = %v", apperr.CodeOf(err))
	}
	if f.artifactHits.Load() != 0 {
		t.Fatal("must not download refused extension")
	}
}

func TestGetArtifactText_PathTraversal(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	cases := []string{
		"../etc/passwd",
		"/etc/passwd",
		"foo/../../secret",
		"https://evil/x",
		"..",
		"",
	}
	for _, p := range cases {
		_, err := f.opts().GetArtifactText(context.Background(), "demo", 1, p, 100)
		if err == nil {
			t.Fatalf("path %q should fail", p)
		}
		if !apperr.IsCode(err, apperr.CodeInvalidArgument) {
			t.Fatalf("path %q code = %v err = %v", p, apperr.CodeOf(err), err)
		}
	}
}

func TestGetArtifactText_NULBinaryContent(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setArtifact(BuildJobPath("demo"), 1, "odd.dat", []byte("a\x00b"))

	_, err := f.opts().GetArtifactText(context.Background(), "demo", 1, "odd.dat", 100)
	if err == nil || !apperr.IsCode(err, apperr.CodeInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

func TestSanitizeArtifactPath(t *testing.T) {
	ok, err := SanitizeArtifactPath("reports/out.txt")
	if err != nil || ok != "reports/out.txt" {
		t.Fatalf("%q %v", ok, err)
	}
	// Clean redundant dots without escaping.
	ok, err = SanitizeArtifactPath("a/./b")
	if err != nil || ok != "a/b" {
		t.Fatalf("%q %v", ok, err)
	}
}

func TestListArtifacts_NotFound(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	// Force 404 by overriding handle — use missing build via empty server default?
	// Fixture returns defaultBuildJSON for any build api. Use a client against closed server.
	c := f.opts()
	f.close()
	_, err := c.ListArtifacts(context.Background(), "demo", 1, 10)
	if err == nil {
		t.Fatal("expected error against closed server")
	}
}

// Wave 43: ListArtifacts uses the live ArtifactListBodyBytes bound for
// readLimited. A tiny bound truncates the mock JSON → fail-closed (invalid JSON).
// Regression: body bound was a fixed private const; operator raise must apply.
func TestListArtifacts_UsesLiveBodyBound(t *testing.T) {
	// Not parallel: mutates package-level artifactListBodyBytes.
	prev := ArtifactListBodyBytes()
	defer SetArtifactListBodyBytes(prev)

	f := newJenkinsFixture()
	defer f.close()
	jobPath := BuildJobPath("demo")

	// Build a body clearly larger than 128 bytes with valid JSON structure.
	var b strings.Builder
	b.WriteString(`{"timestamp":1700000000000,"artifacts":[`)
	for i := 0; i < 40; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"fileName":"file-%04d-long-name.txt","relativePath":"reports/subdir/file-%04d-long-name.txt"}`, i, i)
	}
	b.WriteString(`]}`)
	body := b.String()
	if len(body) < 500 {
		t.Fatalf("fixture body too small for truncate test: %d", len(body))
	}
	f.setBuildArtifactsJSON(jobPath, 9, body)

	// Tiny bound: readLimited truncates mid-JSON → Unmarshal fails closed.
	SetArtifactListBodyBytes(128)
	if ArtifactListBodyBytes() != 128 {
		t.Fatalf("live bound not set: %d", ArtifactListBodyBytes())
	}
	_, err := f.opts().ListArtifacts(context.Background(), "demo", 9, 50)
	if err == nil {
		t.Fatal("expected fail closed when list JSON exceeds live body bound")
	}
	// Must not succeed silently; error should not leak body contents as secrets
	// (paths are not secrets; just ensure we got a protocol/read failure path).
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "artifact") && !strings.Contains(msg, "json") && !strings.Contains(msg, "invalid") {
		t.Fatalf("unexpected error shape: %v", err)
	}

	// Adequate bound: full list succeeds (proves bound is what failed above).
	SetArtifactListBodyBytes(DefaultArtifactListBodyBytes)
	list, err := f.opts().ListArtifacts(context.Background(), "demo", 9, 50)
	if err != nil {
		t.Fatalf("with default body bound: %v", err)
	}
	if list.Count != 40 {
		t.Fatalf("count=%d want 40 truncated=%v", list.Count, list.Truncated)
	}

	// Constants sanity (Wave 43).
	if DefaultArtifactListBodyBytes != 2<<20 {
		t.Fatalf("DefaultArtifactListBodyBytes=%d want 2MiB", DefaultArtifactListBodyBytes)
	}
	if AbsoluteMaxArtifactListBodyBytes != 8<<20 {
		t.Fatalf("AbsoluteMaxArtifactListBodyBytes=%d want 8MiB", AbsoluteMaxArtifactListBodyBytes)
	}
	if AbsoluteMaxArtifactListBodyBytes <= DefaultArtifactListBodyBytes {
		t.Fatalf("absolute %d must exceed default %d", AbsoluteMaxArtifactListBodyBytes, DefaultArtifactListBodyBytes)
	}
}

// Wave 42: ListArtifacts clamps maxArtifacts to AbsoluteMaxArtifactsHardCap
// (not DefaultArtifactsHardCap), so tools can pass operator-raised hard caps.
func TestListArtifacts_AcceptsMaxUpToAbsolute(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	jobPath := BuildJobPath("demo")

	// Build more artifacts than DefaultArtifactsHardCap but within AbsoluteMax.
	// Use AbsoluteMax to prove client does not still clamp at 500.
	const n = 600 // > DefaultArtifactsHardCap(500), ≤ AbsoluteMax(2000)
	var b strings.Builder
	b.WriteString(`{"timestamp":1700000000000,"artifacts":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		name := strings.Repeat("x", 1) // short paths keep body under 2 MiB
		fmt.Fprintf(&b, `{"fileName":"f%04d.txt","relativePath":"r/%s-%04d.txt"}`, i, name, i)
	}
	b.WriteString(`]}`)
	f.setBuildArtifactsJSON(jobPath, 3, b.String())

	// Request past default hard cap — client AbsoluteMax clamp only.
	list, err := f.opts().ListArtifacts(context.Background(), "demo", 3, n)
	if err != nil {
		t.Fatal(err)
	}
	if list.Count != n || len(list.Artifacts) != n {
		t.Fatalf("want %d artifacts (AbsoluteMax path), got count=%d len=%d truncated=%v",
			n, list.Count, len(list.Artifacts), list.Truncated)
	}
	if list.Truncated {
		t.Fatal("truncated want false when n ≤ AbsoluteMax and full list returned")
	}

	// Over AbsoluteMax clamps (does not error).
	list2, err := f.opts().ListArtifacts(context.Background(), "demo", 3, AbsoluteMaxArtifactsHardCap+50)
	if err != nil {
		t.Fatal(err)
	}
	// Server only has n items; clamp would be AbsoluteMax but body has n.
	if list2.Count != n {
		t.Fatalf("over AbsoluteMax still returns available count=%d want %d", list2.Count, n)
	}

	// Constants sanity.
	if DefaultArtifactsHardCap != 500 || MaxArtifactsHardCap != DefaultArtifactsHardCap {
		t.Fatalf("Default=%d Max alias=%d", DefaultArtifactsHardCap, MaxArtifactsHardCap)
	}
	if AbsoluteMaxArtifactsHardCap != 2000 || AbsoluteMaxArtifactsHardCap <= DefaultArtifactsHardCap {
		t.Fatalf("AbsoluteMax=%d", AbsoluteMaxArtifactsHardCap)
	}
}
