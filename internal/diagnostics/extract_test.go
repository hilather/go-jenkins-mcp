package diagnostics_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
)

func TestExtractCandidates_SampleMavenFailure(t *testing.T) {
	t.Parallel()
	log := strings.Join([]string{
		"[INFO] Scanning for projects...",
		"[INFO] Building demo 1.0.0",
		"[ERROR] Failed to execute goal on project demo: Compilation failure",
		"### Error updating database.  Cause: java.sql.SQLException: connection refused",
		"java.lang.NullPointerException: cannot read field",
		"BUILD FAILURE",
		"Total time: 12.3 s",
	}, "\n")

	res := diagnostics.ExtractCandidates(log, diagnostics.Options{IncludeNormalized: true})
	if len(res.Findings) == 0 {
		t.Fatal("expected findings")
	}
	// Every finding has evidence with exact line numbers.
	for _, f := range res.Findings {
		if f.Signature == "" {
			t.Errorf("missing signature for pattern %s", f.Pattern)
		}
		if f.LineStart <= 0 || f.LineEnd < f.LineStart {
			t.Errorf("bad line range %+v", f)
		}
		if len(f.Evidence) == 0 {
			t.Errorf("no evidence for %s", f.Signature)
		}
		if f.Confidence <= 0 || f.Confidence > 1 {
			t.Errorf("confidence out of range: %v", f.Confidence)
		}
	}
	// BUILD FAILURE should surface with high confidence.
	var sawBuildFailure bool
	for _, f := range res.Findings {
		if f.Pattern == "build_failure" {
			sawBuildFailure = true
			if f.Confidence < 0.9 {
				t.Errorf("build_failure confidence=%v", f.Confidence)
			}
		}
	}
	if !sawBuildFailure {
		t.Fatalf("expected build_failure finding; got %#v", res.Findings)
	}
	if res.FirstErrorLine == 0 {
		t.Error("expected first_error_line")
	}
}

func TestExtractCandidates_PanicAndFailed(t *testing.T) {
	t.Parallel()
	log := "ok\npanic: runtime error: index out of range\ngoroutine 1 [running]:\nTests FAILED\n"
	res := diagnostics.ExtractCandidates(log, diagnostics.Options{})
	if len(res.Findings) < 2 {
		t.Fatalf("findings=%d want >=2: %+v", len(res.Findings), res.Findings)
	}
	var sawPanic, sawFailed bool
	for _, f := range res.Findings {
		switch f.Pattern {
		case "panic":
			sawPanic = true
		case "failed_marker":
			sawFailed = true
		}
	}
	if !sawPanic || !sawFailed {
		t.Fatalf("panic=%v failed=%v findings=%+v", sawPanic, sawFailed, res.Findings)
	}
}

func TestNormalizeLine_StripsVolatileTokens(t *testing.T) {
	t.Parallel()
	// Unix paths are not stripped (documented residual); Windows drive paths use basename only.
	a := diagnostics.NormalizeLine(`2024-01-15T10:11:12Z Error: id=550e8400-e29b-41d4-a716-446655440000 code=42 path=/tmp/work`)
	b := diagnostics.NormalizeLine(`2025-06-01T00:00:00Z Error: id=11111111-2222-3333-4444-555555555555 code=99 path=/tmp/work`)
	if a == "" || b == "" {
		t.Fatal("empty normalize")
	}
	if a != b {
		t.Fatalf("volatile tokens should normalize equal:\n  a=%q\n  b=%q", a, b)
	}
	if strings.Contains(a, "550e") || strings.Contains(a, "2024") {
		t.Fatalf("uuid/timestamp leaked: %q", a)
	}
	if !strings.Contains(a, "<uuid>") || !strings.Contains(a, "<ts>") || !strings.Contains(a, "<n>") {
		t.Fatalf("expected placeholders: %q", a)
	}
	sigA := diagnostics.Signature(a)
	sigB := diagnostics.Signature(b)
	if sigA == "" || sigA != sigB {
		t.Fatalf("signatures differ: %s vs %s", sigA, sigB)
	}
	if len(sigA) != diagnostics.SignatureHexLen {
		t.Fatalf("sig len=%d", len(sigA))
	}
}

func TestExtractCandidates_SignatureGroupsRepeats(t *testing.T) {
	t.Parallel()
	log := strings.Join([]string{
		"Error: boom ref=1",
		"Error: boom ref=2",
		"Error: boom ref=3",
		"Error: different",
	}, "\n")
	res := diagnostics.ExtractCandidates(log, diagnostics.Options{IncludeNormalized: true})
	var boom *diagnostics.Finding
	for i := range res.Findings {
		if strings.Contains(res.Findings[i].Normalized, "boom") || strings.Contains(res.Findings[i].Message, "boom") {
			boom = &res.Findings[i]
			break
		}
	}
	if boom == nil {
		t.Fatalf("missing boom finding: %+v", res.Findings)
	}
	if boom.Count != 3 {
		t.Fatalf("count=%d want 3 (same signature after digit strip)", boom.Count)
	}
}

func TestExtractCandidates_MaxFindingsTruncates(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := 0; i < 20; i++ {
		// Distinct messages so each gets its own signature.
		b.WriteString("Error: unique-message-")
		b.WriteByte(byte('A' + i))
		b.WriteByte('\n')
	}
	res := diagnostics.ExtractCandidates(b.String(), diagnostics.Options{MaxFindings: 5})
	if len(res.Findings) != 5 {
		t.Fatalf("findings=%d", len(res.Findings))
	}
	if !res.Truncated {
		t.Fatal("expected truncated")
	}
}

func TestExtractCandidates_EmptyAndCleanLog(t *testing.T) {
	t.Parallel()
	if r := diagnostics.ExtractCandidates("", diagnostics.Options{}); len(r.Findings) != 0 {
		t.Fatalf("empty: %+v", r)
	}
	clean := "Started by user admin\nFinished: SUCCESS\n"
	r := diagnostics.ExtractCandidates(clean, diagnostics.Options{})
	if len(r.Findings) != 0 {
		t.Fatalf("clean log should not yield findings: %+v", r.Findings)
	}
}

func TestExtractFromHits_FallbackSearchHit(t *testing.T) {
	t.Parallel()
	// Hit that does not match failure rules still surfaces (no data loss).
	hits := []diagnostics.SearchHit{
		{Line: 10, Text: "something odd but not an error marker"},
		{Line: 20, Text: "BUILD FAILURE"},
	}
	res := diagnostics.ExtractFromHits(hits, diagnostics.Options{})
	if len(res.Findings) < 2 {
		t.Fatalf("findings=%+v", res.Findings)
	}
	var sawSearch, sawBF bool
	for _, f := range res.Findings {
		if f.Pattern == "search_hit" {
			sawSearch = true
			if f.LineStart != 10 {
				t.Errorf("search_hit line=%d", f.LineStart)
			}
		}
		if f.Pattern == "build_failure" {
			sawBF = true
		}
	}
	if !sawSearch || !sawBF {
		t.Fatalf("search=%v bf=%v %+v", sawSearch, sawBF, res.Findings)
	}
}

func TestExtractCandidates_EvidenceMapsToSource(t *testing.T) {
	t.Parallel()
	log := "line1\nError: exact-source\nline3\n"
	res := diagnostics.ExtractCandidates(log, diagnostics.Options{})
	if len(res.Findings) != 1 {
		t.Fatalf("findings=%+v", res.Findings)
	}
	f := res.Findings[0]
	if f.LineStart != 2 || f.Evidence[0].Line != 2 {
		t.Fatalf("line mapping: %+v", f)
	}
	if f.Evidence[0].Text != "Error: exact-source" {
		t.Fatalf("text=%q", f.Evidence[0].Text)
	}
}

// TestExtractCandidates_NewAdapterRules covers Wave 23 DIAG-001 expanded markers.
// Each rule id must surface on a representative line without relying on generics.
func TestExtractCandidates_NewAdapterRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		line    string
		pattern string
	}{
		{"gradle", "FAILURE: Build failed with an exception.", "gradle_failure"},
		{"junit_triple", "testFoo(com.example.FooTest)  Time elapsed: 0.01 s  <<< FAILURE!", "junit_surefire"},
		{"junit_error", "testBar  Time elapsed: 0.1 s  <<< ERROR!", "junit_surefire"},
		{"junit_phrase", "There are test failures.", "junit_surefire"},
		{"surefire_summary_fail", "Tests run: 12, Failures: 2, Errors: 0, Skipped: 0", "junit_surefire"},
		{"surefire_summary_err", "Tests run: 3, Failures: 0, Errors: 1, Skipped: 0", "junit_surefire"},
		{"go_fail_test", "--- FAIL: TestParse (0.01s)", "go_test_fail"},
		{"go_fail_pkg", "FAIL\tgithub.com/acme/pkg\t0.123s", "go_test_fail"},
		{"npm_err", "npm ERR! code ELIFECYCLE", "npm_error"},
		{"npm_errno", "npm ERR! errno 1", "npm_error"},
		{"elifecycle_alone", "ELIFECYCLE Command failed with exit code 1.", "npm_error"},
		{"oom_java", "java.lang.OutOfMemoryError: Java heap space", "oom"},
		{"oom_linux", "Out of memory: Killed process 4242 (java)", "oom"},
		{"docker", "Error response from daemon: conflict: unable to delete image", "docker_daemon"},
		{"k8s", "pod/app-7d9f8 Back-off restarting failed container: CrashLoopBackOff", "k8s_crashloop"},
		{"clang", "src/main.c:42:5: error: use of undeclared identifier 'x'", "clang_error"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			line := strings.TrimSuffix(tc.line, "\n")
			res := diagnostics.ExtractCandidates(line, diagnostics.Options{})
			if len(res.Findings) == 0 {
				t.Fatalf("no findings for %q", line)
			}
			// First finding should be the specialized rule (single-line input).
			if res.Findings[0].Pattern != tc.pattern {
				t.Fatalf("pattern=%q want %q findings=%+v", res.Findings[0].Pattern, tc.pattern, res.Findings)
			}
			if res.Findings[0].Confidence <= 0 {
				t.Fatalf("confidence=%v", res.Findings[0].Confidence)
			}
			if res.Findings[0].LineStart != 1 {
				t.Fatalf("line_start=%d", res.Findings[0].LineStart)
			}
		})
	}
}

func TestExtractCandidates_SurefireCleanSummaryNoMatch(t *testing.T) {
	t.Parallel()
	// Residual false-positive guard: clean Surefire summary must not match.
	log := "Tests run: 12, Failures: 0, Errors: 0, Skipped: 1"
	res := diagnostics.ExtractCandidates(log, diagnostics.Options{})
	if len(res.Findings) != 0 {
		t.Fatalf("clean surefire summary should not match: %+v", res.Findings)
	}
}

func TestExtractCandidates_BareKilledNoMatch(t *testing.T) {
	t.Parallel()
	// Bare "Killed" is intentionally excluded (OOM rule residual).
	log := "script.sh: line 10: 12345 Killed"
	res := diagnostics.ExtractCandidates(log, diagnostics.Options{})
	if len(res.Findings) != 0 {
		t.Fatalf("bare Killed should not match: %+v", res.Findings)
	}
}

func TestExtractCandidates_MultiAdapterLog(t *testing.T) {
	t.Parallel()
	log := strings.Join([]string{
		"npm ERR! code ELIFECYCLE",
		"--- FAIL: TestX (0.00s)",
		"FAILURE: Build failed with an exception.",
		"BUILD FAILURE",
	}, "\n")
	res := diagnostics.ExtractCandidates(log, diagnostics.Options{})
	want := map[string]bool{
		"npm_error":      false,
		"go_test_fail":   false,
		"gradle_failure": false,
		"build_failure":  false,
	}
	for _, f := range res.Findings {
		if _, ok := want[f.Pattern]; ok {
			want[f.Pattern] = true
		}
	}
	for id, saw := range want {
		if !saw {
			t.Errorf("missing pattern %s in %+v", id, res.Findings)
		}
	}
}

func TestNormalizeLine_WindowsPathBasename(t *testing.T) {
	t.Parallel()
	a := diagnostics.NormalizeLine(`C:\Users\builder\work\src\main.go: error: boom`)
	b := diagnostics.NormalizeLine(`D:\other\checkout\src\main.go: error: boom`)
	if a == "" || b == "" {
		t.Fatal("empty normalize")
	}
	if a != b {
		t.Fatalf("windows basenames should normalize equal:\n  a=%q\n  b=%q", a, b)
	}
	if strings.Contains(a, `users`) || strings.Contains(a, `builder`) || strings.Contains(a, `c:`) {
		t.Fatalf("directory leaked: %q", a)
	}
	if !strings.Contains(a, "main.go") {
		t.Fatalf("basename missing: %q", a)
	}
	// Unix absolute paths remain residual (not stripped to basename).
	u := diagnostics.NormalizeLine(`/home/builder/work/src/main.go: error: boom`)
	if !strings.Contains(u, "/home/") && !strings.Contains(u, "home") {
		// After digit strip path may still contain home/builder segments.
		t.Logf("unix path normalize (residual): %q", u)
	}
	if strings.Contains(u, `c:`) {
		t.Fatalf("unexpected win marker in unix line: %q", u)
	}
}
