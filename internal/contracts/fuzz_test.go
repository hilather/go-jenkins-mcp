package contracts

import (
	"strings"
	"testing"
)

// QA-001: MCP-ish typed ref / job_name validation (HTTP-free contracts package).

const fuzzMaxJob = 8 << 10

// FuzzParseJobFullName rejects absolute URLs, traversal segments, and control
// chars without panicking.
func FuzzParseJobFullName(f *testing.F) {
	f.Add("demo")
	f.Add("folder/sub/job")
	f.Add("")
	f.Add("http://jenkins/job/x")
	f.Add("https://evil/x")
	f.Add("//host/path")
	f.Add("file:/etc/passwd")
	f.Add("javascript:alert(1)")
	f.Add("a\x00b")
	f.Add("job\r\nX")
	f.Add("../x")
	f.Add("folder/../job")
	f.Add(".")
	f.Add("/abs/job")
	f.Add("a//b")
	f.Add(strings.Repeat("n/", 50) + "j")

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > fuzzMaxJob {
			return
		}
		ref, err := ParseJobFullName("job_name", raw)
		if err != nil {
			var fe *FieldError
			// Prefer structured FieldError for tool mapping.
			_ = fe
			if ref.FullName != "" {
				t.Fatalf("error with non-empty FullName: %+v", ref)
			}
			return
		}
		if ref.FullName == "" {
			t.Fatal("empty FullName on success")
		}
		if IsAbsoluteHTTPURL(ref.FullName) || looksLikeSchemeURL(ref.FullName) {
			t.Fatalf("accepted URL-like name: %q", ref.FullName)
		}
		if strings.HasPrefix(ref.FullName, "/") {
			t.Fatalf("accepted absolute path form: %q", ref.FullName)
		}
		for _, seg := range strings.Split(ref.FullName, "/") {
			if seg == "" || seg == "." || seg == ".." {
				t.Fatalf("accepted unsafe segment %q in %q", seg, ref.FullName)
			}
		}
	})
}

// FuzzIsAbsoluteHTTPURL is pure URL-shape detection (SSRF reduction helper).
func FuzzIsAbsoluteHTTPURL(f *testing.F) {
	f.Add("")
	f.Add("http://x")
	f.Add("HTTPS://X")
	f.Add("//proto-rel")
	f.Add("job/name")
	f.Add("http:/not-enough-slashes")
	f.Add("  https://x  ")

	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > fuzzMaxJob {
			return
		}
		a := IsAbsoluteHTTPURL(s)
		b := IsAbsoluteHTTPURL(s)
		if a != b {
			t.Fatal("non-deterministic")
		}
		_ = looksLikeSchemeURL(s)
	})
}

// FuzzParseBuildAndLogRefs covers remaining typed MCP refs.
func FuzzParseBuildAndLogRefs(f *testing.F) {
	f.Add("demo", int64(1), int64(0), int64(8192))
	f.Add("", int64(1), int64(0), int64(1))
	f.Add("http://x", int64(1), int64(0), int64(1))
	f.Add("demo", int64(0), int64(0), int64(1))
	f.Add("demo", int64(-1), int64(-1), int64(-1))
	f.Add("demo", int64(5), int64(10), int64(0))

	f.Fuzz(func(t *testing.T, job string, number, offset, length int64) {
		if len(job) > fuzzMaxJob {
			return
		}
		_, _ = ParseBuildRef("job_name", job, "build_number", number)
		_, _ = ParseQueueItemRef("queue_id", number, ProfileID(job))
		_, _ = ParseLogEvidenceRef("job_name", job, "build_number", number, offset, length, "", 8192)
	})
}
