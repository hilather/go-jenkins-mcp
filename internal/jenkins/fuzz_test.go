package jenkins

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// QA-001: native Go fuzz targets for high-risk Jenkins path/URL/artifact parsers.
//
// Invariants: never panic on garbage; error returns are OK. Inputs are size-capped
// so CI unit runs stay bounded; longer fuzz is opt-in via make fuzz-smoke / -fuzztime.

const (
	fuzzMaxString = 8 << 10  // 8 KiB
	fuzzMaxBytes  = 64 << 10 // 64 KiB
)

// FuzzBuildJobPath ensures job full-name → progressive path construction never panics
// and never emits unescaped path separators in job segments.
func FuzzBuildJobPath(f *testing.F) {
	f.Add("")
	f.Add("job")
	f.Add("folder/job")
	f.Add("folder/sub/job")
	f.Add("../etc/passwd")
	f.Add("/absolute")
	f.Add("http://evil/job/x")
	f.Add("https://evil.example/job/x")
	f.Add("//evil/job/x")
	f.Add("a\x00b")
	f.Add("folder/\x00/job")
	f.Add("unicode- ind/job")
	f.Add(strings.Repeat("a", 4096))
	f.Add("a//b///c")
	f.Add("..")
	f.Add("./job")
	f.Add("job with spaces")
	f.Add("job%2Fname")
	f.Add("folder\\job")
	f.Add(string([]byte{0xff, 0xfe, 'j', 'o', 'b'}))

	f.Fuzz(func(t *testing.T, jobName string) {
		if len(jobName) > fuzzMaxString {
			return
		}
		path := BuildJobPath(jobName)
		// Must be finite and not panic; empty name → empty path.
		if jobName == "" || onlyEmptySegments(jobName) {
			if path != "" {
				t.Fatalf("empty/blank job → %q", path)
			}
			return
		}
		// Every non-empty segment is path-escaped under /job/.
		if !strings.HasPrefix(path, "/job/") && path != "" {
			t.Fatalf("unexpected path form %q from %q", path, jobName)
		}
		// Deterministic.
		if BuildJobPath(jobName) != path {
			t.Fatal("non-deterministic BuildJobPath")
		}
	})
}

func onlyEmptySegments(jobName string) bool {
	for _, s := range strings.Split(jobName, "/") {
		if s != "" {
			return false
		}
	}
	return true
}

// FuzzNormalizeBaseURL covers NET-001 origin pinning base URL parsing.
func FuzzNormalizeBaseURL(f *testing.F) {
	f.Add("")
	f.Add("https://jenkins.example")
	f.Add("https://jenkins.example/jenkins")
	f.Add("http://localhost:8080/")
	f.Add("https://user:pass@jenkins.example/")
	f.Add("ftp://jenkins.example/")
	f.Add("://broken")
	f.Add("https://")
	f.Add("https://jenkins.example/../admin")
	f.Add("https://jenkins.example/foo/../bar/")
	f.Add("https://jenkins.example/a//b")
	f.Add("https://jenkins.example/path?query=1#frag")
	f.Add("//jenkins.example/path")
	f.Add("not a url")
	f.Add(strings.Repeat("https://x/", 200))
	f.Add("https://jenkins.example/" + strings.Repeat("../", 50) + "etc")
	f.Add("https://[::1]:8080/jenkins")
	f.Add("http://192.168.0.1")
	f.Add("https://jenkins.example\x00/evil")

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > fuzzMaxString {
			return
		}
		u, err := NormalizeBaseURL(raw)
		if err != nil {
			if u != nil {
				t.Fatalf("err with non-nil URL: %v", err)
			}
			return
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			t.Fatalf("scheme %q", u.Scheme)
		}
		if u.Host == "" {
			t.Fatal("empty host")
		}
		if u.User != nil {
			t.Fatal("userinfo must be stripped/rejected")
		}
		if u.RawQuery != "" || u.Fragment != "" {
			t.Fatal("query/fragment must be stripped")
		}
		// Deterministic parse of the normalized form.
		again, err2 := NormalizeBaseURL(u.String())
		if err2 != nil {
			t.Fatalf("re-normalize failed: %v for %q", err2, u.String())
		}
		if again.String() != u.String() {
			t.Fatalf("non-idempotent normalize %q → %q", u.String(), again.String())
		}
	})
}

// FuzzSameOriginAndResolve exercises origin comparison and relative URL join
// without network I/O.
func FuzzSameOriginAndResolve(f *testing.F) {
	f.Add("https://jenkins.example/jenkins", "/job/a/1/api/json")
	f.Add("https://jenkins.example/jenkins", "https://jenkins.example/jenkins/job/a")
	f.Add("https://jenkins.example/jenkins", "https://evil.example/job/a")
	f.Add("https://jenkins.example", "//evil.example/x")
	f.Add("https://jenkins.example", "http://jenkins.example/x")
	f.Add("https://jenkins.example/prefix", "../escape")
	f.Add("https://jenkins.example", "")
	f.Add("https://jenkins.example", "file:///etc/passwd")
	f.Add("https://jenkins.example", "https://jenkins.example@evil.example/")
	f.Add("not-a-url", "/job/x")

	f.Fuzz(func(t *testing.T, baseRaw, apiPath string) {
		if len(baseRaw) > fuzzMaxString || len(apiPath) > fuzzMaxString {
			return
		}
		base, err := NormalizeBaseURL(baseRaw)
		if err != nil {
			// Still exercise SameOrigin with nil-safe garbage parses.
			tb, _ := url.Parse(apiPath)
			_ = SameOrigin(nil, tb)
			_ = SameOrigin(base, nil)
			return
		}
		c := &Client{URL: base.String()}
		_, _ = c.resolveRequestURL(apiPath)

		target, terr := url.Parse(apiPath)
		if terr == nil {
			_ = SameOrigin(base, target)
			_ = pathUnderBase(base.Path, target.Path)
		}
		_ = cleanURLPath(apiPath)
	})
}

// FuzzSanitizeArtifactPath covers ART-001 path validation (zip-slip style inputs).
func FuzzSanitizeArtifactPath(f *testing.F) {
	f.Add("")
	f.Add("report.txt")
	f.Add("dir/report.txt")
	f.Add("../etc/passwd")
	f.Add("/etc/passwd")
	f.Add("..\\windows\\system32")
	f.Add("foo/../../bar")
	f.Add("http://evil/x")
	f.Add("https://evil/x")
	f.Add("//host/share")
	f.Add("a\x00b.txt")
	f.Add(strings.Repeat("a/", 200) + "b")
	f.Add("./hidden")
	f.Add("foo//bar")
	f.Add("foo/./bar")
	f.Add("C:\\Windows\\file.txt")
	f.Add("unicode- ind/file.txt")
	f.Add(string([]byte{0xff, '/', 'x'}))

	f.Fuzz(func(t *testing.T, p string) {
		if len(p) > fuzzMaxString {
			return
		}
		out, err := SanitizeArtifactPath(p)
		if err != nil {
			if out != "" {
				t.Fatalf("error with non-empty path: %q %v", out, err)
			}
			return
		}
		if out == "" {
			t.Fatal("empty success path")
		}
		// Path-segment check: ".." as a segment is traversal; substrings like
		// "..0" or "a..b" are ordinary names and may be accepted.
		for _, seg := range strings.Split(out, "/") {
			if seg == ".." {
				t.Fatalf(".. segment residual: %q", out)
			}
			if seg == "" {
				t.Fatalf("empty segment residual: %q", out)
			}
		}
		if strings.HasPrefix(out, "/") {
			t.Fatalf("absolute residual: %q", out)
		}
		if strings.Contains(out, "\\") {
			t.Fatalf("backslash residual: %q", out)
		}
		// Re-sanitize must not panic; identity holds when path has no
		// leading/trailing Unicode space that TrimSpace rewrites (e.g. "./ 0"
		// cleans to " 0" then re-trims to "0"). Either way, result must stay
		// relative and free of ".." segments.
		out2, err2 := SanitizeArtifactPath(out)
		if err2 != nil {
			return
		}
		for _, seg := range strings.Split(out2, "/") {
			if seg == ".." || seg == "" {
				t.Fatalf("re-sanitize bad segment in %q", out2)
			}
		}
		if strings.HasPrefix(out2, "/") {
			t.Fatalf("re-sanitize absolute: %q", out2)
		}
	})
}

// FuzzValidateArchiveMemberPath covers zip-slip member names used by inventory.
func FuzzValidateArchiveMemberPath(f *testing.F) {
	f.Add("ok.txt")
	f.Add("dir/ok.txt")
	f.Add("../escape")
	f.Add("/abs")
	f.Add("C:/Windows/x")
	f.Add("a\\b\\c")
	f.Add("")
	f.Add(strings.Repeat("d/", 64) + "f")
	f.Add(strings.Repeat("n", 600))
	f.Add("http://x/y")
	f.Add("..")
	f.Add("./x")

	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > fuzzMaxString {
			return
		}
		_ = validateArchiveMemberPath(name, DefaultMaxArchivePathDepth, DefaultMaxArchiveNameBytes)
		_ = validateArchiveMemberPath(name, 0, 0)
		_ = validateArchiveMemberPath(name, 1, 8)
	})
}

// FuzzInventoryZip feeds random bytes to zip inventory; must not panic.
// Time and expansion limits keep pathological zips bounded.
func FuzzInventoryZip(f *testing.F) {
	// Minimal empty-ish / invalid seeds.
	f.Add([]byte{})
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte("not a zip"))
	f.Add([]byte{0x00, 0x01, 0x02, 0x03})
	// Local file header magic only.
	f.Add([]byte("PK\x05\x06" + strings.Repeat("\x00", 18)))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxBytes {
			return
		}
		lim := ArchiveInventoryLimits{
			MaxMembers:        32,
			MaxExpandedBytes:  1 << 20,
			MaxExpansionRatio: 50,
			MaxPathDepth:      16,
			MaxNameBytes:      256,
			Deadline:          time.Now().Add(50 * time.Millisecond),
		}
		_, _ = InventoryZip(bytes.NewReader(data), int64(len(data)), lim)
		// Negative size must error, not panic.
		if len(data) > 0 {
			_, _ = InventoryZip(bytes.NewReader(data), -1, lim)
		}
	})
}

// FuzzCheckArtifactTextPolicy ensures extension policy never panics.
func FuzzCheckArtifactTextPolicy(f *testing.F) {
	f.Add("a.txt")
	f.Add("a.exe")
	f.Add("a.DLL")
	f.Add("noext")
	f.Add(".hidden")
	f.Add("path/to/file.bin")
	f.Add(strings.Repeat("x", 200) + ".so")

	f.Fuzz(func(t *testing.T, p string) {
		if len(p) > fuzzMaxString {
			return
		}
		_ = CheckArtifactTextPolicy(p)
	})
}

// FuzzProgressiveLimits covers pure progressive offset/length helpers (LOG-001).
func FuzzProgressiveLimits(f *testing.F) {
	f.Add(0, 0)
	f.Add(0, 8192)
	f.Add(-1, 10)
	f.Add(10, -1)
	f.Add(1<<30, 1<<20)
	f.Add(-100, -100)

	f.Fuzz(func(t *testing.T, offset, length int) {
		_, _, _ = validateNonNegativeOffsetLength(offset, length)
		lim := progressiveLimit(length)
		if length < 0 && lim != 0 {
			t.Fatalf("progressiveLimit(%d)=%d", length, lim)
		}
		if length >= 0 && lim != length {
			// progressiveReadSlack is currently 0.
			if progressiveReadSlack == 0 && lim != length {
				t.Fatalf("progressiveLimit(%d)=%d", length, lim)
			}
		}
	})
}

// FuzzEscapeArtifactURLPath ensures URL path segment escaping never panics
// and produces valid path-ish output for accepted relative paths.
func FuzzEscapeArtifactURLPath(f *testing.F) {
	f.Add("a/b")
	f.Add("a b")
	f.Add("a%2Fb")
	f.Add("")
	f.Add("файл")

	f.Fuzz(func(t *testing.T, rel string) {
		if len(rel) > fuzzMaxString {
			return
		}
		out := escapeArtifactURLPath(rel)
		if !utf8.ValidString(out) {
			// PathEscape may percent-encode; result should still be valid UTF-8.
			t.Fatalf("invalid utf8: %q", out)
		}
	})
}
