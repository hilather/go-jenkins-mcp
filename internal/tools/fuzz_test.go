package tools

import (
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
)

// QA-001: MCP-facing tool input validation and log sanitize pure paths.

const fuzzMaxArg = 8 << 10

// FuzzJobFullName exercises tool job_name validation (MCP-002 / SSRF reduction).
func FuzzJobFullName(f *testing.F) {
	f.Add("demo")
	f.Add("folder/job")
	f.Add("")
	f.Add("http://jenkins/job/x")
	f.Add("https://evil.example/job/x")
	f.Add("//evil/job/x")
	f.Add("file:///etc/passwd")
	f.Add("jenkins://host/job")
	f.Add("../escape")
	f.Add("a\x00b")
	f.Add("job\nname")
	f.Add(strings.Repeat("a/", 100) + "b")
	f.Add("unicode- ind/job")
	f.Add(" data:text/plain,hi")

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > fuzzMaxArg {
			return
		}
		got, err := jobFullName("job_name", raw)
		if err != nil {
			if got != "" {
				t.Fatalf("error with non-empty: %q %v", got, err)
			}
			// Error text must not be enormous and must not re-embed nulls as path.
			msg := err.Error()
			if len(msg) > 4<<10 {
				t.Fatalf("error message too large: %d", len(msg))
			}
			return
		}
		if strings.TrimSpace(got) == "" {
			t.Fatal("empty success")
		}
		// Accepted names must not be absolute http(s) URLs.
		lower := strings.ToLower(strings.TrimSpace(got))
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			t.Fatalf("accepted absolute URL: %q", got)
		}
	})
}

// FuzzBuildRefAndLogEvidence covers flattened MCP build/log evidence fields.
func FuzzBuildRefAndLogEvidence(f *testing.F) {
	f.Add("demo", 1, 0, 8192)
	f.Add("folder/job", 42, 100, 50)
	f.Add("", 1, 0, 1)
	f.Add("http://x/job", 1, 0, 1)
	f.Add("demo", 0, 0, 1)
	f.Add("demo", -1, -1, -1)
	f.Add("demo", 1, -5, 10)
	f.Add(strings.Repeat("j", 200), 99, 0, 0)

	f.Fuzz(func(t *testing.T, job string, number, offset, length int) {
		if len(job) > fuzzMaxArg {
			return
		}
		_, _ = buildRef("job_name", job, "build_number", number)
		_, _ = logEvidence("job_name", job, "build_number", number, offset, length, DefaultLogLength)
		_, _ = queueItemRef("queue_id", number, job)
	})
}

// FuzzPrepareBuildLogsForModel ensures log sanitize for model never panics.
func FuzzPrepareBuildLogsForModel(f *testing.F) {
	f.Add("")
	f.Add("plain log line\n")
	f.Add("password=secret\nAuthorization: Bearer abcdef0123456789\n")
	f.Add("\x1b[31merror\x1b[0m\n")
	f.Add(strings.Repeat("line\n", 200))

	f.Fuzz(func(t *testing.T, logs string) {
		if len(logs) > 16<<10 {
			return
		}
		// nil input
		outNil := PrepareBuildLogsForModel(nil)
		if !outNil.Untrusted || outNil.ContentKind != redact.ContentKindBuildLog {
			t.Fatalf("nil logs: %+v", outNil)
		}

		bl := &jenkins.BuildLogs{
			JobName:     "demo",
			BuildNumber: 1,
			Offset:      0,
			Length:      len(logs),
			TotalSize:   len(logs),
			HasMore:     false,
			Logs:        logs,
		}
		out := PrepareBuildLogsForModel(bl)
		if !out.Untrusted {
			t.Fatal("must mark untrusted")
		}
		if strings.Contains(out.Logs, "\x1b") {
			t.Fatal("ESC residual in model logs")
		}
		// Length is model-visible size after sanitize.
		if out.Length != len(out.Logs) {
			t.Fatalf("Length=%d len(Logs)=%d", out.Length, len(out.Logs))
		}
	})
}

// FuzzRedactParamMap covers sensitive Jenkins parameter key redaction.
func FuzzRedactParamMap(f *testing.F) {
	f.Add("password", "secret")
	f.Add("OK", "value")
	f.Add("API_TOKEN", "tok")
	f.Add("", "")
	f.Add("normal", "password=embedded")

	f.Fuzz(func(t *testing.T, k, v string) {
		if len(k) > 1024 || len(v) > fuzzMaxArg {
			return
		}
		m := map[string]string{k: v}
		out := redactParamMap(m)
		if len(out) != 1 {
			t.Fatalf("expected one key, got %d", len(out))
		}
		if redact.IsSensitiveFieldName(k) {
			if out[k] != redact.Replacement {
				t.Fatalf("sensitive key %q → %q", k, out[k])
			}
		}
		// Empty map path.
		_ = redactParamMap(nil)
		_ = redactParamMap(map[string]string{})
	})
}
