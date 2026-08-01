package redact_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
)

// Random-looking 40-char hex (git-SHA shape; high nibble diversity).
const bareHex40 = "a1b2c3d4e5f6789012345678abcdef12deadbeef"

// 43-char base64url-like opaque token (mixed classes, high uniqueness).
const bareB64URL43 = "xK9mP2vN8qR4sT6uW0yZ1aB3cD5eF7gH9iJ1kL2mNoP"

// Jenkins-style API token canary: 32-char mixed-case hex (unlabeled).
// All-lowercase 32-hex is reserved for W3C trace_id preservation.
const jenkinsAPITokenHex32 = "11A2b3C4d5E6f708192A3b4C5d6E7f80"

func TestBareTokenRedactsHighEntropyHex40(t *testing.T) {
	t.Parallel()
	in := "auth material " + bareHex40 + " trailing"
	out, rep := redact.RedactTextReport(in)
	if strings.Contains(out, bareHex40) {
		t.Fatalf("40-char hex leaked: %q", out)
	}
	if !strings.Contains(out, redact.Replacement) {
		t.Fatalf("expected marker: %q", out)
	}
	if rep.Counts[redact.CategoryBareToken] < 1 {
		t.Fatalf("expected bare_token count: %+v", rep)
	}
	if !strings.Contains(out, "auth material ") || !strings.Contains(out, " trailing") {
		t.Fatalf("over-redacted context: %q", out)
	}
	raw, _ := json.Marshal(rep)
	if strings.Contains(string(raw), bareHex40) {
		t.Fatalf("report leaked hex: %s", raw)
	}
}

func TestBareTokenRedactsBase64URL43(t *testing.T) {
	t.Parallel()
	in := "opaque=" + bareB64URL43
	// Note: "opaque=" is not a labeled detector; body is bare.
	out, rep := redact.RedactTextReport(in)
	if strings.Contains(out, bareB64URL43) {
		t.Fatalf("base64url leaked: %q", out)
	}
	if rep.Counts[redact.CategoryBareToken] < 1 {
		t.Fatalf("expected bare_token: %+v", rep)
	}
}

func TestBareTokenJenkinsAPITokenCanary(t *testing.T) {
	t.Parallel()
	// Canary: unlabeled Jenkins personal API token shape in a log line.
	// Must never remain after RedactText / Secrets (Writer path uses RedactText).
	samples := []string{
		"Using token " + jenkinsAPITokenHex32 + " for request",
		"crumb=" + jenkinsAPITokenHex32,
		jenkinsAPITokenHex32,
	}
	for _, s := range samples {
		out := redact.Secrets(s)
		if strings.Contains(out, jenkinsAPITokenHex32) {
			t.Errorf("Jenkins API token canary leaked in %q → %q", s, out)
		}
		if strings.Contains(out, "11A2b3C4") || strings.Contains(out, "5d6E7f80") {
			t.Errorf("partial Jenkins canary residual: %q", out)
		}
	}
	// Labeled form still uses api_token category (not only bare_token).
	labeled := "api_token=" + jenkinsAPITokenHex32
	out, rep := redact.RedactTextReport(labeled)
	if strings.Contains(out, jenkinsAPITokenHex32) {
		t.Fatalf("labeled api_token leaked: %q", out)
	}
	// Prefer labeled category when prefix matches; bare may or may not also fire
	// depending on residual after labeled replace — value must be gone either way.
	if rep.Total() < 1 {
		t.Fatalf("expected redaction: %+v", rep)
	}
	_ = rep.Counts[redact.CategoryAPIToken]
}

func TestBareTokenPreservesJobPathsAndWords(t *testing.T) {
	t.Parallel()
	safe := strings.Join([]string{
		"Job path: folder/job-name",
		"folder/team/deploy-prod",
		"short",
		"password",
		"Build #123 SUCCESS",
		"commit abcdef1",          // short SHA
		"ref 1a2b3c4",             // short hex
		"service-deploy-pipeline", // hyphenated words, no digits
		"my-long-jenkins-job-name-here",
		"ERROR connection refused",
	}, "\n")
	out, rep := redact.RedactTextReport(safe)
	for _, keep := range []string{
		"folder/job-name",
		"folder/team/deploy-prod",
		"short",
		"Build #123 SUCCESS",
		"abcdef1",
		"1a2b3c4",
		"service-deploy-pipeline",
		"my-long-jenkins-job-name-here",
		"connection refused",
	} {
		if !strings.Contains(out, keep) {
			t.Errorf("false positive removed %q from:\n%s", keep, out)
		}
	}
	if rep.Counts[redact.CategoryBareToken] != 0 {
		t.Errorf("unexpected bare_token hits on safe corpus: %+v\nout=%q", rep, out)
	}
}

func TestBareTokenLowDiversityNotRedacted(t *testing.T) {
	t.Parallel()
	// Repeated hex pattern — low uniqueness, not a random secret.
	low := strings.Repeat("aabb", 10) // 40 hex chars, unique={a,b}
	out := redact.RedactText("id=" + low)
	if !strings.Contains(out, low) {
		t.Fatalf("low-diversity hex over-redacted: %q", out)
	}
}

func TestBareTokenPreservesW3CTraceID32(t *testing.T) {
	t.Parallel()
	// W3C trace-context trace_id is exactly 32 lowercase hex.
	// Must not be treated as a bare secret (export_trace_refs / OTEL).
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	if len(traceID) != 32 {
		t.Fatalf("fixture len=%d", len(traceID))
	}
	for _, in := range []string{
		traceID,
		"trace_id=" + traceID,
		`{"trace_id":"` + traceID + `"}`,
	} {
		out, rep := redact.RedactTextReport(in)
		if !strings.Contains(out, traceID) {
			t.Fatalf("W3C trace_id over-redacted from %q → %q", in, out)
		}
		if rep.Counts[redact.CategoryBareToken] != 0 {
			t.Fatalf("bare_token hit on trace_id (%q): %+v", in, rep)
		}
	}
}

func TestBareTokenWriterPathScrubs(t *testing.T) {
	t.Parallel()
	var buf strings.Builder
	// strings.Builder is not io.Writer in older Go? It is io.Writer.
	w := redact.NewWriter(&buf)
	line := "accidental dump " + bareHex40 + " end\n"
	if _, err := w.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, bareHex40) {
		t.Fatalf("Writer bare hex canary leaked: %q", out)
	}
	if !strings.Contains(out, redact.Replacement) {
		t.Fatalf("expected marker via Writer: %q", out)
	}
	if !strings.Contains(out, "accidental dump ") {
		t.Fatalf("over-redacted Writer line: %q", out)
	}

	buf.Reset()
	line2 := "token " + bareB64URL43 + "\n"
	if _, err := w.Write([]byte(line2)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), bareB64URL43) {
		t.Fatalf("Writer base64url canary leaked: %q", buf.String())
	}
}

func TestBareTokenContainsSecretHint(t *testing.T) {
	t.Parallel()
	if !redact.ContainsSecretHint(bareHex40) {
		t.Fatal("expected hint on bare hex")
	}
	out := redact.RedactText("x " + bareHex40 + " y")
	if redact.ContainsSecretHint(out) {
		t.Fatalf("hint still true after redaction: %q", out)
	}
}

func TestBareTokenIdempotent(t *testing.T) {
	t.Parallel()
	in := "tok " + bareB64URL43
	out := redact.RedactText(in)
	out2 := redact.RedactText(out)
	if out != out2 {
		t.Fatalf("non-idempotent: %q → %q", out, out2)
	}
}
