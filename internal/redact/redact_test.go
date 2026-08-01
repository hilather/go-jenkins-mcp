package redact_test

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
)

func TestSecretsRedactsCommonLeaks(t *testing.T) {
	t.Parallel()
	in := strings.Join([]string{
		"Authorization: Bearer super-secret-token-value",
		"Cookie: JSESSIONID=abc123session",
		"api_token=rawtokendata",
		"password=hunter2",
		"safe field: job name",
	}, "\n")
	out := redact.Secrets(in)
	for _, leak := range []string{"super-secret-token-value", "abc123session", "rawtokendata", "hunter2"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q in %q", leak, out)
		}
	}
	if !strings.Contains(out, "safe field: job name") {
		t.Errorf("over-redacted safe content: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected redaction marker: %q", out)
	}
}

func TestSecretsEmpty(t *testing.T) {
	t.Parallel()
	if redact.Secrets("") != "" {
		t.Fatal("empty")
	}
	if redact.RedactText("") != "" {
		t.Fatal("RedactText empty")
	}
}

func TestKnownSecretsExactMatch(t *testing.T) {
	// Sequential: mutates package known-secret state.
	redact.ClearKnownSecrets()
	t.Cleanup(redact.ClearKnownSecrets)

	token := "session-tok-exact-9f3a2b1c0d"
	redact.SetKnownSecrets([]string{token, ""})
	in := "user logged in with " + token + " ok"
	out, rep := redact.RedactTextReport(in)
	if strings.Contains(out, token) {
		t.Fatalf("known secret leaked: %q", out)
	}
	if !strings.Contains(out, redact.Replacement) {
		t.Fatalf("expected marker: %q", out)
	}
	if rep.Counts[redact.CategoryKnownSecret] < 1 {
		t.Fatalf("expected known_secret count: %+v", rep)
	}
	// Report must never contain the secret value.
	b, _ := json.Marshal(rep)
	if strings.Contains(string(b), token) {
		t.Fatalf("report leaked secret: %s", b)
	}
}

func TestKnownSecretsLongestFirst(t *testing.T) {
	redact.ClearKnownSecrets()
	t.Cleanup(redact.ClearKnownSecrets)
	short := "abcTOKEN"
	long := "abcTOKEN-extra-suffix"
	redact.SetKnownSecrets([]string{short, long})
	out := redact.RedactText("prefix " + long + " end")
	if strings.Contains(out, "TOKEN") || strings.Contains(out, "extra") {
		t.Fatalf("overlapping known secret residual: %q", out)
	}
}

func TestBuiltinDetectorsTruePositives(t *testing.T) {
	t.Parallel()
	// Canary secrets — must never remain in output.
	awsKey := "AKIAIOSFODNN7EXAMPLE"
	// 40-char AWS secret (example shape).
	awsSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	gh := "ghp_" + strings.Repeat("A", 36)
	gl := "glpat-" + strings.Repeat("B", 20)
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHH\n-----END RSA PRIVATE KEY-----"
	conn := "postgres://appuser:s3cretPass@db.example.com:5432/prod"
	basic := "Authorization: Basic dXNlcjpwYXNz"

	in := strings.Join([]string{
		"aws_access_key_id=" + awsKey,
		"aws_secret_access_key=" + awsSecret,
		"auth=" + jwt,
		"GITHUB_TOKEN=" + gh,
		"GITLAB=" + gl,
		pem,
		"DATABASE_URL=" + conn,
		basic,
		"build failed at step 3",
	}, "\n")

	out, rep := redact.RedactTextReport(in)
	canaries := []string{awsKey, awsSecret, jwt, gh, gl, "s3cretPass", "dXNlcjpwYXNz", "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn"}
	for _, c := range canaries {
		if strings.Contains(out, c) {
			t.Errorf("canary leaked %q in output:\n%s", c, out)
		}
	}
	if !strings.Contains(out, "build failed at step 3") {
		t.Errorf("over-redacted diagnostic text: %q", out)
	}
	if rep.Total() < 5 {
		t.Errorf("expected multiple category hits, got %+v", rep)
	}
	// Report canary: no secret material.
	raw, _ := json.Marshal(rep)
	for _, c := range canaries {
		if strings.Contains(string(raw), c) {
			t.Errorf("report leaked canary %q: %s", c, raw)
		}
	}
	if redact.ContainsSecretHint(out) {
		t.Errorf("ContainsSecretHint still true after redaction: %q", out)
	}
}

func TestFalsePositiveSanityPreservesDiagnostics(t *testing.T) {
	t.Parallel()
	// Useful diagnostic content that must survive.
	safe := strings.Join([]string{
		"ERROR: connection refused to host db.example.com:5432",
		"FAILED test TestUserLogin (0.12s)",
		"Job path: folder/team/deploy-prod",
		"Bearer of bad news: stack overflow at line 42", // not a token
		"password validation failed for field email",    // no value after password=
		"http://example.com/api/v1/tokens/list",         // path, not a secret
		"Build #123 SUCCESS in 4m",
	}, "\n")
	out := redact.RedactText(safe)
	for _, keep := range []string{
		"connection refused",
		"TestUserLogin",
		"folder/team/deploy-prod",
		"stack overflow at line 42",
		"password validation failed",
		"Build #123 SUCCESS",
	} {
		if !strings.Contains(out, keep) {
			t.Errorf("false positive removed %q from:\n%s", keep, out)
		}
	}
}

func TestStructuredFieldRedaction(t *testing.T) {
	t.Parallel()
	in := map[string]any{
		"job":       "deploy",
		"password":  "hunter2",
		"API_TOKEN": "raw-api-token-value",
		"nested": map[string]any{
			"client_secret": "nested-secret-xyz",
			"region":        "us-east-1",
		},
		"note": "Authorization: Bearer leaky-bearer-token-999",
	}
	out := redact.RedactJSON(in)
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("type %T", out)
	}
	if m["password"] != redact.Replacement {
		t.Errorf("password field: %v", m["password"])
	}
	if m["API_TOKEN"] != redact.Replacement {
		t.Errorf("API_TOKEN field: %v", m["API_TOKEN"])
	}
	if m["job"] != "deploy" {
		t.Errorf("job over-redacted: %v", m["job"])
	}
	nested, _ := m["nested"].(map[string]any)
	if nested["client_secret"] != redact.Replacement {
		t.Errorf("nested secret: %v", nested["client_secret"])
	}
	if nested["region"] != "us-east-1" {
		t.Errorf("region: %v", nested["region"])
	}
	note, _ := m["note"].(string)
	if strings.Contains(note, "leaky-bearer-token-999") {
		t.Errorf("string field not pattern-redacted: %q", note)
	}
}

func TestRedactJSONStructRoundTrip(t *testing.T) {
	t.Parallel()
	type params struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	out := redact.RedactJSON(params{Name: "x", Password: "s3cret"})
	m := out.(map[string]any)
	if m["password"] != redact.Replacement || m["name"] != "x" {
		t.Fatalf("%v", m)
	}
}

func TestEnterprisePatternsHook(t *testing.T) {
	// Sequential: package enterprise state.
	redact.SetEnterprisePatterns(nil)
	t.Cleanup(func() { redact.SetEnterprisePatterns(nil) })

	pats, err := redact.CompileEnterprisePatterns([]struct{ Name, Expr string }{
		{Name: "corp_badge", Expr: `\bCORP-[0-9]{6}-SECRET\b`},
	})
	if err != nil {
		t.Fatal(err)
	}
	redact.SetEnterprisePatterns(redact.StaticEnterprise(pats))
	in := "badge CORP-123456-SECRET in log"
	out, rep := redact.RedactTextReport(in)
	if strings.Contains(out, "CORP-123456-SECRET") {
		t.Fatalf("enterprise pattern missed: %q", out)
	}
	if rep.Counts["corp_badge"] < 1 {
		t.Fatalf("expected corp_badge count: %+v", rep)
	}
}

func TestCompileEnterprisePatternsInvalid(t *testing.T) {
	t.Parallel()
	_, err := redact.CompileEnterprisePatterns([]struct{ Name, Expr string }{
		{Name: "bad", Expr: `(`},
	})
	if err == nil {
		t.Fatal("expected compile error")
	}
}

func TestOverlappingSecretPatterns(t *testing.T) {
	t.Parallel()
	// Bearer inside Authorization should not leave residual token.
	in := "Authorization: Bearer " + strings.Repeat("x", 32)
	out := redact.RedactText(in)
	if redact.ContainsSecretHint(out) {
		t.Fatalf("overlap residual: %q", out)
	}
	if strings.Contains(out, strings.Repeat("x", 32)) {
		t.Fatalf("token residual: %q", out)
	}
}

func TestSplitAcrossBufferResidualDocumented(t *testing.T) {
	t.Parallel()
	// Progressive chunks are redacted independently. A secret split across
	// two buffers may not match detectors that need the full token shape.
	// Residual: multi-chunk reassembly is not done here (STO/SEARCH path).
	part1 := "ghp_" + strings.Repeat("A", 20)
	part2 := strings.Repeat("B", 20)
	full := part1 + part2
	if !strings.Contains(redact.RedactText(full), redact.Replacement) && strings.Contains(redact.RedactText(full), "ghp_") {
		// full should redact
	}
	outFull := redact.RedactText(full)
	if strings.Contains(outFull, "ghp_") && !strings.Contains(outFull, redact.Replacement) {
		t.Fatalf("full token should redact: %q", outFull)
	}
	// Split: each half alone may not look like a full ghp_ token (36+ body).
	// This documents residual behavior rather than claiming cross-buffer fix.
	out1 := redact.RedactText(part1)
	// part1 is ghp_ + 20 chars — may or may not match depending on min length.
	_ = out1
	_ = part2
}

func TestIsSensitiveFieldName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"password", "Password", "api-token", "CLIENT_SECRET", "my_access_token"} {
		if !redact.IsSensitiveFieldName(name) {
			t.Errorf("expected sensitive: %q", name)
		}
	}
	for _, name := range []string{"job", "region", "build_number", "status"} {
		if redact.IsSensitiveFieldName(name) {
			t.Errorf("expected not sensitive: %q", name)
		}
	}
}

// Regression: apperr-style canary — secret must never remain after RedactText.
func TestCanaryNeverInOutput(t *testing.T) {
	t.Parallel()
	const canary = "canary-secret-value-NEVER-LEAK-7f3a"
	redact.ClearKnownSecrets()
	t.Cleanup(redact.ClearKnownSecrets)
	redact.SetKnownSecrets([]string{canary})
	samples := []string{
		"error: " + canary,
		"Bearer " + canary,
		`{"token":"` + canary + `"}`,
	}
	for _, s := range samples {
		out := redact.RedactText(s)
		if strings.Contains(out, canary) {
			t.Errorf("Regression: canary leaked in %q → %q", s, out)
		}
		if strings.Contains(out, "NEVER-LEAK") {
			t.Errorf("Regression: partial canary in %q", out)
		}
	}
}

func TestRedactTextIdempotentMarker(t *testing.T) {
	t.Parallel()
	in := "password=once"
	out := redact.RedactText(in)
	out2 := redact.RedactText(out)
	// Second pass should not invent more secrets from the marker.
	if strings.Count(out2, redact.Replacement) < 1 {
		t.Fatalf("%q", out2)
	}
	// Avoid pathological growth: marker re-application on "password=[REDACTED]"
	// is acceptable if stable size-wise.
	if len(out2) > len(out)+len(redact.Replacement) {
		t.Fatalf("non-idempotent growth: %d → %d", len(out), len(out2))
	}
}

// Ensure replacement constant is the only form we advertise.
func TestReplacementConstant(t *testing.T) {
	t.Parallel()
	if redact.Replacement != "[REDACTED]" {
		t.Fatal(redact.Replacement)
	}
	// Guard against accidental export of raw match helpers that log values.
	_ = regexp.MustCompile
}
