package redact_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// Regression: the labeled detectors required the key to be immediately
// followed by = or : (modulo whitespace), so serialized JSON — the most
// common serialization format in this codebase — escaped redaction entirely:
// RedactText(`{"password":"hunter2"}`) returned the input unchanged (YAML
// `password: hunter2` was redacted). JSON-quoted labeled forms are now
// covered; the value's closing quote is never part of the match, so redacted
// output stays well-formed.
func TestRedactText_JSONQuotedSecrets(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		in    string
		want  string // must appear after redaction
		never string // must not appear
	}{
		{"password compact", `{"password":"hunter2"}`, `"password":"[REDACTED]"}`, "hunter2"},
		{"token spaced", `{"token": "abc123"}`, `"token": "[REDACTED]"}`, "abc123"},
		{"access_token", `{"access_token":"tok-xyz-123"}`, `"access_token":"[REDACTED]"}`, "tok-xyz-123"},
		{"client_secret", `{"client_secret":"shh"}`, `"client_secret":"[REDACTED]"}`, "shh"},
		{"api_key", `{"api_key":"key-1"}`, `"api_key":"[REDACTED]"}`, "key-1"},
		{"refresh_token", `{"refresh_token":"rt-99"}`, `"refresh_token":"[REDACTED]"}`, "rt-99"},
		{"authorization", `{"authorization":"Bearer abc"}`, `"authorization":"[REDACTED]"}`, "abc"},
		{"nested", `{"outer":{"password":"hunter2"},"ok":1}`, `"password":"[REDACTED]"`, "hunter2"},
		{"single quotes", `{'password':'hunter2'}`, `'password':'[REDACTED]'`, "hunter2"},
	}
	for _, tc := range cases {
		got := redact.RedactText(tc.in)
		if strings.Contains(got, tc.never) {
			t.Errorf("%s: secret survived: %s", tc.name, got)
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: want %q in %q", tc.name, tc.want, got)
		}
	}
	// Non-secret keys untouched.
	if got := redact.RedactText(`{"user":"alice","count":3}`); got != `{"user":"alice","count":3}` {
		t.Fatalf("non-secret JSON changed: %s", got)
	}
	// ContainsSecretHint must flag an unredacted JSON-quoted secret (the
	// fail-closed checker had the same blind spot).
	if !redact.ContainsSecretHint(`{"password":"hunter2"}`) {
		t.Fatal("ContainsSecretHint must flag JSON-quoted labeled secrets")
	}
}
