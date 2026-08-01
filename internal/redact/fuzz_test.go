package redact_test

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
)

// QA-001: additional redaction/sanitize fuzz targets (see also FuzzStripControlSequences).

const fuzzMaxText = 16 << 10 // 16 KiB — regex redaction is CPU-heavy

// FuzzRedactText ensures layered secret redaction never panics and is deterministic.
func FuzzRedactText(f *testing.F) {
	f.Add("")
	f.Add("plain text")
	f.Add("password=supersecret")
	f.Add("Authorization: Bearer abcdef0123456789")
	f.Add("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepart")
	f.Add("AKIAIOSFODNN7EXAMPLE")
	f.Add("ghp_" + strings.Repeat("A", 36))
	f.Add("glpat-" + strings.Repeat("B", 20))
	f.Add("Cookie: JSESSIONID=abc123; path=/")
	f.Add("-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----")
	f.Add("postgres://user:secretpass@host:5432/db")
	f.Add("api_token=xyz\naccess_token=abc")
	f.Add("a1b2c3d4e5f6789012345678abcdef12deadbeef")    // bare 40-hex
	f.Add("xK9mP2vN8qR4sT6uW0yZ1aB3cD5eF7gH9iJ1kL2mNoP") // bare 43-b64url
	f.Add("folder/job-name")
	f.Add(strings.Repeat("password=x ", 100))
	f.Add("\x1b[31mpassword=secret\x1b[0m")
	f.Add(string([]byte{0xff, 0xfe, 'p', 'a', 's', 's'}))
	f.Add("client_secret: value-with-unicode- ind")

	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > fuzzMaxText {
			return
		}
		out1, rep1 := redact.RedactTextReport(s)
		out2, rep2 := redact.RedactTextReport(s)
		if out1 != out2 {
			t.Fatal("non-deterministic RedactText")
		}
		if rep1.Total() != rep2.Total() {
			t.Fatal("non-deterministic report totals")
		}
		// Secrets helper is an alias path.
		if redact.Secrets(s) != out1 {
			t.Fatal("Secrets != RedactText")
		}
		// Report must never contain original secret-like long tokens as keys.
		for cat := range rep1.Counts {
			if strings.Contains(cat, "password=") || strings.Contains(cat, "Bearer ") {
				t.Fatalf("category looks like a value: %q", cat)
			}
		}
	})
}

// FuzzSanitizeForModel covers control-strip + redaction composition.
func FuzzSanitizeForModel(f *testing.F) {
	f.Add("")
	f.Add("ok")
	f.Add("\x1b[31mred\x1b[0m password=x")
	f.Add("\x1b]8;;http://x\x07click\x1b]8;;\x07 Bearer tokentokentoken")
	f.Add("\x00\x01\x1b")
	f.Add("\u202Epassword=secret")
	f.Add(strings.Repeat("\x1b[31m", 200) + "x")

	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > fuzzMaxText {
			return
		}
		out, rep := redact.SanitizeForModelReport(s)
		if redact.SanitizeForModel(s) != out {
			t.Fatal("SanitizeForModel mismatch with Report")
		}
		// No ESC / C1 residual after strip layer (same invariant as StripControlSequences).
		if strings.Contains(out, "\x1b") {
			t.Fatalf("ESC residual: %q", out)
		}
		for r := rune(0x80); r <= 0x9f; r++ {
			if strings.ContainsRune(out, r) {
				t.Fatalf("C1 U+%04X residual", r)
			}
		}
		if !utf8.ValidString(out) {
			t.Fatalf("invalid utf8: %q", out)
		}
		// Deterministic.
		out2, rep2 := redact.SanitizeForModelReport(s)
		if out2 != out || rep2.Total() != rep.Total() {
			t.Fatal("non-deterministic SanitizeForModel")
		}
		// Untrusted wrapper path.
		ex := redact.NewUntrustedExcerpt(s, redact.ContentKindBuildLog)
		if !ex.Untrusted || ex.Text != out {
			t.Fatalf("excerpt mismatch: %+v", ex)
		}
	})
}

// FuzzRedactJSON ensures structured JSON redaction never panics.
func FuzzRedactJSON(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"password":"x","ok":"y"}`))
	f.Add([]byte(`{"nested":{"token":"abc"},"list":[1,"Bearer abcdefghijkl"]}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"password=secret"`))
	f.Add([]byte(`not json`))
	f.Add([]byte{0xff, 0xfe})
	f.Add([]byte(strings.Repeat(`{"a":`, 50) + `1` + strings.Repeat(`}`, 50)))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxText {
			return
		}
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			// Still exercise string path via RedactText on raw.
			_ = redact.RedactText(string(data))
			return
		}
		out1, r1 := redact.RedactJSONReport(v)
		out2, r2 := redact.RedactJSONReport(v)
		if r1.Total() != r2.Total() {
			t.Fatal("non-deterministic RedactJSON report")
		}
		// Round-trip encode should not panic.
		_, _ = json.Marshal(out1)
		_ = out2
	})
}

// FuzzIsSensitiveFieldName covers structured key classification.
func FuzzIsSensitiveFieldName(f *testing.F) {
	f.Add("")
	f.Add("password")
	f.Add("PASSWORD")
	f.Add("my_api_token")
	f.Add("normal_field")
	f.Add("x-Authorization")
	f.Add(strings.Repeat("token", 100))

	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 4096 {
			return
		}
		a := redact.IsSensitiveFieldName(name)
		b := redact.IsSensitiveFieldName(name)
		if a != b {
			t.Fatal("non-deterministic IsSensitiveFieldName")
		}
	})
}
