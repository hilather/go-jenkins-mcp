package gateway

import (
	"encoding/base64"
	"testing"
)

// Regression: rejectIDTokenAsAPICredential substring-matched
// "token_use":"id_token" / "typ":"id_token" — valid JSON with other whitespace
// around the colon ("token_use" : "id_token", tabs, newlines) bypassed the
// guard, so an ID token could be stored as a Jenkins API credential (defeating
// the HOST-010 invariant). The payload is now parsed as JSON first.
func TestRejectIDTokenAsAPICredential_WhitespaceVariants(t *testing.T) {
	t.Parallel()
	mkJWT := func(payloadJSON string) string {
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		return hdr + "." + base64.RawURLEncoding.EncodeToString([]byte(payloadJSON)) + ".sig"
	}
	// Compact, spaced, tabbed, and newline variants must all be rejected —
	// the old substring matcher only caught the two compact spellings.
	payloads := []string{
		`{"token_use":"id_token"}`,
		`{"token_use" : "id_token"}`,
		"{\n\t\"token_use\"\t:\n\t\"id_token\"\n}",
		`{"typ":"id_token"}`,
		`{"typ" : "id_token"}`,
	}
	for _, p := range payloads {
		if err := rejectIDTokenAsAPICredential(mkJWT(p)); err == nil {
			t.Errorf("id_token payload %q must be rejected", p)
		}
	}
	// Access tokens and opaque strings still pass.
	if err := rejectIDTokenAsAPICredential(mkJWT(`{"token_use":"access_token"}`)); err != nil {
		t.Fatalf("access_token must pass: %v", err)
	}
	if err := rejectIDTokenAsAPICredential("opaque-lab-token"); err != nil {
		t.Fatalf("opaque token must pass: %v", err)
	}
	if err := rejectIDTokenAsAPICredential(""); err != nil {
		t.Fatalf("empty must pass (handled elsewhere): %v", err)
	}
}
