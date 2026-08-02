package auth_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/auth"
)

func TestPKCE_S256RoundTrip(t *testing.T) {
	t.Parallel()
	v, err := auth.GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateCodeVerifier(v); err != nil {
		t.Fatal(err)
	}
	ch, err := auth.CodeChallengeS256(v)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(v))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if ch != want {
		t.Fatalf("challenge: got %q want %q", ch, want)
	}
	// RFC 7636 example shape: no padding.
	if len(ch) == 0 || ch[len(ch)-1] == '=' {
		t.Fatalf("challenge must be unpadded base64url: %q", ch)
	}
}

func TestPKCE_ValidateRejects(t *testing.T) {
	t.Parallel()
	if err := auth.ValidateCodeVerifier("short"); err == nil {
		t.Fatal("short")
	}
	if err := auth.ValidateCodeVerifier("has space and is long enough to pass length check!!!"); err == nil {
		t.Fatal("space")
	}
	if _, err := auth.CodeChallengeS256("nope"); err == nil {
		t.Fatal("challenge on bad verifier")
	}
	if _, err := auth.GenerateCodeVerifierN(1); err == nil {
		t.Fatal("tiny entropy")
	}
}

// Regression: known S256 vector (verifier is 43 unreserved chars).
func TestPKCE_S256KnownVector(t *testing.T) {
	t.Parallel()
	// 43-char verifier from RFC 7636 appendix B style alphabet.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	if err := auth.ValidateCodeVerifier(verifier); err != nil {
		t.Fatal(err)
	}
	ch, err := auth.CodeChallengeS256(verifier)
	if err != nil {
		t.Fatal(err)
	}
	// Precomputed SHA256 base64url of the verifier above.
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if ch != want {
		t.Fatalf("got %q want %q", ch, want)
	}
	if ch != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		// RFC 7636 Appendix B published challenge for this verifier.
		t.Fatalf("RFC vector mismatch: %q", ch)
	}
}
