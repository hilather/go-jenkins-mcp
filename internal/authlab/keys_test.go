package authlab_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/authlab"
)

func TestGenerateAndMintRoundTrip(t *testing.T) {
	t.Parallel()
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := key.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid != authlab.DefaultKid {
		t.Fatalf("jwks: %+v", jwks)
	}

	now := time.Unix(1_700_000_000, 0)
	tok, err := key.MintAccessToken(authlab.MintParams{
		Issuer:   "http://127.0.0.1:18081",
		Subject:  "alice",
		Audience: authlab.DefaultAudience,
		TTL:      time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("not a compact jwt: %d dots", strings.Count(tok, "."))
	}

	claims, err := authlab.ValidateAccessToken(tok, jwks, authlab.ValidateParams{
		Issuer:   "http://127.0.0.1:18081",
		Audience: authlab.DefaultAudience,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "alice" {
		t.Fatalf("sub: %q", claims.Subject)
	}
}

func TestLoadOrGenerateKey_Persists(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	k1, err := authlab.LoadOrGenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "private.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "public.jwks.json")); err != nil {
		t.Fatal(err)
	}
	k2, err := authlab.LoadOrGenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Same modulus → same key reloaded.
	if k1.Private.N.Cmp(k2.Private.N) != 0 {
		t.Fatal("reloaded key differs")
	}
}

func TestMint_WrongAudienceRejected(t *testing.T) {
	t.Parallel()
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := key.JWKS()
	now := time.Unix(1_700_000_000, 0)
	tok, err := key.MintAccessToken(authlab.MintParams{
		Issuer:   "http://127.0.0.1:18081",
		Subject:  "bob",
		Audience: "https://graph.microsoft.com",
		TTL:      time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = authlab.ValidateAccessToken(tok, jwks, authlab.ValidateParams{
		Issuer:   "http://127.0.0.1:18081",
		Audience: authlab.DefaultAudience,
		Now:      func() time.Time { return now },
	})
	if err == nil {
		t.Fatal("expected audience mismatch")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Fatalf("err: %v", err)
	}
	// Canary: raw token never in error.
	if strings.Contains(err.Error(), tok) {
		t.Fatal("token leaked in error")
	}
}

func TestMint_ExpiredRejected(t *testing.T) {
	t.Parallel()
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := key.JWKS()
	now := time.Unix(1_700_000_000, 0)
	tok, err := key.MintAccessToken(authlab.MintParams{
		Issuer:    "http://127.0.0.1:18081",
		Subject:   "bob",
		Audience:  authlab.DefaultAudience,
		ExpOffset: -time.Hour,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = authlab.ValidateAccessToken(tok, jwks, authlab.ValidateParams{
		Issuer:   "http://127.0.0.1:18081",
		Audience: authlab.DefaultAudience,
		Now:      func() time.Time { return now },
	})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestMint_WrongIssuerRejected(t *testing.T) {
	t.Parallel()
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := key.JWKS()
	now := time.Unix(1_700_000_000, 0)
	tok, err := key.MintAccessToken(authlab.MintParams{
		Issuer:   "https://evil.example",
		Subject:  "bob",
		Audience: authlab.DefaultAudience,
		TTL:      time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = authlab.ValidateAccessToken(tok, jwks, authlab.ValidateParams{
		Issuer:   "http://127.0.0.1:18081",
		Audience: authlab.DefaultAudience,
		Now:      func() time.Time { return now },
	})
	if err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("expected issuer mismatch, got %v", err)
	}
}

func TestExtractBearer(t *testing.T) {
	t.Parallel()
	if got := authlab.ExtractBearer("Bearer abc.def.ghi"); got != "abc.def.ghi" {
		t.Fatalf("got %q", got)
	}
	if got := authlab.ExtractBearer("bearer tok"); got != "tok" {
		t.Fatalf("case: %q", got)
	}
	if authlab.ExtractBearer("Basic dXNlcjpwYXNz") != "" {
		t.Fatal("basic should not extract")
	}
	if !authlab.HasBearerScheme("Bearer ") {
		t.Fatal("empty bearer still has scheme")
	}
	if authlab.HasBearerScheme("Basic x") {
		t.Fatal("basic is not bearer")
	}
}
