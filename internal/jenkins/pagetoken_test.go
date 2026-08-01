package jenkins

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

func TestPageToken_RoundTrip(t *testing.T) {
	fp := FilterFingerprint("folder", "name", "view")
	tok := EncodePageToken(50, 25, fp)
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
	// Opaque: no cleartext filter strings.
	if strings.Contains(tok, "folder") || strings.Contains(tok, "name") {
		t.Fatalf("token leaks filter material: %q", tok)
	}
	got, err := DecodePageToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Offset != 50 || got.Limit != 25 {
		t.Fatalf("got offset=%d limit=%d", got.Offset, got.Limit)
	}
	if got.FilterHash != fp {
		t.Fatalf("fingerprint mismatch")
	}
	if got.Version != pageTokenVersion {
		t.Fatalf("version=%d", got.Version)
	}
}

// Wave 40: optional extraParts change the fingerprint (policy-bound list_jobs tokens).
func TestListJobsFilterFingerprint_ExtraParts(t *testing.T) {
	base := ListJobsFilterFingerprint("", "", "", DefaultListJobsDepth, false)
	withPolicy := ListJobsFilterFingerprint("", "", "", DefaultListJobsDepth, false, "deny_job_prefixes", "secret-folder")
	if base == withPolicy {
		t.Fatal("extraParts must change fingerprint")
	}
	// Same extraParts → same fingerprint; order-stable material is caller's job.
	again := ListJobsFilterFingerprint("", "", "", DefaultListJobsDepth, false, "deny_job_prefixes", "secret-folder")
	if withPolicy != again {
		t.Fatal("identical extraParts must match")
	}
	// Token must not embed pattern cleartext.
	tok := EncodePageToken(0, 10, withPolicy)
	if strings.Contains(tok, "secret-folder") || strings.Contains(tok, "deny_job") {
		t.Fatalf("token leaks policy material: %q", tok)
	}
}

func TestPageToken_InvalidRejects(t *testing.T) {
	cases := []string{
		"not-valid-base64!!!",
		"AAAA",
		"YWJjZGVmZ2hpams", // short valid base64, wrong length/magic
		// Wrong magic, correct length payload.
		base64.RawURLEncoding.EncodeToString(append([]byte("XXXX"), make([]byte, pageTokenPayloadLen-4)...)),
	}
	for _, c := range cases {
		_, err := DecodePageToken(c)
		if err == nil {
			t.Fatalf("expected error for %q", c)
		}
		if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("code=%s want invalid_argument for %q", apperr.CodeOf(err), c)
		}
	}
	// Empty is OK (no token).
	got, err := DecodePageToken("")
	if err != nil || got.Offset != 0 {
		t.Fatalf("empty token: got=%+v err=%v", got, err)
	}
}

func TestResolveListPagination_TokenWinsAndHardCap(t *testing.T) {
	fp := FilterFingerprint("x")
	tok := EncodePageToken(40, 999, fp) // token limit above hard max
	off, lim, err := ResolveListPagination(tok, 0, 10, 50, 200, fp)
	if err != nil {
		t.Fatal(err)
	}
	if off != 40 {
		t.Fatalf("offset=%d want 40 (token wins)", off)
	}
	if lim != 200 {
		t.Fatalf("limit=%d want 200 hard cap", lim)
	}
}

func TestResolveListPagination_FilterMismatch(t *testing.T) {
	tok := EncodePageToken(10, 20, FilterFingerprint("a"))
	_, _, err := ResolveListPagination(tok, 0, 0, 50, 200, FilterFingerprint("b"))
	if err == nil {
		t.Fatal("expected filter mismatch")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
}

func TestResolveListPagination_NoTokenUsesOffsetLimit(t *testing.T) {
	fp := FilterFingerprint()
	off, lim, err := ResolveListPagination("", 7, 3, 50, 200, fp)
	if err != nil {
		t.Fatal(err)
	}
	if off != 7 || lim != 3 {
		t.Fatalf("offset=%d limit=%d", off, lim)
	}
	// Defaults when limit omitted.
	_, lim, err = ResolveListPagination("", 0, 0, 50, 200, fp)
	if err != nil || lim != 50 {
		t.Fatalf("default limit: lim=%d err=%v", lim, err)
	}
}

func TestNextPageTokenIfMore(t *testing.T) {
	fp := FilterFingerprint("jobs")
	if NextPageTokenIfMore(0, 10, 10, 10, fp) != "" {
		t.Fatal("complete page should not emit token")
	}
	next := NextPageTokenIfMore(0, 10, 10, 25, fp)
	if next == "" {
		t.Fatal("expected next token")
	}
	tok, err := DecodePageToken(next)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Offset != 10 || tok.Limit != 10 {
		t.Fatalf("next token offset=%d limit=%d", tok.Offset, tok.Limit)
	}
}
