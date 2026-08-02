package jenkins

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
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

// HOST-004: page_token minted for Alice must fail closed when Bob continues.
func TestPageToken_SubjectIsolation_AliceTokenRejectedForBob(t *testing.T) {
	t.Parallel()
	fp := FilterFingerprint("folder", "name", "view")
	aliceKey := "tenant-a|alice-sub|corp"
	bobKey := "tenant-a|bob-sub|corp"

	// Alice mints a continuation under her subject binding.
	tok := EncodePageTokenWithSubject(50, 25, fp, aliceKey)
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
	// Opaque: raw subject key must not appear in the token.
	if strings.Contains(tok, "alice-sub") || strings.Contains(tok, aliceKey) {
		t.Fatalf("token leaks subject material: %q", tok)
	}

	// Alice can continue with the same subjectKey.
	off, lim, err := ResolveListPaginationWithSubject(tok, 0, 0, 50, 200, fp, aliceKey)
	if err != nil {
		t.Fatalf("alice continue: %v", err)
	}
	if off != 50 || lim != 25 {
		t.Fatalf("alice resolve offset=%d limit=%d", off, lim)
	}

	// Bob must not continue Alice's token (filter fingerprint mismatch).
	_, _, err = ResolveListPaginationWithSubject(tok, 0, 0, 50, 200, fp, bobKey)
	if err == nil {
		t.Fatal("expected bob to be rejected for alice page_token")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s want invalid_argument", apperr.CodeOf(err))
	}
	if strings.Contains(err.Error(), aliceKey) || strings.Contains(err.Error(), bobKey) {
		t.Fatalf("error must not embed subject keys: %v", err)
	}

	// Unbound (stdio) resolve of a subject-bound token also fails closed.
	_, _, err = ResolveListPagination(tok, 0, 0, 50, 200, fp)
	if err == nil {
		t.Fatal("unbound resolve of subject-bound token must fail")
	}
}

func TestBindSubjectToPageFilter_EmptyLeavesUnchanged(t *testing.T) {
	t.Parallel()
	base := FilterFingerprint("x")
	if BindSubjectToPageFilter(base, "") != base {
		t.Fatal("empty subject must leave fingerprint unchanged")
	}
	if BindSubjectToPageFilter(base, "   ") != base {
		t.Fatal("whitespace subject must leave fingerprint unchanged")
	}
	bound := BindSubjectToPageFilter(base, "tenant|user|corp")
	if bound == base {
		t.Fatal("non-empty subject must change fingerprint")
	}
	// Stable for same subject.
	if BindSubjectToPageFilter(base, "tenant|user|corp") != bound {
		t.Fatal("same subject must be stable")
	}
}

// HOST-004: NextPageTokenIfMoreWithSubject round-trips under the same subject only.
func TestNextPageTokenIfMoreWithSubject_RoundTrip(t *testing.T) {
	t.Parallel()
	fp := FilterFingerprint("jobs")
	subj := "t1|user-1|corp"
	next := NextPageTokenIfMoreWithSubject(0, 10, 10, 25, fp, subj)
	if next == "" {
		t.Fatal("expected next token")
	}
	off, lim, err := ResolveListPaginationWithSubject(next, 0, 0, 50, 200, fp, subj)
	if err != nil {
		t.Fatal(err)
	}
	if off != 10 || lim != 10 {
		t.Fatalf("offset=%d limit=%d", off, lim)
	}
	// Different tenant same subject label must not share tokens.
	otherTenant := "t2|user-1|corp"
	_, _, err = ResolveListPaginationWithSubject(next, 0, 0, 50, 200, fp, otherTenant)
	if err == nil {
		t.Fatal("cross-tenant page_token continue must fail closed")
	}
}
