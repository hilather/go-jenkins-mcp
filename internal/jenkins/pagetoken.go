package jenkins

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Opaque list page tokens (MCP-001 residual / HOST-004 multi-tenant isolation).
//
// Format (v1): base64url(no pad) of a small binary payload:
//
//	magic "JM1\x00" | uint32 offset | uint32 limit | 8-byte filter fingerprint
//
// Tokens are intentionally opaque to models. They are not an authentication
// boundary by themselves: opacity + version + filter fingerprint only. Never
// put secrets or credentials into tokens.
//
// Multi-tenant (HOST-004): bind the caller's subjectKey into the filter
// fingerprint via BindSubjectToPageFilter / *WithSubject helpers so user B
// cannot continue user A's page_token. Empty subjectKey leaves the fingerprint
// unchanged (stdio single-user pilot). Gateway mode should always pass a
// non-empty subjectKey (gateway.SubjectKey = tenant|subject|profile).
//
// When both page_token and offset/limit are provided, page_token wins.
// Invalid or tampered non-empty tokens fail closed as invalid_argument.
// A token cannot raise limit past the tool's hard max (clamped on resolve).

const (
	pageTokenMagic      = "JM1\x00"
	pageTokenVersion    = 1
	pageTokenFPBytes    = 8
	pageTokenPayloadLen = 4 + 4 + 4 + pageTokenFPBytes // magic(4) + offset + limit + fp
)

// PageToken is the decoded opaque list continuation cursor.
type PageToken struct {
	Version    int
	Offset     int
	Limit      int
	FilterHash [pageTokenFPBytes]byte
}

// FilterFingerprint returns a stable 8-byte fingerprint of filter key material.
// Callers should pass only non-secret filter fields (folder, name, result, …).
func FilterFingerprint(parts ...string) [pageTokenFPBytes]byte {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(p))
	}
	sum := h.Sum(nil)
	var out [pageTokenFPBytes]byte
	copy(out[:], sum[:pageTokenFPBytes])
	return out
}

// EncodePageToken builds an opaque next-page token for (offset, limit, filterFP).
// Returns empty string when offset < 0 (no token).
func EncodePageToken(offset, limit int, filterFP [pageTokenFPBytes]byte) string {
	if offset < 0 {
		return ""
	}
	if limit < 0 {
		limit = 0
	}
	buf := make([]byte, pageTokenPayloadLen)
	copy(buf[0:4], pageTokenMagic)
	binary.BigEndian.PutUint32(buf[4:8], uint32(offset))
	binary.BigEndian.PutUint32(buf[8:12], uint32(limit))
	copy(buf[12:12+pageTokenFPBytes], filterFP[:])
	return base64.RawURLEncoding.EncodeToString(buf)
}

// DecodePageToken parses an opaque page token. Empty token is not an error
// (caller treats empty as "no token"). Non-empty invalid tokens return
// CodeInvalidArgument.
func DecodePageToken(token string) (PageToken, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return PageToken{}, nil
	}
	// Reject obvious secret-looking material (never should appear; defense in depth).
	if len(token) > 512 {
		return PageToken{}, apperr.New(apperr.CodeInvalidArgument, "page_token is invalid or corrupted")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		// Also try standard base64url with padding for client quirks.
		raw, err = base64.URLEncoding.DecodeString(token)
		if err != nil {
			return PageToken{}, apperr.New(apperr.CodeInvalidArgument, "page_token is invalid or corrupted")
		}
	}
	if len(raw) != pageTokenPayloadLen {
		return PageToken{}, apperr.New(apperr.CodeInvalidArgument, "page_token is invalid or corrupted")
	}
	if string(raw[0:4]) != pageTokenMagic {
		return PageToken{}, apperr.New(apperr.CodeInvalidArgument, "page_token is invalid or corrupted")
	}
	off := int(binary.BigEndian.Uint32(raw[4:8]))
	lim := int(binary.BigEndian.Uint32(raw[8:12]))
	var fp [pageTokenFPBytes]byte
	copy(fp[:], raw[12:12+pageTokenFPBytes])
	return PageToken{
		Version:    pageTokenVersion,
		Offset:     off,
		Limit:      lim,
		FilterHash: fp,
	}, nil
}

// ResolveListPagination merges page_token with explicit offset/limit.
//
// Rules:
//   - empty page_token → use offset/limit args (offset < 0 → 0; limit <= 0 → defaultLimit)
//   - non-empty page_token → token wins for offset; token limit used when > 0, else defaultLimit
//   - filter fingerprint must match current request filters
//   - final limit is clamped to [1, maxLimit] (token cannot raise past hard max)
//
// Returns resolved offset, limit, or CodeInvalidArgument on bad/mismatched token.
func ResolveListPagination(pageToken string, offset, limit, defaultLimit, maxLimit int, filterFP [pageTokenFPBytes]byte) (resOffset, resLimit int, err error) {
	if defaultLimit <= 0 {
		defaultLimit = 50
	}
	if maxLimit <= 0 {
		maxLimit = defaultLimit
	}
	if maxLimit < defaultLimit {
		// Keep hard max as the upper bound even if defaults are misconfigured.
		defaultLimit = maxLimit
	}

	pageToken = strings.TrimSpace(pageToken)
	if pageToken != "" {
		tok, derr := DecodePageToken(pageToken)
		if derr != nil {
			return 0, 0, derr
		}
		if tok.FilterHash != filterFP {
			return 0, 0, apperr.New(apperr.CodeInvalidArgument,
				"page_token does not match current filters; re-list from the first page")
		}
		resOffset = tok.Offset
		if resOffset < 0 {
			resOffset = 0
		}
		if tok.Limit > 0 {
			resLimit = tok.Limit
		} else {
			resLimit = defaultLimit
		}
	} else {
		resOffset = offset
		if resOffset < 0 {
			resOffset = 0
		}
		resLimit = limit
		if resLimit <= 0 {
			resLimit = defaultLimit
		}
	}

	if resLimit > maxLimit {
		resLimit = maxLimit
	}
	if resLimit < 1 {
		resLimit = 1
	}
	return resOffset, resLimit, nil
}

// NextPageTokenIfMore returns an opaque token for the next page when more
// items exist after the current page (offset+returned < total). Empty when done.
func NextPageTokenIfMore(offset, limit, returned, total int, filterFP [pageTokenFPBytes]byte) string {
	if returned <= 0 || limit <= 0 {
		return ""
	}
	next := offset + returned
	if next >= total {
		return ""
	}
	return EncodePageToken(next, limit, filterFP)
}

// FormatFilterBool is a stable string for filter fingerprints.
func FormatFilterBool(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// FormatFilterInt is a stable string for filter fingerprints.
func FormatFilterInt(v int) string {
	return fmt.Sprintf("%d", v)
}

// BindSubjectToPageFilter mixes subjectKey into a list filter fingerprint so
// continuation tokens fail closed across subjects (HOST-004).
//
// Empty / whitespace subjectKey leaves base unchanged (stdio single-user pilot).
// Non-empty subjectKey should be a stable non-secret identity key such as
// gateway.SubjectKey(caller) = "tenant|subject|profile" — never tokens or
// credentials. The raw subjectKey is hashed into the fingerprint and never
// appears in the opaque page_token bytes as cleartext.
func BindSubjectToPageFilter(base [pageTokenFPBytes]byte, subjectKey string) [pageTokenFPBytes]byte {
	subjectKey = strings.TrimSpace(subjectKey)
	if subjectKey == "" {
		return base
	}
	h := sha256.New()
	_, _ = h.Write(base[:])
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte("host004-subject"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(subjectKey))
	sum := h.Sum(nil)
	var out [pageTokenFPBytes]byte
	copy(out[:], sum[:pageTokenFPBytes])
	return out
}

// EncodePageTokenWithSubject is EncodePageToken with subject isolation (HOST-004).
// Prefer this (or bind the fingerprint first) in multi-tenant gateway mode.
func EncodePageTokenWithSubject(offset, limit int, filterFP [pageTokenFPBytes]byte, subjectKey string) string {
	return EncodePageToken(offset, limit, BindSubjectToPageFilter(filterFP, subjectKey))
}

// ResolveListPaginationWithSubject is ResolveListPagination with subject-bound
// filter matching (HOST-004). A page_token minted for subject A is rejected
// when resolved under subject B (filter fingerprint mismatch → invalid_argument).
func ResolveListPaginationWithSubject(
	pageToken string,
	offset, limit, defaultLimit, maxLimit int,
	filterFP [pageTokenFPBytes]byte,
	subjectKey string,
) (resOffset, resLimit int, err error) {
	return ResolveListPagination(pageToken, offset, limit, defaultLimit, maxLimit,
		BindSubjectToPageFilter(filterFP, subjectKey))
}

// NextPageTokenIfMoreWithSubject is NextPageTokenIfMore with subject isolation
// (HOST-004). The returned token is only valid under the same subjectKey.
func NextPageTokenIfMoreWithSubject(
	offset, limit, returned, total int,
	filterFP [pageTokenFPBytes]byte,
	subjectKey string,
) string {
	return NextPageTokenIfMore(offset, limit, returned, total,
		BindSubjectToPageFilter(filterFP, subjectKey))
}
