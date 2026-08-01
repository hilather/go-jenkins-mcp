package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

func TestInvalidArgStableCode(t *testing.T) {
	t.Parallel()
	err := invalidArg("missing required argument: name")
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%q", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "missing required argument") {
		t.Fatalf("msg=%q", err.Error())
	}
}

func TestMapToolErrRedactsAndClassifies(t *testing.T) {
	t.Parallel()
	// Regression: tool error path must not leak Authorization headers.
	raw := errors.New("GET failed: Authorization: Bearer super-secret-token-value status 401")
	mapped := mapToolErr(raw)
	if strings.Contains(mapped.Error(), "super-secret-token-value") {
		t.Fatalf("leaked token: %q", mapped.Error())
	}
	if apperr.CodeOf(mapped) != apperr.CodeAuthentication {
		t.Fatalf("want authentication, got %q (%v)", apperr.CodeOf(mapped), mapped)
	}

	if apperr.CodeOf(mapToolErr(context.Canceled)) != apperr.CodeCancelled {
		t.Fatal("cancelled")
	}
	if mapToolErr(nil) != nil {
		t.Fatal("nil")
	}
}

// fakeConsent implements progressiveConsent for mapToolErr without importing gateway.
type fakeConsent struct {
	url, session string
}

func (f fakeConsent) Error() string { return "consent required" }
func (f fakeConsent) ConsentAuthorizationURL() string {
	return f.url
}
func (f fakeConsent) ConsentSessionID() string { return f.session }

// Regression: Mode C ConsentRequired surfaces auth URL + session_id only on tool path.
func TestMapToolErr_ConsentRequiredMetadataOnly(t *testing.T) {
	t.Parallel()
	const canary = "access_token_must_never_appear_xyz789"
	const authURL = "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?state=abc"
	const session = "consent-session-id-42"

	// Direct progressiveConsent error.
	mapped := mapToolErr(fakeConsent{url: authURL, session: session})
	if apperr.CodeOf(mapped) != apperr.CodeAuthentication {
		t.Fatalf("code=%q want authentication", apperr.CodeOf(mapped))
	}
	msg := mapped.Error()
	if !strings.Contains(msg, authURL) {
		t.Fatalf("want authorization_url in model message: %q", msg)
	}
	if !strings.Contains(msg, session) {
		t.Fatalf("want session_id in model message: %q", msg)
	}
	if !strings.Contains(msg, "authorization_url=") || !strings.Contains(msg, "session_id=") {
		t.Fatalf("want progressive consent fields: %q", msg)
	}
	if strings.Contains(msg, canary) {
		t.Fatalf("token canary leaked: %q", msg)
	}
	// Progressive format embedded in apperr (code prefix + message).
	wantBody := progressiveConsentMessage(authURL, session)
	if !strings.Contains(msg, wantBody) {
		t.Fatalf("msg=%q want body %q", msg, wantBody)
	}

	// Wrapped under fmt.Errorf %w (jenkins applyAuth path).
	wrapped := fmt.Errorf("jenkins applyAuth: %w", fakeConsent{url: authURL, session: session})
	mapped2 := mapToolErr(wrapped)
	if apperr.CodeOf(mapped2) != apperr.CodeAuthentication {
		t.Fatalf("wrapped code=%q", apperr.CodeOf(mapped2))
	}
	if !strings.Contains(mapped2.Error(), authURL) || !strings.Contains(mapped2.Error(), session) {
		t.Fatalf("wrapped lost consent metadata: %q", mapped2.Error())
	}

	// Multi-level wrap (AuthProvider → applyAuth → tool).
	deep := fmt.Errorf("tool: %w", fmt.Errorf("jenkins: %w", fakeConsent{url: authURL, session: session}))
	mappedDeep := mapToolErr(deep)
	if !strings.Contains(mappedDeep.Error(), wantBody) {
		t.Fatalf("deep wrap lost progressive format: %q", mappedDeep.Error())
	}

	// Incomplete consent → authentication without inventing tokens or URL.
	incomplete := mapToolErr(fakeConsent{url: "", session: ""})
	if apperr.CodeOf(incomplete) != apperr.CodeAuthentication {
		t.Fatalf("incomplete code=%q", apperr.CodeOf(incomplete))
	}
	if strings.Contains(incomplete.Error(), canary) {
		t.Fatal("canary in incomplete path")
	}
	if strings.Contains(incomplete.Error(), "authorization_url=") ||
		strings.Contains(incomplete.Error(), "session_id=") {
		t.Fatalf("incomplete must not invent progressive fields: %q", incomplete.Error())
	}

	// Partial metadata (URL only or session only) → fail closed without half-fields.
	urlOnly := mapToolErr(fakeConsent{url: authURL, session: ""})
	if apperr.CodeOf(urlOnly) != apperr.CodeAuthentication {
		t.Fatalf("url-only code=%q", apperr.CodeOf(urlOnly))
	}
	if strings.Contains(urlOnly.Error(), "authorization_url=") {
		t.Fatalf("url-only must not surface unpaired URL: %q", urlOnly.Error())
	}
	sessOnly := mapToolErr(fakeConsent{url: "", session: session})
	if strings.Contains(sessOnly.Error(), "session_id=") {
		t.Fatalf("session-only must not surface unpaired session: %q", sessOnly.Error())
	}
}

// Regression: progressive consent tool path never embeds secret canaries.
func TestMapToolErr_ConsentRequired_SecretCanaries(t *testing.T) {
	t.Parallel()
	const authURL = "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?client_id=public&state=xyz"
	const session = "opaque-consent-session-99"
	// Canaries that must never appear on the progressive tool surface.
	canaries := []string{
		"access_token_must_never_appear_xyz789",
		"refresh_token=super-secret-refresh",
		"client_secret=super-secret-client",
		"Authorization: Bearer super-secret-token-value",
		"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.canary",
	}
	mapped := mapToolErr(fakeConsent{url: authURL, session: session})
	msg := mapped.Error()
	for _, c := range canaries {
		if strings.Contains(msg, c) {
			t.Fatalf("canary %q leaked in progressive consent message: %q", c, msg)
		}
	}
	// Only progressive keys allowed as structured fields.
	if !strings.Contains(msg, "authorization_url="+authURL) {
		t.Fatalf("want authorization_url=: %q", msg)
	}
	if !strings.Contains(msg, "session_id="+session) {
		t.Fatalf("want session_id=: %q", msg)
	}
	// Must not invent token-shaped keys.
	for _, badKey := range []string{"access_token=", "refresh_token=", "client_secret=", "id_token="} {
		if strings.Contains(strings.ToLower(msg), badKey) {
			t.Fatalf("forbidden key %q in progressive message: %q", badKey, msg)
		}
	}
}
