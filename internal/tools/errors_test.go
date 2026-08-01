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

	// Wrapped under fmt.Errorf %w (jenkins applyAuth path).
	wrapped := fmt.Errorf("jenkins applyAuth: %w", fakeConsent{url: authURL, session: session})
	mapped2 := mapToolErr(wrapped)
	if apperr.CodeOf(mapped2) != apperr.CodeAuthentication {
		t.Fatalf("wrapped code=%q", apperr.CodeOf(mapped2))
	}
	if !strings.Contains(mapped2.Error(), authURL) || !strings.Contains(mapped2.Error(), session) {
		t.Fatalf("wrapped lost consent metadata: %q", mapped2.Error())
	}

	// Incomplete consent → authentication without inventing tokens.
	incomplete := mapToolErr(fakeConsent{url: "", session: ""})
	if apperr.CodeOf(incomplete) != apperr.CodeAuthentication {
		t.Fatalf("incomplete code=%q", apperr.CodeOf(incomplete))
	}
	if strings.Contains(incomplete.Error(), canary) {
		t.Fatal("canary in incomplete path")
	}
}
