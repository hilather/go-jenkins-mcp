package apperr_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

func TestAllCodesDocumentedAndValid(t *testing.T) {
	t.Parallel()
	// FND-005 contract: closed taxonomy including required backlog codes.
	required := []apperr.Code{
		apperr.CodeAuthentication,
		apperr.CodeAuthorization,
		apperr.CodeNotFound,
		apperr.CodeCapabilityMissing,
		apperr.CodeThrottled,
		apperr.CodeTimeout,
		apperr.CodeCancelled,
		apperr.CodeCorruptCache,
		apperr.CodeQuota,
		apperr.CodePolicyDenial,
		apperr.CodeUpstreamProtocol,
	}
	all := apperr.AllCodes()
	seen := map[apperr.Code]bool{}
	for _, c := range all {
		if !c.Valid() {
			t.Errorf("code %q should be Valid", c)
		}
		if c.DefaultMessage() == "" || c.DefaultMessage() == "error" && c != "" {
			// empty code only returns "error"
		}
		if c.DefaultMessage() == "" {
			t.Errorf("code %q missing default message", c)
		}
		if seen[c] {
			t.Errorf("duplicate code %q", c)
		}
		seen[c] = true
	}
	for _, c := range required {
		if !seen[c] {
			t.Errorf("required code %q missing from AllCodes", c)
		}
		if string(c) != strings.ToLower(string(c)) || strings.Contains(string(c), " ") {
			t.Errorf("code %q must be snake_case", c)
		}
	}
}

func TestErrorModelVisibleRedactsSecrets(t *testing.T) {
	t.Parallel()
	// Regression: model-visible path must never echo tokens/headers/cookies.
	secretish := "Authorization: Bearer super-secret-token-value\nCookie: JSESSIONID=abc\napi_token=rawtokendata"
	err := apperr.Wrap(apperr.CodeAuthentication, secretish, errors.New("transport: "+secretish))
	visible := err.Error()
	for _, leak := range []string{
		"super-secret-token-value",
		"rawtokendata",
		"JSESSIONID=abc",
		"Bearer super-secret",
	} {
		if strings.Contains(visible, leak) {
			t.Errorf("model-visible Error() leaked %q in %q", leak, visible)
		}
	}
	if !strings.Contains(visible, string(apperr.CodeAuthentication)) {
		t.Errorf("expected code in visible message: %q", visible)
	}
	// Internal cause preserved for diagnostic mode.
	if err.Cause() == nil || !strings.Contains(err.Cause().Error(), "super-secret-token-value") {
		// Cause may still hold raw transport text; diagnostic mode must scrub before export.
		// Here we only require the chain to exist.
		if err.Cause() == nil {
			t.Fatal("expected internal cause chain")
		}
	}
	// ModelMessage on plain errors also redacts.
	plain := errors.New("Authorization: Bearer leaked-token-xyz")
	mm := apperr.ModelMessage(plain)
	if strings.Contains(mm, "leaked-token-xyz") {
		t.Errorf("ModelMessage leaked token: %q", mm)
	}
}

func TestCauseNotInErrorString(t *testing.T) {
	t.Parallel()
	cause := errors.New("internal detail: Authorization: Bearer internal-only-token")
	err := apperr.Wrap(apperr.CodeUpstreamProtocol, "bad response from Jenkins", cause)
	if strings.Contains(err.Error(), "internal-only-token") {
		t.Fatalf("Error() included cause secret: %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatal("errors.Is should find cause via Unwrap")
	}
}

func TestClassifyCancellationAndTimeout(t *testing.T) {
	t.Parallel()
	if c, ok := apperr.Classify(context.Canceled); !ok || c != apperr.CodeCancelled {
		t.Fatalf("canceled: %v %v", c, ok)
	}
	if c, ok := apperr.Classify(context.DeadlineExceeded); !ok || c != apperr.CodeTimeout {
		t.Fatalf("deadline: %v %v", c, ok)
	}
	if !apperr.IsCancelled(context.Canceled) {
		t.Fatal("IsCancelled")
	}
	if !apperr.IsTimeout(context.DeadlineExceeded) {
		t.Fatal("IsTimeout")
	}

	wrapped := apperr.Wrap(apperr.CodeTimeout, "upstream slow", context.DeadlineExceeded)
	if apperr.CodeOf(wrapped) != apperr.CodeTimeout {
		t.Fatal("CodeOf wrapped timeout")
	}
}

func TestClassifyHTTPHeuristics(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		code apperr.Code
	}{
		{errors.New("jenkins: 401 unauthorized"), apperr.CodeAuthentication},
		{errors.New("status 403 Forbidden"), apperr.CodeAuthorization},
		{errors.New("job not found"), apperr.CodeNotFound},
		{errors.New("429 too many requests"), apperr.CodeThrottled},
	}
	for _, tc := range cases {
		c, ok := apperr.Classify(tc.err)
		if !ok || c != tc.code {
			t.Errorf("%v: got %q ok=%v want %q", tc.err, c, ok, tc.code)
		}
	}
}

func TestNewAndCodeOf(t *testing.T) {
	t.Parallel()
	err := apperr.New(apperr.CodePolicyDenial, "read-only mode")
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatal(apperr.CodeOf(err))
	}
	if apperr.CodeOf(nil) != "" {
		t.Fatal("nil")
	}
	mystery := errors.New("mystery")
	if c, ok := apperr.Classify(mystery); ok {
		t.Fatalf("unexpected classify %v", c)
	}
	if apperr.CodeOf(mystery) != apperr.CodeInternal {
		t.Fatalf("want internal, got %q", apperr.CodeOf(mystery))
	}
}
