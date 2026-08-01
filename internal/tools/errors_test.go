package tools

import (
	"context"
	"errors"
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
