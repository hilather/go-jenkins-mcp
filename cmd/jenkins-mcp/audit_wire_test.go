package main

import (
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

func TestAuditReasonFromErr_IdentityMismatch(t *testing.T) {
	t.Parallel()
	err := apperr.New(apperr.CodeAuthentication, "jenkins identity does not match expected user for this profile")
	if got := auditReasonFromErr(err); got != "identity_mismatch" {
		t.Fatalf("got %q", got)
	}
	if got := auditReasonFromErr(apperr.New(apperr.CodeAuthentication, "jenkins identity is anonymous; authentication failed closed")); got != "anonymous_identity" {
		t.Fatalf("got %q", got)
	}
	if got := auditReasonFromErr(apperr.New(apperr.CodeTimeout, "operation timed out")); got != "timeout" {
		t.Fatalf("got %q", got)
	}
}
