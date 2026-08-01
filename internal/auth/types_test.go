package auth_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
)

// Ensures Session is a value type (not a package-level global credential string).
func TestSessionIsScopedNotGlobal(t *testing.T) {
	t.Parallel()
	s := auth.Session{
		ProfileID: contracts.ProfileID("corp"),
		Method:    auth.MethodAPIToken,
		User:      "alice",
		Secret:    "must-not-appear-in-status",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	// Status sanitization contract: Status has no Secret field.
	st := reflect.TypeOf(auth.Status{})
	if _, ok := st.FieldByName("Secret"); ok {
		t.Fatal("auth.Status must not carry Secret")
	}
	if _, ok := st.FieldByName("Token"); ok {
		t.Fatal("auth.Status must not carry Token")
	}
	if s.ProfileID != "corp" || s.Method != auth.MethodAPIToken {
		t.Fatal("session fields")
	}
	// CredentialProvider interface is assignable (compile-time check via var).
	var _ auth.CredentialProvider = nil
	var _ auth.CredentialProvider = (*auth.APITokenProvider)(nil)
	var _ auth.CredentialProvider = (*auth.OIDCProvider)(nil)
	// Status must expose HasRefresh as bool metadata only (OAUTH-007).
	if f, ok := st.FieldByName("HasRefresh"); !ok || f.Type.Kind() != reflect.Bool {
		t.Fatal("auth.Status.HasRefresh must be bool")
	}
}
