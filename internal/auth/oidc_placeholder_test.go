package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/auth"
)

// Regression: the OIDC provider's Authenticate forces sess.User = "oidc" when
// the profile has no username, and VerifyIdentityHTTP then computed
// expected="oidc" — so every real Jenkins principal failed the
// EqualFold(p.ID, expected) check, and `serve` failed closed at AUTH-004 for
// the default OIDC profile (the documented "bind solely to whoAmI principal
// when no username label is known" escape requires expected == ""). The
// placeholder is now treated as "no label".
func TestVerifyIdentityHTTP_OIDPlaceholderBindsToWhoAmI(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice","fullName":"Alice A","anonymous":false,"authenticated":true}`))
	}))
	defer srv.Close()

	pr := auth.Profile{ID: "corp", URL: srv.URL} // no username label
	sess := auth.Session{
		ProfileID: "corp",
		Method:    auth.MethodOIDC,
		User:      "oidc", // the placeholder written by OIDCProvider.Authenticate
		Secret:    "access-token",
	}
	p, err := auth.VerifyIdentityHTTP(context.Background(), pr, sess, srv.Client())
	if err != nil {
		t.Fatalf("placeholder user must bind to whoAmI principal: %v", err)
	}
	if p.ID != "alice" {
		t.Fatalf("principal %q", p.ID)
	}
}

// Control: a real username label still binds strictly (mismatch fails closed).
func TestVerifyIdentityHTTP_RealLabelStillBinds(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice","anonymous":false,"authenticated":true}`))
	}))
	defer srv.Close()

	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "bob"}
	sess := auth.Session{ProfileID: "corp", Method: auth.MethodOIDC, User: "bob", Secret: "x"}
	if _, err := auth.VerifyIdentityHTTP(context.Background(), pr, sess, srv.Client()); err == nil {
		t.Fatal("mismatched real label must fail closed")
	}
}

// Regression (review follow-up): a profile whose stored Jenkins username is
// literally "oidc" must NOT skip the AUTH-004 mismatch gate — the placeholder
// relaxation applies only to the session label when the profile has no
// username. A profile-configured "oidc" binds strictly.
func TestVerifyIdentityHTTP_ProfileNamedOIDCStillBindsStrictly(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// whoAmI reports a DIFFERENT principal than the configured "oidc".
		_, _ = w.Write([]byte(`{"id":"alice","anonymous":false,"authenticated":true}`))
	}))
	defer srv.Close()

	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "oidc"} // real label
	sess := auth.Session{ProfileID: "corp", Method: auth.MethodOIDC, User: "oidc", Secret: "x"}
	if _, err := auth.VerifyIdentityHTTP(context.Background(), pr, sess, srv.Client()); err == nil {
		t.Fatal("profile-configured 'oidc' username must bind strictly and fail on mismatch")
	}
}
