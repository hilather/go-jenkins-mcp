package jenkins

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

const liveAuthCanary = "LIVE_AUTH_CANARY_token_must_not_appear_in_errors_xyz789ABC"

// Regression: mid-serve AuthProvider supplies Bearer on each request; static
// Token is ignored when AuthProvider is set.
func TestCallJenkins_AuthProviderBearerRefresh(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	var lastAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuth = r.Header.Get("Authorization")
		hits.Add(1)
		if r.URL.Path != WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice","anonymous":false,"authenticated":true}`))
	}))
	t.Cleanup(srv.Close)

	var providerHits atomic.Int32
	c := &Client{
		URL:        srv.URL,
		User:       "stale-label",
		Token:      "stale-expired-token",
		AuthScheme: AuthSchemeBearer,
		Client:     srv.Client(),
		AuthProvider: func() (user, secret string, scheme AuthScheme, err error) {
			providerHits.Add(1)
			return "alice", "fresh-access-after-refresh", AuthSchemeBearer, nil
		},
	}
	who, err := c.WhoAmI(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if who.ID != "alice" {
		t.Fatalf("%+v", who)
	}
	if lastAuth != "Bearer fresh-access-after-refresh" {
		t.Fatalf("Authorization=%q", lastAuth)
	}
	if providerHits.Load() != 1 {
		t.Fatalf("provider hits %d", providerHits.Load())
	}
	// Client fields updated from provider.
	if c.Token != "fresh-access-after-refresh" {
		t.Fatalf("client token not updated")
	}
	// Second call also refreshes via provider (provider owns single-flight).
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
	if providerHits.Load() != 2 {
		t.Fatalf("provider hits %d", providerHits.Load())
	}
}

// Regression: AuthProvider error fails closed before the request is sent.
func TestCallJenkins_AuthProviderFailureNoRequest(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c := &Client{
		URL:    srv.URL,
		Token:  liveAuthCanary,
		Client: srv.Client(),
		AuthProvider: func() (string, string, AuthScheme, error) {
			return "", "", "", apperr.New(apperr.CodeAuthentication,
				"token refresh failed; re-authenticate")
		},
	}
	// Prefer CallJenkins so we assert applyAuth fail-closed without whoAmI wrap.
	_, err := c.CallJenkins(context.Background(), srv.Client(), http.MethodGet, WhoAmIPath, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if hits.Load() != 0 {
		t.Fatalf("request must not be sent on auth provider failure; hits=%d", hits.Load())
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	if strings.Contains(err.Error(), liveAuthCanary) {
		t.Fatalf("canary in error: %v", err)
	}
	// WhoAmI must also surface authentication code (sanitize preserves apperr).
	_, err = c.WhoAmI(context.Background())
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("whoAmI code %v err %v", apperr.CodeOf(err), err)
	}
}

// Regression: api_token path unchanged when AuthProvider is nil.
func TestCallJenkins_AuthProviderNilUsesStaticBasic(t *testing.T) {
	t.Parallel()
	const user = "tester"
	const token = "static-api-token-value"
	var gotUser, gotPass string
	var gotOK bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOK = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"tester","anonymous":false}`))
	}))
	t.Cleanup(srv.Close)

	c := &Client{
		URL:    srv.URL,
		User:   user,
		Token:  token,
		Client: srv.Client(),
		// AuthProvider intentionally nil
	}
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !gotOK || gotUser != user || gotPass != token {
		t.Fatalf("basic: ok=%v user=%q", gotOK, gotUser)
	}
}

func TestCallJenkins_AuthProviderErrorCanary(t *testing.T) {
	t.Parallel()
	// Provider incorrectly embeds canary — applyAuth must still surface the
	// error as-is from provider (provider responsibility), but our test
	// provider must not leak; LiveSessionSource scrubs.
	c := &Client{
		URL: "http://127.0.0.1:9", // unused
		AuthProvider: func() (string, string, AuthScheme, error) {
			return "", "", "", apperr.New(apperr.CodeAuthentication, "authentication failed")
		},
	}
	// Build a request path that never hits network on provider error.
	// Use a fake client that panics if called.
	c.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("transport must not be used")
		return nil, nil
	})}
	resp, err := c.CallJenkins(context.Background(), nil, http.MethodGet, WhoAmIPath, nil, nil)
	if err == nil {
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), liveAuthCanary) {
		t.Fatalf("canary leak: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
