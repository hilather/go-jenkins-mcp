package jenkins

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
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

// Regression: AuthProviderCtx supplies credentials from request context and
// does not write secrets onto Client.User/Token (multi-user race residual).
func TestCallJenkins_AuthProviderCtxUsedNoStaticWrite(t *testing.T) {
	t.Parallel()
	const liveTok = "CTX_AUTH_LIVE_token_must_not_write_back_xyz"
	var lastAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice","anonymous":false,"authenticated":true}`))
	}))
	t.Cleanup(srv.Close)

	type subjectKey struct{}
	c := &Client{
		URL:    srv.URL,
		User:   "stale-user",
		Token:  "stale-static-must-not-be-sent",
		Client: srv.Client(),
		AuthProviderCtx: func(ctx context.Context) (user, secret string, scheme AuthScheme, err error) {
			sub, _ := ctx.Value(subjectKey{}).(string)
			if sub != "alice" {
				return "", "", "", apperr.New(apperr.CodeAuthentication, "unexpected subject")
			}
			return "alice", liveTok, AuthSchemeBearer, nil
		},
	}
	ctx := context.WithValue(context.Background(), subjectKey{}, "alice")
	if _, err := c.WhoAmI(ctx); err != nil {
		t.Fatal(err)
	}
	if lastAuth != "Bearer "+liveTok {
		t.Fatalf("Authorization=%q", lastAuth)
	}
	// Must not write secrets back onto Client (multi-user residual).
	if c.Token == liveTok || c.User == "alice" {
		t.Fatalf("AuthProviderCtx must not write User/Token; user=%q token_set=%v", c.User, c.Token == liveTok)
	}
	if c.Token != "stale-static-must-not-be-sent" {
		t.Fatalf("static token mutated: %q", c.Token)
	}
}

// Regression: AuthProviderCtx prefers context provider over process AuthProvider.
func TestCallJenkins_AuthProviderCtxWinsOverAuthProvider(t *testing.T) {
	t.Parallel()
	var lastAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ctx-user","anonymous":false}`))
	}))
	t.Cleanup(srv.Close)

	c := &Client{
		URL:    srv.URL,
		Client: srv.Client(),
		AuthProvider: func() (string, string, AuthScheme, error) {
			return "process", "process-token-must-not-win", AuthSchemeBearer, nil
		},
		AuthProviderCtx: func(ctx context.Context) (string, string, AuthScheme, error) {
			_ = ctx
			return "ctx-user", "ctx-token-wins", AuthSchemeBearer, nil
		},
	}
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lastAuth != "Bearer ctx-token-wins" {
		t.Fatalf("Authorization=%q want ctx token", lastAuth)
	}
}

// Regression: AuthProviderCtx error fails closed; cancelled context surfaces.
func TestCallJenkins_AuthProviderCtxFailureAndCancel(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	const canary = "CTX_AUTH_CANARY_secret_never_in_errors_abc123"
	c := &Client{
		URL:    srv.URL,
		Token:  canary,
		Client: srv.Client(),
		AuthProviderCtx: func(ctx context.Context) (string, string, AuthScheme, error) {
			if err := ctx.Err(); err != nil {
				return "", "", "", apperr.Wrap(apperr.CodeCancelled, "auth provider cancelled", err)
			}
			return "", "", "", apperr.New(apperr.CodeAuthentication, "obtain failed for subject")
		},
	}
	_, err := c.CallJenkins(context.Background(), srv.Client(), http.MethodGet, WhoAmIPath, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if hits.Load() != 0 {
		t.Fatalf("request must not be sent; hits=%d", hits.Load())
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("canary in error: %v", err)
	}

	// Cancelled context: provider must see cancel and fail closed without network.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.CallJenkins(ctx, srv.Client(), http.MethodGet, WhoAmIPath, nil, nil)
	if err == nil {
		t.Fatal("expected cancel error")
	}
	if hits.Load() != 0 {
		t.Fatalf("request must not be sent on cancel; hits=%d", hits.Load())
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("canary on cancel: %v", err)
	}
}

func TestClient_HasLiveAuthProvider(t *testing.T) {
	t.Parallel()
	if (&Client{}).HasLiveAuthProvider() {
		t.Fatal("empty")
	}
	var nilC *Client
	if nilC.HasLiveAuthProvider() {
		t.Fatal("nil")
	}
	c := &Client{AuthProvider: func() (string, string, AuthScheme, error) { return "", "", "", nil }}
	if !c.HasLiveAuthProvider() {
		t.Fatal("AuthProvider")
	}
	c2 := &Client{AuthProviderCtx: func(context.Context) (string, string, AuthScheme, error) {
		return "", "", "", nil
	}}
	if !c2.HasLiveAuthProvider() {
		t.Fatal("AuthProviderCtx")
	}
}

func TestWithAuthProviderCtx_NilSafe(t *testing.T) {
	t.Parallel()
	var nilC *Client
	if nilC.WithAuthProviderCtx(nil) != nil {
		t.Fatal("nil receiver")
	}
	c := &Client{}
	c.WithAuthProviderCtx(func(context.Context) (string, string, AuthScheme, error) {
		return "u", "s", AuthSchemeBasic, nil
	})
	if c.AuthProviderCtx == nil {
		t.Fatal("not installed")
	}
	c.WithAuthProviderCtx(nil)
	if c.AuthProviderCtx != nil {
		t.Fatal("clear")
	}
}
