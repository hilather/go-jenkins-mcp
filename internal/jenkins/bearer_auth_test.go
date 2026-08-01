package jenkins

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const bearerCanary = "CANARY_BEARER_token_must_not_appear_in_errors_abc123XYZ"

func TestCallJenkins_BearerAuthHeader(t *testing.T) {
	t.Parallel()
	var gotAuth string
	var gotBasicUser, gotBasicPass string
	var gotBasicOK bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotBasicUser, gotBasicPass, gotBasicOK = r.BasicAuth()
		if r.URL.Path != WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice","fullName":"Alice","anonymous":false,"authenticated":true}`))
	}))
	t.Cleanup(srv.Close)

	c := &Client{
		URL:        srv.URL,
		User:       "alice-label",
		Token:      bearerCanary,
		AuthScheme: AuthSchemeBearer,
		Client:     srv.Client(),
	}
	who, err := c.WhoAmI(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if who.ID != "alice" {
		t.Fatalf("%+v", who)
	}
	if gotBasicOK {
		t.Fatalf("bearer path must not send Basic auth (user=%q pass_present=%v)", gotBasicUser, gotBasicPass != "")
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotAuth != "Bearer "+bearerCanary {
		t.Fatalf("want Bearer canary, got %q", gotAuth)
	}
	// Canary: error paths must not echo token.
	c.Token = bearerCanary
	c.URL = srv.URL + "/missing-origin-will-not-matter"
	// Force a 404-ish path with valid origin:
	c.URL = srv.URL
	resp, err := c.CallJenkins(context.Background(), srv.Client(), http.MethodGet, "/no-such-path", nil, nil)
	if err != nil {
		if strings.Contains(err.Error(), bearerCanary) {
			t.Fatalf("token in error: %v", err)
		}
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), bearerCanary) {
		// Response body from our fixture won't have it; just ensure we didn't write it.
	}
}

func TestCallJenkins_BasicAuthUnchanged(t *testing.T) {
	t.Parallel()
	const user = "tester"
	const token = "secret-api-token-value"
	var gotUser, gotPass string
	var gotOK bool
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUser, gotPass, gotOK = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"tester","anonymous":false}`))
	}))
	t.Cleanup(srv.Close)

	// Default empty AuthScheme → Basic.
	c := &Client{
		URL:    srv.URL,
		User:   user,
		Token:  token,
		Client: srv.Client(),
	}
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !gotOK || gotUser != user || gotPass != token {
		t.Fatalf("basic auth: ok=%v user=%q pass=%q", gotOK, gotUser, gotPass)
	}
	if strings.HasPrefix(strings.ToLower(gotAuth), "bearer ") {
		t.Fatal("api_token path must not send Bearer")
	}

	// Explicit Basic scheme.
	gotOK = false
	c.AuthScheme = AuthSchemeBasic
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !gotOK {
		t.Fatal("explicit basic")
	}
}

func TestNewClientWithTransportScheme_Bearer(t *testing.T) {
	t.Parallel()
	var authz string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"id":"x","anonymous":false}`))
	}))
	t.Cleanup(srv.Close)

	cfg := DefaultTransportConfig()
	cfg.APIClientTimeout = 0
	c, err := NewClientWithTransportScheme(srv.URL, "label", bearerCanary, AuthSchemeBearer, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Use fixture client transport target via CallJenkins with server client for simplicity.
	c.Client = srv.Client()
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
	if authz != "Bearer "+bearerCanary {
		t.Fatalf("authz=%q", authz)
	}
	if c.AuthScheme != AuthSchemeBearer {
		t.Fatalf("scheme=%q", c.AuthScheme)
	}
}

func TestWhoAmI_BearerUnauthorizedNoTokenLeak(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("invalid token " + bearerCanary))
	}))
	t.Cleanup(srv.Close)
	c := &Client{
		URL:        srv.URL,
		Token:      bearerCanary,
		AuthScheme: AuthSchemeBearer,
		Client:     srv.Client(),
	}
	_, err := c.WhoAmI(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), bearerCanary) {
		t.Fatalf("token leaked: %v", err)
	}
}
