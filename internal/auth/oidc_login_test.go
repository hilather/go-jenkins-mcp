package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
	"github.com/hilather/go-jenkins-mcp/internal/keyring"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
)

const (
	testAccessToken  = "ACCESS_TOKEN_canary_do_not_leak_xyz789"
	testRefreshToken = "REFRESH_TOKEN_canary_do_not_leak_abc456"
	testAuthCode     = "test-auth-code-001"
)

// freeLoopbackPort reserves a 127.0.0.1 port for redirect URI construction.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	// Retry: parallel tests may race on the TOCTOU between close and re-listen.
	var last error
	for i := 0; i < 20; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			last = err
			continue
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		// Brief settle so the OS reclaims the port for the same process.
		time.Sleep(5 * time.Millisecond)
		// Probe that the port is still free for our later bind.
		ln2, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			last = err
			continue
		}
		_ = ln2.Close()
		time.Sleep(5 * time.Millisecond)
		return port
	}
	t.Fatalf("freeLoopbackPort: %v", last)
	return 0
}

// mockOIDCIdP serves discovery, authorize (redirect), and token with PKCE check.
type mockOIDCIdP struct {
	t             *testing.T
	srv           *httptest.Server
	issuer        string
	wantChallenge string // when set, token endpoint verifies code_verifier
	resource      string
	// mutateAuthorize can force bad redirects / omit state
	forceState string // if non-empty, override state in redirect (for mismatch tests)
	omitCode   bool
	tokenEmpty bool
	// lastAuthorizeURL captures the last authorize request URL
	mu               sync.Mutex
	lastCodeVerifier string
	tokenHits        atomic.Int32
}

func startMockOIDCIdP(t *testing.T) *mockOIDCIdP {
	t.Helper()
	m := &mockOIDCIdP{t: t}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 m.issuer,
				"authorization_endpoint": m.issuer + "/authorize",
				"token_endpoint":         m.issuer + "/token",
				"jwks_uri":               m.issuer + "/jwks",
			})
		case r.URL.Path == "/authorize":
			q := r.URL.Query()
			// Validate required PKCE params present.
			if q.Get("response_type") != "code" {
				http.Error(w, "bad response_type", http.StatusBadRequest)
				return
			}
			if q.Get("code_challenge_method") != "S256" {
				http.Error(w, "need S256", http.StatusBadRequest)
				return
			}
			ch := q.Get("code_challenge")
			if ch == "" {
				http.Error(w, "missing challenge", http.StatusBadRequest)
				return
			}
			m.mu.Lock()
			m.wantChallenge = ch
			m.mu.Unlock()
			if m.resource != "" && q.Get("resource") != m.resource {
				http.Error(w, "resource mismatch", http.StatusBadRequest)
				return
			}
			redir := q.Get("redirect_uri")
			state := q.Get("state")
			if m.forceState != "" {
				state = m.forceState
			}
			u, err := url.Parse(redir)
			if err != nil {
				http.Error(w, "bad redir", http.StatusBadRequest)
				return
			}
			rq := u.Query()
			if !m.omitCode {
				rq.Set("code", testAuthCode)
			}
			rq.Set("state", state)
			u.RawQuery = rq.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
		case r.URL.Path == "/token":
			m.tokenHits.Add(1)
			if r.Method != http.MethodPost {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			vals, err := url.ParseQuery(string(body))
			if err != nil {
				http.Error(w, "form", http.StatusBadRequest)
				return
			}
			if vals.Get("grant_type") != "authorization_code" {
				http.Error(w, "grant", http.StatusBadRequest)
				return
			}
			if vals.Get("code") != testAuthCode {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			verifier := vals.Get("code_verifier")
			m.mu.Lock()
			m.lastCodeVerifier = verifier
			want := m.wantChallenge
			m.mu.Unlock()
			// PKCE S256 verification on mock token endpoint.
			if want != "" {
				sum := sha256.Sum256([]byte(verifier))
				got := base64.RawURLEncoding.EncodeToString(sum[:])
				if got != want {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"pkce"}`))
					return
				}
			}
			if m.resource != "" && vals.Get("resource") != m.resource {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_target"}`))
				return
			}
			// Public client: must not send client_secret.
			if vals.Get("client_secret") != "" {
				http.Error(w, "public client must not send secret", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if m.tokenEmpty {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"token_type": "Bearer",
					"expires_in": 3600,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  testAccessToken,
				"refresh_token": testRefreshToken,
				"token_type":    "Bearer",
				"expires_in":    3600,
				"id_token":      "header.payload.sig",
				"scope":         "openid",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	m.issuer = m.srv.URL
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockOIDCIdP) client() *http.Client {
	return m.srv.Client()
}

func testOIDCProfile(issuer, audience string, redirect string) *profile.Profile {
	return &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "oidc-corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodOIDC,
		Username:      "alice",
		OIDC: &profile.OIDCConfig{
			Issuer:          issuer,
			ClientID:        "public-client-id",
			RedirectURIs:    []string{redirect},
			Scopes:          []string{"openid", "profile"},
			JenkinsAudience: audience,
		},
	}
}

// driveBrowserFollowAuthorize follows the authorize URL with CheckRedirect disabled
// for the first hop... actually we want to follow the IdP redirect to our callback.
func driveBrowserFollowAuthorize(t *testing.T, authURL string) {
	t.Helper()
	// Default client follows redirects to loopback callback.
	client := &http.Client{
		Timeout: 5 * time.Second,
		// Do not send cookies; simple GET is enough.
	}
	resp, err := client.Get(authURL)
	if err != nil {
		// Callback server may close after success mid-body; still OK if login succeeds.
		t.Logf("browser get: %v", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
}

func TestLoginOIDC_FullFlowWithPKCE(t *testing.T) {
	// Not parallel: exclusive loopback bind for callback server.
	idp := startMockOIDCIdP(t)
	audience := "api://jenkins-api"
	idp.resource = audience

	port := freeLoopbackPort(t)
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	p := testOIDCProfile(idp.issuer, audience, redirect)
	store := auth.NewMemoryTokenStore()

	var opened atomic.Bool
	result, err := auth.LoginOIDC(context.Background(), p, auth.LoginOptions{
		HTTPClient: idp.client(),
		TokenStore: store,
		Timeout:    15 * time.Second,
		OpenBrowser: func(ctx context.Context, authURL string) error {
			opened.Store(true)
			// Sanity: authorize URL shape.
			u, err := url.Parse(authURL)
			if err != nil {
				return err
			}
			q := u.Query()
			if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
				t.Error("missing PKCE params")
			}
			if q.Get("resource") != audience {
				t.Errorf("resource: %q", q.Get("resource"))
			}
			if q.Get("client_id") != "public-client-id" {
				t.Errorf("client_id: %q", q.Get("client_id"))
			}
			if !strings.Contains(q.Get("scope"), "openid") {
				t.Errorf("scope: %q", q.Get("scope"))
			}
			// Drive IdP → redirect → loopback callback asynchronously.
			go driveBrowserFollowAuthorize(t, authURL)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !opened.Load() {
		t.Fatal("browser opener not called")
	}
	if result.Session.Method != auth.MethodOIDC {
		t.Fatalf("method: %s", result.Session.Method)
	}
	if result.Session.Secret != testAccessToken {
		t.Fatal("session secret mismatch")
	}
	if !result.HasRefresh {
		t.Fatal("expected refresh token flag")
	}
	if result.Session.ExpiresAt.Before(time.Now()) {
		t.Fatal("expires in past")
	}
	if result.Issuer != idp.issuer {
		t.Fatalf("issuer: %q", result.Issuer)
	}
	// Token store has material.
	blob, err := store.Get(context.Background(), string(p.ID))
	if err != nil {
		t.Fatal(err)
	}
	if blob.AccessToken != testAccessToken || blob.RefreshToken != testRefreshToken {
		t.Fatal("stored blob mismatch")
	}
	// PKCE verified on mock token endpoint.
	if idp.tokenHits.Load() != 1 {
		t.Fatalf("token hits: %d", idp.tokenHits.Load())
	}
	idp.mu.Lock()
	if idp.lastCodeVerifier == "" {
		t.Error("token endpoint did not see code_verifier")
	}
	idp.mu.Unlock()

	// Provider Authenticate/Status/Logout round-trip.
	prov := auth.NewOIDCProviderWithStore(store, nil)
	prov.Tokens = store
	sess, err := prov.Authenticate(context.Background(), auth.ProfileFrom(p))
	if err != nil || sess.Secret != testAccessToken {
		t.Fatalf("provider auth: %v %+v", err, sess)
	}
	st, err := prov.Status(context.Background(), auth.ProfileFrom(p))
	if err != nil || !st.Authenticated || !st.HasCredential {
		t.Fatalf("status: %+v %v", st, err)
	}
	// Canary: secrets never in status.
	if strings.Contains(st.ErrorMessageSafe, testAccessToken) || strings.Contains(st.User, testAccessToken) {
		t.Fatal("token leaked in status")
	}
	if err := prov.Logout(context.Background(), auth.ProfileFrom(p)); err != nil {
		t.Fatal(err)
	}
	_, err = prov.Authenticate(context.Background(), auth.ProfileFrom(p))
	if err == nil {
		t.Fatal("expected failure after logout")
	}
}

func TestLoginOIDC_StateMismatch(t *testing.T) {
	idp := startMockOIDCIdP(t)
	idp.forceState = "attacker-forged-state"
	port := freeLoopbackPort(t)
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	p := testOIDCProfile(idp.issuer, "api://jenkins-api", redirect)

	_, err := auth.LoginOIDC(context.Background(), p, auth.LoginOptions{
		HTTPClient: idp.client(),
		TokenStore: auth.NewMemoryTokenStore(),
		Timeout:    10 * time.Second,
		OpenBrowser: func(ctx context.Context, authURL string) error {
			go driveBrowserFollowAuthorize(t, authURL)
			return nil
		},
	})
	if err == nil {
		t.Fatal("expected state mismatch failure")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}
	if !strings.Contains(err.Error(), "state") {
		t.Fatalf("msg: %v", err)
	}
	if strings.Contains(err.Error(), testAccessToken) {
		t.Fatal("token in error")
	}
}

func TestLoginOIDC_Timeout(t *testing.T) {
	idp := startMockOIDCIdP(t)
	port := freeLoopbackPort(t)
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	p := testOIDCProfile(idp.issuer, "api://jenkins-api", redirect)

	// No-op browser: never hits callback.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := auth.LoginOIDC(ctx, p, auth.LoginOptions{
		HTTPClient:  idp.client(),
		OpenBrowser: auth.NoopBrowser,
		Timeout:     200 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected timeout")
	}
	code := apperr.CodeOf(err)
	if code != apperr.CodeTimeout && code != apperr.CodeCancelled {
		t.Fatalf("code: %v err=%v", code, err)
	}
}

func TestLoginOIDC_EmptyAccessToken(t *testing.T) {
	idp := startMockOIDCIdP(t)
	idp.tokenEmpty = true
	port := freeLoopbackPort(t)
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	p := testOIDCProfile(idp.issuer, "api://jenkins-api", redirect)

	_, err := auth.LoginOIDC(context.Background(), p, auth.LoginOptions{
		HTTPClient: idp.client(),
		Timeout:    10 * time.Second,
		OpenBrowser: func(ctx context.Context, authURL string) error {
			go driveBrowserFollowAuthorize(t, authURL)
			return nil
		},
	})
	if err == nil {
		t.Fatal("expected empty access_token failure")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code: %v", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "access_token") {
		t.Fatalf("msg: %v", err)
	}
}

func TestSelectLoopbackRedirect_FailClosed(t *testing.T) {
	// Public host rejected.
	_, _, _, err := auth.SelectLoopbackRedirect([]string{"https://evil.example.com/cb"}, "")
	if err == nil {
		t.Fatal("public host")
	}
	// localhost rejected (bind policy is 127.0.0.1 only).
	_, _, _, err = auth.SelectLoopbackRedirect([]string{"http://localhost:9999/cb"}, "")
	if err == nil {
		t.Fatal("localhost must be rejected (bind 127.0.0.1 only)")
	}
	// 0.0.0.0 rejected.
	_, _, _, err = auth.SelectLoopbackRedirect([]string{"http://0.0.0.0:9999/cb"}, "")
	if err == nil {
		t.Fatal("0.0.0.0")
	}
	// Prefer must be in allowlist.
	_, _, _, err = auth.SelectLoopbackRedirect(
		[]string{"http://127.0.0.1:1/cb"},
		"http://127.0.0.1:2/cb",
	)
	if err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("open redirect: %v", err)
	}
	// Good.
	uri, host, port, err := auth.SelectLoopbackRedirect([]string{"http://127.0.0.1:34567/oauth/callback"}, "")
	if err != nil || host != "127.0.0.1" || port != 34567 || uri == "" {
		t.Fatalf("%q %q %d %v", uri, host, port, err)
	}
}

func TestBuildAuthorizeURL_ResourceAndPKCE(t *testing.T) {
	doc := &auth.DiscoveryDocument{
		AuthorizationEndpoint: "https://idp.example.com/oauth2/v2.0/authorize",
	}
	u, err := auth.BuildAuthorizeURL(doc, auth.AuthorizeParams{
		ClientID:      "cid",
		RedirectURI:   "http://127.0.0.1:1/cb",
		Scopes:        []string{"openid"},
		State:         "st",
		Nonce:         "nn",
		CodeChallenge: "ch",
		Resource:      "api://jenkins",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != "ch" {
		t.Fatalf("pkce: %v", q)
	}
	if q.Get("resource") != "api://jenkins" {
		t.Fatalf("resource: %q", q.Get("resource"))
	}
	if q.Get("nonce") != "nn" || q.Get("state") != "st" {
		t.Fatalf("state/nonce: %v", q)
	}
}

func TestKeyringOIDCTokenStore_RoundTrip(t *testing.T) {
	kr := keyring.NewStore(keyring.NewMemory())
	st := auth.NewKeyringTokenStore(kr)
	blob := auth.TokenBundle{
		AccessToken:  testAccessToken,
		RefreshToken: testRefreshToken,
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := st.Set(context.Background(), "corp", blob); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(context.Background(), "corp")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != testAccessToken || got.RefreshToken != testRefreshToken {
		t.Fatal("mismatch")
	}
	// Namespace isolation from api_token.
	ref := keyring.CredentialRef{
		ProfileID: "corp",
		Origin:    "https://jenkins.example.com",
		Method:    "api_token",
		Account:   "alice",
	}
	if err := kr.SetAPIToken(ref, "api-token-value"); err != nil {
		t.Fatal(err)
	}
	// OIDC get still returns OIDC blob.
	got, err = st.Get(context.Background(), "corp")
	if err != nil || got.AccessToken != testAccessToken {
		t.Fatal("oidc isolated from api_token")
	}
	if err := st.Delete(context.Background(), "corp"); err != nil {
		t.Fatal(err)
	}
	_, err = st.Get(context.Background(), "corp")
	if err == nil {
		t.Fatal("expected missing after clear")
	}
	// API token still present.
	if tok, err := kr.GetAPIToken(ref); err != nil || tok != "api-token-value" {
		t.Fatalf("api token should remain: %v", err)
	}
}

func TestOIDCProvider_ExpiredAccessToken(t *testing.T) {
	store := auth.NewMemoryTokenStore()
	p := testOIDCProfile("https://idp.example.com", "api://j", "http://127.0.0.1:1/cb")
	_ = store.Set(context.Background(), string(p.ID), auth.TokenBundle{
		AccessToken: testAccessToken,
		ExpiresAt:   time.Now().Add(-time.Minute),
	})
	prov := &auth.OIDCProvider{Tokens: store}
	_, err := prov.Authenticate(context.Background(), auth.ProfileFrom(p))
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("msg: %v", err)
	}
}

func TestLoginOIDC_Cancel(t *testing.T) {
	idp := startMockOIDCIdP(t)
	port := freeLoopbackPort(t)
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	p := testOIDCProfile(idp.issuer, "api://jenkins-api", redirect)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := auth.LoginOIDC(ctx, p, auth.LoginOptions{
		HTTPClient:  idp.client(),
		OpenBrowser: auth.NoopBrowser,
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		// May fail earlier on discovery cancel.
		if err == nil {
			t.Fatal("expected error")
		}
		code := apperr.CodeOf(err)
		if code != apperr.CodeCancelled && code != apperr.CodeTimeout {
			t.Fatalf("code: %v err=%v", code, err)
		}
	}
}

func TestLoginOIDC_RejectsNonOIDCProfile(t *testing.T) {
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "tok",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	_, err := auth.LoginOIDC(context.Background(), p, auth.LoginOptions{
		HTTPClient: http.DefaultClient,
	})
	if err == nil {
		t.Fatal("expected reject")
	}
}
