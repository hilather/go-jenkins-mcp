package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
)

const liveCredCanary = "LIVE_CRED_CANARY_access_must_never_appear_in_errors_or_status_ZZZ"

// Expired access mid-serve: LiveSessionSource triggers single refresh once.
func TestLiveSessionSource_ExpiredAccessTriggersRefreshOnce(t *testing.T) {
	t.Parallel()
	var refreshHits atomic.Int32
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type %q", r.Form.Get("grant_type"))
		}
		refreshHits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-live-access-token-value",
			"refresh_token": "rotated-live-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(tokenSrv.Close)

	store := auth.NewMemoryTokenStore()
	oidc := auth.NewOIDCProviderWithStore(store, tokenSrv.Client())
	ctx := context.Background()
	if err := oidc.StoreTokens(ctx, "corp", auth.TokenBundle{
		AccessToken:  liveCredCanary,
		RefreshToken: "refresh-for-live-source",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	guard := auth.NewSessionGuard("fp-live")
	src := &auth.LiveSessionSource{
		OIDC: oidc,
		Profile: auth.Profile{
			ID:                contracts.ProfileID("corp"),
			OIDCClientID:      "mcp-client",
			OIDCTokenEndpoint: tokenSrv.URL,
			User:              "alice",
		},
		Guard: guard,
	}

	c1, err := src.Credentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c1.Secret != "new-live-access-token-value" {
		t.Fatalf("secret=%q", c1.Secret)
	}
	if c1.Scheme != auth.HTTPAuthBearer {
		t.Fatalf("scheme=%q", c1.Scheme)
	}
	if refreshHits.Load() != 1 {
		t.Fatalf("refresh hits %d", refreshHits.Load())
	}
	// Second call uses valid in-memory access — no second refresh.
	c2, err := src.Credentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Secret != "new-live-access-token-value" {
		t.Fatal("unexpected secret change")
	}
	if refreshHits.Load() != 1 {
		t.Fatalf("unexpected second refresh: %d", refreshHits.Load())
	}
	if err := guard.Check(); err != nil {
		t.Fatal(err)
	}
}

// Refresh fail marks SessionGuard so subsequent Credentials and Check fail closed.
func TestLiveSessionSource_RefreshFailMarksGuard(t *testing.T) {
	t.Parallel()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"revoked ` + liveCredCanary + `"}`))
	}))
	t.Cleanup(tokenSrv.Close)

	store := auth.NewMemoryTokenStore()
	oidc := auth.NewOIDCProviderWithStore(store, tokenSrv.Client())
	ctx := context.Background()
	if err := oidc.StoreTokens(ctx, "corp", auth.TokenBundle{
		AccessToken:  liveCredCanary,
		RefreshToken: "dead-refresh",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	guard := auth.NewSessionGuard("fp")
	src := &auth.LiveSessionSource{
		OIDC: oidc,
		Profile: auth.Profile{
			ID:                "corp",
			OIDCClientID:      "c",
			OIDCTokenEndpoint: tokenSrv.URL,
		},
		Guard: guard,
	}
	_, err := src.Credentials(ctx)
	if err == nil {
		t.Fatal("expected refresh failure")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	if strings.Contains(err.Error(), liveCredCanary) {
		t.Fatalf("canary in error: %v", err)
	}
	// Guard marked; subsequent Check and Credentials fail without network.
	if err := guard.Check(); err == nil {
		t.Fatal("guard must fail after refresh failure")
	}
	_, err2 := src.Credentials(ctx)
	if err2 == nil {
		t.Fatal("credentials must fail closed after guard mark")
	}
	if strings.Contains(err2.Error(), liveCredCanary) {
		t.Fatalf("canary in second error: %v", err2)
	}
}

func TestLiveSessionSource_DisableSession(t *testing.T) {
	t.Parallel()
	guard := auth.NewSessionGuard("fp")
	src := &auth.LiveSessionSource{Guard: guard}
	if err := guard.Check(); err != nil {
		t.Fatal(err)
	}
	src.DisableSession()
	if err := guard.Check(); err == nil {
		t.Fatal("disabled session must fail closed")
	}
}

func TestValidateServeAccessToken_JWTAudienceFailClosed(t *testing.T) {
	t.Parallel()
	priv, jwksJSON, kid := testRSAJWKSJSON(t)
	now := time.Now()
	// Combined discovery + JWKS server (same origin as issuer).
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 srvURL,
				"authorization_endpoint": srvURL + "/authorize",
				"token_endpoint":         srvURL + "/token",
				"jwks_uri":               srvURL + "/jwks",
			})
		case "/jwks":
			_, _ = w.Write(jwksJSON)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL
	// Token audience is Graph — must fail closed for Jenkins serve.
	tok := mustSignRS256Live(t, priv, kid, map[string]any{
		"iss":       srvURL,
		"sub":       "user-1",
		"aud":       "https://graph.microsoft.com",
		"exp":       now.Add(time.Hour).Unix(),
		"nbf":       now.Add(-time.Minute).Unix(),
		"token_use": "access_token",
		"groups":    []string{"ops"},
	})

	_, err := auth.ValidateServeAccessToken(context.Background(), tok, auth.ServeTokenValidation{
		Issuer:     srvURL,
		Audience:   "https://jenkins.example.com",
		JenkinsURL: "https://jenkins.example.com",
		HTTP:       srv.Client(),
	})
	if err == nil {
		t.Fatal("wrong audience must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication && apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	if strings.Contains(err.Error(), tok) {
		t.Fatalf("token in error: %v", err)
	}
}

func TestValidateServeAccessToken_GoodJWTAndGroups(t *testing.T) {
	t.Parallel()
	priv, jwksJSON, kid := testRSAJWKSJSON(t)
	now := time.Now()
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 srvURL,
				"authorization_endpoint": srvURL + "/authorize",
				"token_endpoint":         srvURL + "/token",
				"jwks_uri":               srvURL + "/jwks",
			})
		case "/jwks":
			_, _ = w.Write(jwksJSON)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	tok := mustSignRS256Live(t, priv, kid, map[string]any{
		"iss":                srvURL,
		"sub":                "sub-alice",
		"preferred_username": "alice",
		"aud":                "api://jenkins-api",
		"exp":                now.Add(time.Hour).Unix(),
		"nbf":                now.Add(-time.Minute).Unix(),
		"token_use":          "access_token",
		"groups":             []string{"team-a", "ops"},
	})
	res, err := auth.ValidateServeAccessToken(context.Background(), tok, auth.ServeTokenValidation{
		Issuer:     srvURL,
		Audience:   "api://jenkins-api",
		JenkinsURL: "https://jenkins.example.com",
		HTTP:       srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Form != auth.TokenFormJWT || res.Claims.Subject != "sub-alice" {
		t.Fatalf("%+v", res)
	}
	gr, err := auth.GroupsFromValidatedToken(tok, res, auth.DefaultGroupClaimConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(gr.Groups) != 2 {
		t.Fatalf("groups %v", gr.Groups)
	}
	bind := auth.BindOIDCSubject(res.Claims.Subject, "", "alice", gr.Groups, gr.ResidualNote)
	if bind.Fingerprint == "" || bind.ExternalSubject != "sub-alice" {
		t.Fatalf("%+v", bind)
	}
}

func TestValidateServeAccessToken_Opaque(t *testing.T) {
	t.Parallel()
	res, err := auth.ValidateServeAccessToken(context.Background(), "opaque-ref-token", auth.ServeTokenValidation{
		Issuer:   "https://idp.example.com",
		Audience: "api://j",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Form != auth.TokenFormOpaque {
		t.Fatal(res.Form)
	}
}

func testRSAJWKSJSON(t *testing.T) (*rsa.PrivateKey, []byte, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "kid-live-1"
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())
	raw, err := json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": n, "e": e,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return priv, raw, kid
}

func mustSignRS256Live(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	pl, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(hdr)
	p := base64.RawURLEncoding.EncodeToString(pl)
	signing := h + "." + p
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}
