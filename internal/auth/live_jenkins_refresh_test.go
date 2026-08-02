package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// End-to-end style: expired OIDC access → LiveSessionSource refresh once →
// Jenkins Client AuthProvider sends Bearer with new token.
func TestMidServeRefresh_JenkinsClientUsesFreshBearer(t *testing.T) {
	t.Parallel()
	var refreshHits atomic.Int32
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		refreshHits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "jenkins-fresh-bearer-token",
			"refresh_token": "rt-1",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(tokenSrv.Close)

	var lastAuth string
	jenkinsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuth = r.Header.Get("Authorization")
		if !strings.HasPrefix(r.URL.Path, "/whoAmI") && r.URL.Path != jenkins.WhoAmIPath {
			// Accept whoAmI path variants.
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice","anonymous":false,"authenticated":true}`))
	}))
	t.Cleanup(jenkinsSrv.Close)

	store := auth.NewMemoryTokenStore()
	oidc := auth.NewOIDCProviderWithStore(store, tokenSrv.Client())
	ctx := context.Background()
	if err := oidc.StoreTokens(ctx, "corp", auth.TokenBundle{
		AccessToken:  liveCredCanary,
		RefreshToken: "rt-old",
		ExpiresAt:    time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	guard := auth.NewSessionGuard(auth.IdentityFingerprint("sub", "", "alice", nil))
	src := &auth.LiveSessionSource{
		OIDC: oidc,
		Profile: auth.Profile{
			ID:                contracts.ProfileID("corp"),
			OIDCClientID:      "mcp",
			OIDCTokenEndpoint: tokenSrv.URL,
			User:              "alice",
		},
		Guard: guard,
	}

	c := &jenkins.Client{
		URL:        jenkinsSrv.URL,
		Token:      liveCredCanary, // stale; AuthProvider must replace
		AuthScheme: jenkins.AuthSchemeBearer,
		Client:     jenkinsSrv.Client(),
	}
	c.WithAuthProvider(func() (user, secret string, scheme jenkins.AuthScheme, err error) {
		creds, err := src.Credentials(context.Background())
		if err != nil {
			return "", "", "", err
		}
		sch := jenkins.AuthSchemeBasic
		if creds.Scheme == auth.HTTPAuthBearer {
			sch = jenkins.AuthSchemeBearer
		}
		return creds.User, creds.Secret, sch, nil
	})

	who, err := c.WhoAmI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if who.ID != "alice" {
		t.Fatalf("%+v", who)
	}
	if lastAuth != "Bearer jenkins-fresh-bearer-token" {
		t.Fatalf("Authorization=%q", lastAuth)
	}
	if refreshHits.Load() != 1 {
		t.Fatalf("refresh hits %d", refreshHits.Load())
	}
	// Second Jenkins call: no second refresh.
	if _, err := c.WhoAmI(ctx); err != nil {
		t.Fatal(err)
	}
	if refreshHits.Load() != 1 {
		t.Fatalf("second refresh: %d", refreshHits.Load())
	}
}

// Refresh failure marks guard; subsequent Jenkins calls fail without sending.
func TestMidServeRefresh_FailBlocksJenkinsAndGuard(t *testing.T) {
	t.Parallel()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	t.Cleanup(tokenSrv.Close)

	var jenkinsHits atomic.Int32
	jenkinsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jenkinsHits.Add(1)
		w.WriteHeader(200)
	}))
	t.Cleanup(jenkinsSrv.Close)

	store := auth.NewMemoryTokenStore()
	oidc := auth.NewOIDCProviderWithStore(store, tokenSrv.Client())
	ctx := context.Background()
	if err := oidc.StoreTokens(ctx, "corp", auth.TokenBundle{
		AccessToken:  liveCredCanary,
		RefreshToken: "dead",
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
	c := &jenkins.Client{
		URL:        jenkinsSrv.URL,
		Token:      liveCredCanary,
		AuthScheme: jenkins.AuthSchemeBearer,
		Client:     jenkinsSrv.Client(),
		AuthProvider: func() (string, string, jenkins.AuthScheme, error) {
			creds, err := src.Credentials(context.Background())
			if err != nil {
				return "", "", "", err
			}
			return creds.User, creds.Secret, jenkins.AuthSchemeBearer, nil
		},
	}
	_, err := c.WhoAmI(ctx)
	if err == nil {
		t.Fatal("expected auth failure")
	}
	if jenkinsHits.Load() != 0 {
		t.Fatalf("jenkins hit on auth fail: %d", jenkinsHits.Load())
	}
	if strings.Contains(err.Error(), liveCredCanary) {
		t.Fatalf("canary: %v", err)
	}
	if err := guard.Check(); err == nil {
		t.Fatal("guard must be marked")
	}
	// Subsequent tool-path Check fails closed.
	if err := guard.Check(); err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("subsequent check: %v", err)
	}
	_, err2 := c.WhoAmI(ctx)
	if err2 == nil {
		t.Fatal("second call must fail")
	}
	if jenkinsHits.Load() != 0 {
		t.Fatalf("jenkins must stay dark: %d", jenkinsHits.Load())
	}
}
