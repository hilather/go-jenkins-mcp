package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/keyring"
)

const (
	accessCanary  = "ACCESS_CANARY_must_never_appear_in_errors_or_status_xyz"
	refreshCanary = "REFRESH_CANARY_must_never_appear_in_errors_or_status_abc"
	idTokenCanary = "IDTOKEN_CANARY_must_never_appear_xyz"
)

func TestTokenBundleRedactedString(t *testing.T) {
	t.Parallel()
	b := auth.TokenBundle{
		AccessToken:  accessCanary,
		RefreshToken: refreshCanary,
		TokenType:    "Bearer",
		ExpiresAt:    time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		IDToken:      idTokenCanary,
	}
	s := b.String()
	for _, canary := range []string{accessCanary, refreshCanary, idTokenCanary} {
		if strings.Contains(s, canary) {
			t.Fatalf("secret in String(): %s", s)
		}
	}
	if !strings.Contains(s, "has_access=true") || !strings.Contains(s, "has_refresh=true") {
		t.Fatalf("expected flags: %s", s)
	}
}

func TestTokenBundleKeyringRoundTrip(t *testing.T) {
	t.Parallel()
	b := auth.TokenBundle{
		AccessToken:  accessCanary,
		RefreshToken: refreshCanary,
		TokenType:    "Bearer",
		ExpiresAt:    time.Date(2030, 6, 1, 12, 0, 0, 0, time.UTC),
		IDToken:      idTokenCanary,
	}
	raw, err := b.MarshalKeyring()
	if err != nil {
		t.Fatal(err)
	}
	got, err := auth.UnmarshalTokenBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != accessCanary || got.RefreshToken != refreshCanary || got.IDToken != idTokenCanary {
		t.Fatalf("round-trip mismatch")
	}
	// Corrupt fails closed without echoing payload.
	_, err = auth.UnmarshalTokenBundle([]byte(`{not-json` + accessCanary))
	if err == nil || apperr.CodeOf(err) != apperr.CodeCorruptCache {
		t.Fatalf("corrupt: %v", err)
	}
	if strings.Contains(err.Error(), accessCanary) {
		t.Fatalf("canary in corrupt error: %v", err)
	}
}

func TestKeyringTokenStoreRoundTrip(t *testing.T) {
	t.Parallel()
	kr := keyring.NewStore(keyring.NewMemory())
	store := auth.NewKeyringTokenStore(kr)
	ctx := context.Background()
	b := auth.TokenBundle{
		AccessToken:  accessCanary,
		RefreshToken: refreshCanary,
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour).UTC(),
	}
	if err := store.Set(ctx, "corp", b); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, "corp")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != accessCanary || got.RefreshToken != refreshCanary {
		t.Fatal("mismatch")
	}
	ok, err := store.Has(ctx, "corp")
	if err != nil || !ok {
		t.Fatalf("Has: %v %v", ok, err)
	}
	if err := store.Delete(ctx, "corp"); err != nil {
		t.Fatal(err)
	}
	_, err = store.Get(ctx, "corp")
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("expected missing: %v", err)
	}
}

func TestExpiredAccessTriggersRefresh(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse: %v", err)
			http.Error(w, "bad", 400)
			return
		}
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("refresh_token") != refreshCanary {
			t.Errorf("refresh token mismatch")
		}
		if r.Form.Get("client_id") != "mcp-client" {
			t.Errorf("client_id %q", r.Form.Get("client_id"))
		}
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access-token-value-after-refresh",
			"refresh_token": "rotated-refresh-token-value",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(srv.Close)

	store := auth.NewMemoryTokenStore()
	p := auth.NewOIDCProviderWithStore(store, srv.Client())
	ctx := context.Background()
	expired := auth.TokenBundle{
		AccessToken:  "old-access-expired",
		RefreshToken: refreshCanary,
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-time.Minute),
	}
	if err := p.StoreTokens(ctx, "corp", expired); err != nil {
		t.Fatal(err)
	}
	pr := auth.Profile{
		ID:                "corp",
		URL:               "https://jenkins.example.com",
		OIDCClientID:      "mcp-client",
		OIDCTokenEndpoint: srv.URL,
	}
	sess, err := p.Authenticate(ctx, pr)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Secret != "new-access-token-value-after-refresh" {
		t.Fatalf("access not refreshed: %s", sess.Secret)
	}
	if sess.Method != auth.MethodOIDC {
		t.Fatalf("method %s", sess.Method)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
	// Rotated refresh persisted.
	got, err := store.Get(ctx, "corp")
	if err != nil {
		t.Fatal(err)
	}
	if got.RefreshToken != "rotated-refresh-token-value" {
		t.Fatalf("rotation not stored: %s", got.String())
	}
	// Second authenticate uses new access without another refresh (still valid).
	_, err = p.Authenticate(ctx, pr)
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("unexpected second refresh: %d", hits.Load())
	}
}

func TestConcurrentRefreshSingleFlight(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	var release sync.WaitGroup
	release.Add(1)
	var entered sync.WaitGroup
	entered.Add(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			entered.Done()
		}
		release.Wait()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "shared-access-after-singleflight",
			"refresh_token": refreshCanary,
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(srv.Close)

	store := auth.NewMemoryTokenStore()
	p := auth.NewOIDCProviderWithStore(store, srv.Client())
	ctx := context.Background()
	if err := p.StoreTokens(ctx, "corp", auth.TokenBundle{
		AccessToken:  "expired-access",
		RefreshToken: refreshCanary,
		ExpiresAt:    time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	pr := auth.Profile{
		ID:                "corp",
		OIDCClientID:      "c",
		OIDCTokenEndpoint: srv.URL,
	}

	const n = 16
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			defer done.Done()
			start.Wait()
			sess, err := p.Authenticate(ctx, pr)
			if err != nil {
				errs <- err
				return
			}
			if sess.Secret != "shared-access-after-singleflight" {
				errs <- errString("bad access")
			}
		}()
	}
	start.Done()
	// Wait until the IdP handler is entered, then release.
	entered.Wait()
	// Give other goroutines time to pile onto singleflight.
	time.Sleep(20 * time.Millisecond)
	release.Done()
	done.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("expected single refresh, got %d", hits.Load())
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestInvalidGrantClearsStore(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "refresh " + refreshCanary + " revoked",
		})
	}))
	t.Cleanup(srv.Close)

	store := auth.NewMemoryTokenStore()
	p := auth.NewOIDCProviderWithStore(store, srv.Client())
	ctx := context.Background()
	if err := p.StoreTokens(ctx, "corp", auth.TokenBundle{
		AccessToken:  accessCanary,
		RefreshToken: refreshCanary,
		ExpiresAt:    time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	pr := auth.Profile{
		ID:                "corp",
		OIDCClientID:      "c",
		OIDCTokenEndpoint: srv.URL,
	}
	_, err := p.Authenticate(ctx, pr)
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("got %v", err)
	}
	msg := err.Error()
	if strings.Contains(msg, accessCanary) || strings.Contains(msg, refreshCanary) {
		t.Fatalf("canary in error: %s", msg)
	}
	if !strings.Contains(msg, "jenkins-mcp login --profile corp") {
		t.Fatalf("expected recovery hint: %s", msg)
	}
	// Store cleared.
	ok, err := store.Has(ctx, "corp")
	if err != nil || ok {
		t.Fatalf("store should be cleared: ok=%v err=%v", ok, err)
	}
}

func TestLogoutClearsKeyringAndMemory(t *testing.T) {
	t.Parallel()
	var revokeHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		if r.Form.Get("token") != refreshCanary {
			t.Errorf("revoke token mismatch")
		}
		if r.Form.Get("token_type_hint") != "refresh_token" {
			t.Errorf("hint %q", r.Form.Get("token_type_hint"))
		}
		revokeHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	kr := keyring.NewStore(keyring.NewMemory())
	p := auth.NewOIDCProvider(kr, srv.Client())
	ctx := context.Background()
	if err := p.StoreTokens(ctx, "corp", auth.TokenBundle{
		AccessToken:  accessCanary,
		RefreshToken: refreshCanary,
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	pr := auth.Profile{
		ID:                     "corp",
		OIDCClientID:           "c",
		OIDCRevocationEndpoint: srv.URL,
	}
	details, err := p.LogoutDetailed(ctx, pr)
	if err != nil {
		t.Fatal(err)
	}
	if !details.LocalCleared || !details.RevocationAttempted || !details.RevocationOK {
		t.Fatalf("%+v", details)
	}
	if revokeHits.Load() != 1 {
		t.Fatalf("revoke hits %d", revokeHits.Load())
	}
	ok, err := kr.HasOIDCTokens("corp")
	if err != nil || ok {
		t.Fatalf("keyring should be empty: %v %v", ok, err)
	}
	// Authenticate after logout fails.
	_, err = p.Authenticate(ctx, pr)
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("post-logout auth: %v", err)
	}
}

func TestLogoutLocalSucceedsWhenRevocationFails(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	store := auth.NewMemoryTokenStore()
	p := auth.NewOIDCProviderWithStore(store, srv.Client())
	ctx := context.Background()
	_ = p.StoreTokens(ctx, "corp", auth.TokenBundle{
		AccessToken:  accessCanary,
		RefreshToken: refreshCanary,
		ExpiresAt:    time.Now().Add(time.Hour),
	})
	details, err := p.LogoutDetailed(ctx, auth.Profile{
		ID:                     "corp",
		OIDCClientID:           "c",
		OIDCRevocationEndpoint: srv.URL,
	})
	if err != nil {
		t.Fatalf("local logout must succeed: %v", err)
	}
	if !details.LocalCleared || !details.RevocationAttempted || details.RevocationOK {
		t.Fatalf("%+v", details)
	}
	if details.RevocationMessage == "" {
		t.Fatal("expected revocation message")
	}
	if strings.Contains(details.RevocationMessage, refreshCanary) {
		t.Fatalf("canary in revoke msg: %s", details.RevocationMessage)
	}
	ok, _ := store.Has(ctx, "corp")
	if ok {
		t.Fatal("store not cleared")
	}
}

func TestOIDCStatusSanitizationCanary(t *testing.T) {
	t.Parallel()
	store := auth.NewMemoryTokenStore()
	p := auth.NewOIDCProviderWithStore(store, nil)
	ctx := context.Background()
	exp := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := p.StoreTokens(ctx, "corp", auth.TokenBundle{
		AccessToken:  accessCanary,
		RefreshToken: refreshCanary,
		TokenType:    "Bearer",
		ExpiresAt:    exp,
		IDToken:      idTokenCanary,
	}); err != nil {
		t.Fatal(err)
	}
	st, err := p.Status(ctx, auth.Profile{ID: contracts.ProfileID("corp"), User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Method != auth.MethodOIDC {
		t.Fatalf("method %s", st.Method)
	}
	if !st.Authenticated || !st.HasCredential || !st.HasRefresh {
		t.Fatalf("%+v", st)
	}
	if !st.ExpiresAt.Equal(exp) {
		t.Fatalf("expires %v", st.ExpiresAt)
	}
	// Canary: no secrets in any string field.
	blob, _ := json.Marshal(st)
	s := string(blob) + st.ErrorMessageSafe + st.RecoveryHint + st.User + st.PrincipalID
	for _, c := range []string{accessCanary, refreshCanary, idTokenCanary} {
		if strings.Contains(s, c) {
			t.Fatalf("canary leaked in status: %s", s)
		}
	}

	// Missing tokens → recovery hint, no crash.
	st2, err := p.Status(ctx, auth.Profile{ID: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if st2.Authenticated || st2.HasRefresh {
		t.Fatalf("%+v", st2)
	}
	if !strings.Contains(st2.RecoveryHint, "jenkins-mcp login --profile other") {
		t.Fatalf("recovery: %q", st2.RecoveryHint)
	}
}

func TestOIDCCorruptBlobRecoverable(t *testing.T) {
	t.Parallel()
	kr := keyring.NewStore(keyring.NewMemory())
	// Plant corrupt blob directly.
	if err := kr.SetOIDCTokens("corp", `{broken`+accessCanary); err != nil {
		t.Fatal(err)
	}
	p := auth.NewOIDCProvider(kr, nil)
	ctx := context.Background()
	_, err := p.Authenticate(ctx, auth.Profile{ID: "corp", OIDCClientID: "c", OIDCTokenEndpoint: "http://127.0.0.1:1/token"})
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), accessCanary) {
		t.Fatalf("canary in error: %v", err)
	}
	// Corrupt entry cleared.
	ok, err := kr.HasOIDCTokens("corp")
	if err != nil || ok {
		t.Fatalf("expected cleared: %v %v", ok, err)
	}
}

func TestRefreshKeepsOldRefreshWhenNotRotated(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No refresh_token in response.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access-only",
			"token_type":   "Bearer",
			"expires_in":   100,
		})
	}))
	t.Cleanup(srv.Close)
	store := auth.NewMemoryTokenStore()
	p := auth.NewOIDCProviderWithStore(store, srv.Client())
	ctx := context.Background()
	_ = p.StoreTokens(ctx, "corp", auth.TokenBundle{
		AccessToken:  "old",
		RefreshToken: refreshCanary,
		ExpiresAt:    time.Now().Add(-time.Second),
	})
	_, err := p.Authenticate(ctx, auth.Profile{
		ID: "corp", OIDCClientID: "c", OIDCTokenEndpoint: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(ctx, "corp")
	if got.RefreshToken != refreshCanary {
		t.Fatalf("should keep old refresh: %s", got.String())
	}
	if got.AccessToken != "new-access-only" {
		t.Fatal("access not updated")
	}
}

func TestNewProviderOIDCIsReal(t *testing.T) {
	t.Parallel()
	kr := keyring.NewStore(keyring.NewMemory())
	cp, err := auth.NewProvider("oidc_bearer", kr)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cp.(*auth.OIDCProvider); !ok {
		t.Fatalf("type %T", cp)
	}
}
