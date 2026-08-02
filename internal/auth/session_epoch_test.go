package auth_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
)

// Canary must never appear in session.epoch (non-secret file).
const epochTokenCanary = "EPOCH_CANARY_access_token_refresh_secret_must_never_land_in_epoch_file_ZZZ"

func TestSessionEpochStore_BumpLoadAtomicMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := &auth.SessionEpochStore{Dir: dir}

	missing, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !missing.Empty() {
		t.Fatalf("missing file should be empty: %+v", missing)
	}

	e1, err := store.Bump()
	if err != nil {
		t.Fatal(err)
	}
	if e1.Empty() || e1.Seq != 1 {
		t.Fatalf("first bump: %+v", e1)
	}
	path := store.Path()
	if path != filepath.Join(dir, auth.SessionEpochFileName) {
		t.Fatalf("path %q", path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o want 0600", fi.Mode().Perm())
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Value != e1.Value {
		t.Fatalf("load=%q bump=%q", loaded.Value, e1.Value)
	}

	e2, err := store.Bump()
	if err != nil {
		t.Fatal(err)
	}
	if e2.Seq != 2 || e2.Value == e1.Value {
		t.Fatalf("second bump must advance: e1=%+v e2=%+v", e1, e2)
	}
	// Content shape: seq RFC3339Nano nonce — no token-shaped secrets.
	if strings.Contains(e2.Value, "access_token") || strings.Contains(e2.Value, "refresh") {
		t.Fatalf("epoch looks like token material: %q", e2.Value)
	}
}

// Regression: epoch file never contains token material (canary).
func TestSessionEpochStore_NeverContainsTokenCanary(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := &auth.SessionEpochStore{Dir: dir}
	for i := 0; i < 5; i++ {
		if _, err := store.Bump(); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), epochTokenCanary) {
		t.Fatalf("canary leaked into epoch file: %q", raw)
	}
	// Coarse secret-shaped markers must not appear.
	for _, bad := range []string{"access_token", "refresh_token", "Bearer ", epochTokenCanary} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("forbidden %q in epoch: %q", bad, raw)
		}
	}
	// Length bound: epoch is small metadata.
	if len(raw) > 512 {
		t.Fatalf("epoch file too large (%d)", len(raw))
	}
}

// Simulate two processes sharing a temp dir: login bumps epoch, serve binds,
// logout bumps, live source fails closed and clears memory.
func TestCrossProcessLogout_LiveSessionSourceFailsClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	epochStore := &auth.SessionEpochStore{Dir: dir}

	// Process A (login): store tokens + bump epoch.
	memStore := auth.NewMemoryTokenStore()
	loginProv := auth.NewOIDCProviderWithStore(memStore, nil)
	loginProv.Epoch = epochStore
	ctx := context.Background()
	if err := loginProv.StoreTokens(ctx, "corp", auth.TokenBundle{
		AccessToken:  epochTokenCanary,
		RefreshToken: "refresh-for-epoch-test",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	epAfterLogin, err := epochStore.Load()
	if err != nil || epAfterLogin.Empty() {
		t.Fatalf("login must create epoch: %+v err=%v", epAfterLogin, err)
	}

	// Process B (serve): separate OIDCProvider memory, same durable TokenStore + epoch path.
	// Do not attach Epoch to serveProv — only the login/logout CLI process bumps.
	serveProv := auth.NewOIDCProviderWithStore(memStore, nil)
	// Seed process-local memory as if serve already Authenticate()'d (no epoch bump).
	if err := serveProv.StoreTokens(ctx, "corp", auth.TokenBundle{
		AccessToken:  epochTokenCanary,
		RefreshToken: "refresh-for-epoch-test",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	epAtServe, err := epochStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if epAtServe.Value != epAfterLogin.Value {
		// Serve-side StoreTokens without Epoch must not change the file.
		t.Fatalf("serve seed changed epoch: login=%q serve=%q", epAfterLogin.Value, epAtServe.Value)
	}
	watcher := &auth.SessionEpochWatcher{Store: epochStore}
	if err := watcher.Bind(); err != nil {
		t.Fatal(err)
	}
	if watcher.Seen() != epAtServe.Value {
		t.Fatalf("bound %q != %q", watcher.Seen(), epAtServe.Value)
	}

	guard := auth.NewSessionGuard("fp-epoch")
	src := &auth.LiveSessionSource{
		OIDC: serveProv,
		Profile: auth.Profile{
			ID:   contracts.ProfileID("corp"),
			User: "alice",
		},
		Guard: guard,
		Epoch: watcher,
	}

	// Healthy credentials while epoch matches.
	c, err := src.Credentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.Secret != epochTokenCanary {
		t.Fatalf("secret=%q", c.Secret)
	}
	if err := guard.Check(); err != nil {
		t.Fatal(err)
	}

	// Process A (logout): clear keyring + bump epoch (other process).
	logoutProv := auth.NewOIDCProviderWithStore(memStore, nil)
	logoutProv.Epoch = epochStore
	if err := logoutProv.Logout(ctx, auth.Profile{ID: "corp"}); err != nil {
		t.Fatal(err)
	}
	epAfterLogout, err := epochStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if epAfterLogout.Value == epAtServe.Value {
		t.Fatal("logout must bump epoch")
	}

	// Process B: next Credentials sees epoch change → fail closed.
	_, err = src.Credentials(ctx)
	if err == nil {
		t.Fatal("expected fail-closed after cross-process logout")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	if strings.Contains(err.Error(), epochTokenCanary) {
		t.Fatalf("canary in error: %v", err)
	}
	if !strings.Contains(err.Error(), "another process") && !strings.Contains(err.Error(), "logged out") {
		// Disable produces "session is logged out" on subsequent Check; first
		// error is the epoch message.
		if !strings.Contains(err.Error(), "invalidated") && !strings.Contains(err.Error(), "logged out") {
			t.Fatalf("unexpected message: %v", err)
		}
	}
	// Guard disabled; subsequent Check fails without re-reading epoch.
	if err := guard.Check(); err == nil {
		t.Fatal("guard must be disabled after epoch invalidation")
	}
	// Memory cleared: Authenticate alone must fail (keyring empty).
	_, err = serveProv.Authenticate(ctx, auth.Profile{ID: "corp"})
	if err == nil {
		t.Fatal("authenticate after logout+clear must fail")
	}
	if strings.Contains(err.Error(), epochTokenCanary) {
		t.Fatalf("canary in auth error: %v", err)
	}

	// Epoch file still free of token canary.
	raw, err := os.ReadFile(epochStore.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), epochTokenCanary) {
		t.Fatalf("token canary in epoch file: %q", raw)
	}
}

func TestSessionEpochWatcher_UnchangedOK(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := &auth.SessionEpochStore{Dir: dir}
	if _, err := store.Bump(); err != nil {
		t.Fatal(err)
	}
	w := &auth.SessionEpochWatcher{Store: store}
	if err := w.Bind(); err != nil {
		t.Fatal(err)
	}
	if err := w.Check(); err != nil {
		t.Fatal(err)
	}
	changed, err := w.Changed()
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
}

func TestSessionEpochWatcher_NilSafe(t *testing.T) {
	t.Parallel()
	var w *auth.SessionEpochWatcher
	if err := w.Bind(); err != nil {
		t.Fatal(err)
	}
	if err := w.Check(); err != nil {
		t.Fatal(err)
	}
	w2 := &auth.SessionEpochWatcher{}
	if err := w2.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestLiveSessionSource_EpochChangeDisablesWithoutNetwork(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	epochStore := &auth.SessionEpochStore{Dir: dir}
	if _, err := epochStore.Bump(); err != nil {
		t.Fatal(err)
	}
	mem := auth.NewMemoryTokenStore()
	oidc := auth.NewOIDCProviderWithStore(mem, nil)
	ctx := context.Background()
	// Do not attach Epoch to oidc — avoid double-bump on StoreTokens.
	if err := oidc.StoreTokens(ctx, "corp", auth.TokenBundle{
		AccessToken: "valid-access-not-canary-short",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	// After StoreTokens without Epoch field, re-bind watcher to current file.
	// (StoreTokens with nil Epoch does not bump.)
	w := &auth.SessionEpochWatcher{Store: epochStore}
	if err := w.Bind(); err != nil {
		t.Fatal(err)
	}
	guard := auth.NewSessionGuard("fp")
	src := &auth.LiveSessionSource{
		OIDC:    oidc,
		Profile: auth.Profile{ID: "corp"},
		Guard:   guard,
		Epoch:   w,
	}
	if _, err := src.Credentials(ctx); err != nil {
		t.Fatal(err)
	}
	// External logout bump.
	if _, err := epochStore.Bump(); err != nil {
		t.Fatal(err)
	}
	_, err := src.Credentials(ctx)
	if err == nil {
		t.Fatal("expected epoch invalidation")
	}
	if strings.Contains(err.Error(), "valid-access") {
		t.Fatalf("secret in error: %v", err)
	}
	if err := guard.Check(); err == nil {
		t.Fatal("guard disabled")
	}
}

// AuthGate path: LiveSessionSource.Check sees epoch bump without Credentials().
func TestLiveSessionSource_CheckAsAuthGate_EpochInvalidation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	epochStore := &auth.SessionEpochStore{Dir: dir}
	if _, err := epochStore.Bump(); err != nil {
		t.Fatal(err)
	}
	w := &auth.SessionEpochWatcher{Store: epochStore}
	if err := w.Bind(); err != nil {
		t.Fatal(err)
	}
	guard := auth.NewSessionGuard("fp-gate")
	src := &auth.LiveSessionSource{
		OIDC:    auth.NewOIDCProviderWithStore(auth.NewMemoryTokenStore(), nil),
		Profile: auth.Profile{ID: "corp"},
		Guard:   guard,
		Epoch:   w,
	}
	if err := src.Check(); err != nil {
		t.Fatal(err)
	}
	if _, err := epochStore.Bump(); err != nil {
		t.Fatal(err)
	}
	if err := src.Check(); err == nil {
		t.Fatal("AuthGate Check must fail closed after epoch bump")
	}
	if err := guard.Check(); err == nil {
		t.Fatal("guard must be disabled after AuthGate epoch check")
	}
	// Second Check still fails (guard disabled) without secret material.
	if err := src.Check(); err == nil {
		t.Fatal("expected continued fail-closed")
	}
}
