package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
)

const identityCanary = "CANARY_TOKEN_identity_verify_must_not_appear_in_errors_ZZZ"

func whoAmIServer(t *testing.T, body string, status int, checkAuth bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jenkins.WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		if checkAuth {
			u, p, ok := r.BasicAuth()
			if !ok || u != "alice" || p != identityCanary {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVerifyIdentitySuccess(t *testing.T) {
	t.Parallel()
	srv := whoAmIServer(t, `{"id":"alice","fullName":"Alice","anonymous":false}`, 0, true)

	pr := auth.Profile{ID: contracts.ProfileID("corp"), URL: srv.URL, User: "alice"}
	sess := auth.Session{ProfileID: pr.ID, Method: auth.MethodAPIToken, User: "alice", Secret: identityCanary}
	p, err := auth.VerifyIdentityHTTP(context.Background(), pr, sess, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "alice" || p.FullName != "Alice" {
		t.Fatalf("%+v", p)
	}
	bound := auth.BindPrincipal(sess, p)
	if bound.Principal.ID != "alice" || bound.User != "alice" {
		t.Fatalf("%+v", bound)
	}
}

func TestVerifyIdentityAnonymousFailsClosed(t *testing.T) {
	t.Parallel()
	srv := whoAmIServer(t, `{"id":"anonymous","fullName":"","anonymous":true}`, 0, false)
	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "alice"}
	sess := auth.Session{User: "alice", Secret: identityCanary}
	_, err := auth.VerifyIdentityHTTP(context.Background(), pr, sess, srv.Client())
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), identityCanary) {
		t.Fatalf("token leaked: %v", err)
	}
}

func TestVerifyIdentityMismatchFailsClosed(t *testing.T) {
	t.Parallel()
	// Regression: renamed / unexpected principal must not bind the process session.
	srv := whoAmIServer(t, `{"id":"bob","fullName":"Bob","anonymous":false}`, 0, false)
	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "alice"}
	sess := auth.Session{User: "alice", Secret: identityCanary}
	_, err := auth.VerifyIdentityHTTP(context.Background(), pr, sess, srv.Client())
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), identityCanary) {
		t.Fatalf("token leaked: %v", err)
	}
}

func TestVerifyIdentityHTTPErrorSecretCanary(t *testing.T) {
	t.Parallel()
	srv := whoAmIServer(t, "nope "+identityCanary, http.StatusUnauthorized, false)
	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "alice"}
	sess := auth.Session{User: "alice", Secret: identityCanary}
	_, err := auth.VerifyIdentityHTTP(context.Background(), pr, sess, srv.Client())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), identityCanary) {
		t.Fatalf("token leaked: %v", err)
	}
	msg := apperr.ModelMessage(err)
	if strings.Contains(msg, identityCanary) {
		t.Fatalf("token in model message: %s", msg)
	}
}

func TestVerifyIdentityMissingOptionalFullName(t *testing.T) {
	t.Parallel()
	srv := whoAmIServer(t, `{"id":"alice","anonymous":false}`, 0, false)
	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "alice"}
	sess := auth.Session{User: "alice", Secret: identityCanary}
	p, err := auth.VerifyIdentityHTTP(context.Background(), pr, sess, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "alice" || p.FullName != "" {
		t.Fatalf("%+v", p)
	}
}

func TestVerifyIdentityCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := auth.VerifyIdentity(ctx, auth.Profile{URL: "http://127.0.0.1:9", User: "a"},
		auth.Session{User: "a", Secret: "x"})
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("got %v", err)
	}
}

func TestPrincipalFromWhoAmI(t *testing.T) {
	t.Parallel()
	_, err := auth.PrincipalFromWhoAmI(jenkins.WhoAmI{ID: "", Anonymous: false})
	if err == nil {
		t.Fatal("empty id")
	}
	_, err = auth.PrincipalFromWhoAmI(jenkins.WhoAmI{ID: "anonymous", Anonymous: false})
	if err == nil {
		t.Fatal("anonymous id string")
	}
	p, err := auth.PrincipalFromWhoAmI(jenkins.WhoAmI{ID: "Alice", FullName: "A Lice", Anonymous: false})
	if err != nil || p.ID != "Alice" {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestIdentityCacheTTL(t *testing.T) {
	t.Parallel()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"id":"alice","fullName":"Alice","anonymous":false}`))
	}))
	t.Cleanup(srv.Close)
	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "alice"}
	sess := auth.Session{User: "alice", Secret: identityCanary}
	cache := auth.NewIdentityCache(time.Hour)

	p1, err := auth.VerifyIdentityCachedHTTP(context.Background(), pr, sess, cache, srv.Client())
	if err != nil || p1.ID != "alice" {
		t.Fatalf("%+v %v", p1, err)
	}
	p2, err := auth.VerifyIdentityCachedHTTP(context.Background(), pr, sess, cache, srv.Client())
	if err != nil || p2.ID != "alice" {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected single whoAmI call, got %d", calls)
	}
	cache.Invalidate()
	_, err = auth.VerifyIdentityCachedHTTP(context.Background(), pr, sess, cache, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected re-verify after invalidate, got %d", calls)
	}
}

// Wave 24 AUTH-004: ParseIdentityReverifyTTL bounds and precedence (fail closed).
func TestParseIdentityReverifyTTL(t *testing.T) {
	t.Parallel()

	t.Run("unset_defaults_5m", func(t *testing.T) {
		t.Parallel()
		d, err := auth.ParseIdentityReverifyTTL("", "")
		if err != nil {
			t.Fatal(err)
		}
		if d != auth.DefaultIdentityCacheTTL {
			t.Fatalf("got %v want %v", d, auth.DefaultIdentityCacheTTL)
		}
	})

	t.Run("zero_defaults_5m", func(t *testing.T) {
		t.Parallel()
		for _, raw := range []string{"0", "0s", "0m"} {
			d, err := auth.ParseIdentityReverifyTTL(raw, "1h") // flag wins over bad env
			if err != nil {
				t.Fatalf("%q: %v", raw, err)
			}
			if d != auth.DefaultIdentityCacheTTL {
				t.Fatalf("%q: got %v want default", raw, d)
			}
		}
		// Env-only zero.
		d, err := auth.ParseIdentityReverifyTTL("", "0s")
		if err != nil {
			t.Fatal(err)
		}
		if d != auth.DefaultIdentityCacheTTL {
			t.Fatalf("env zero: got %v", d)
		}
	})

	t.Run("flag_overrides_env", func(t *testing.T) {
		t.Parallel()
		d, err := auth.ParseIdentityReverifyTTL("30s", "10m")
		if err != nil {
			t.Fatal(err)
		}
		if d != 30*time.Second {
			t.Fatalf("got %v want 30s", d)
		}
	})

	t.Run("env_when_flag_empty", func(t *testing.T) {
		t.Parallel()
		d, err := auth.ParseIdentityReverifyTTL("", "1m")
		if err != nil {
			t.Fatal(err)
		}
		if d != time.Minute {
			t.Fatalf("got %v want 1m", d)
		}
	})

	t.Run("min_and_max_ok", func(t *testing.T) {
		t.Parallel()
		d, err := auth.ParseIdentityReverifyTTL(auth.MinIdentityReverifyTTL.String(), "")
		if err != nil || d != auth.MinIdentityReverifyTTL {
			t.Fatalf("min: %v %v", d, err)
		}
		d, err = auth.ParseIdentityReverifyTTL(auth.MaxIdentityReverifyTTL.String(), "")
		if err != nil || d != auth.MaxIdentityReverifyTTL {
			t.Fatalf("max: %v %v", d, err)
		}
	})

	t.Run("below_min_fail_closed", func(t *testing.T) {
		t.Parallel()
		_, err := auth.ParseIdentityReverifyTTL("9s", "")
		if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("want invalid, got %v", err)
		}
		if !strings.Contains(err.Error(), "minimum") {
			t.Fatalf("msg: %v", err)
		}
	})

	t.Run("above_max_fail_closed", func(t *testing.T) {
		t.Parallel()
		_, err := auth.ParseIdentityReverifyTTL("", "31m")
		if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("want invalid, got %v", err)
		}
		if !strings.Contains(err.Error(), "maximum") {
			t.Fatalf("msg: %v", err)
		}
	})

	t.Run("unparseable_fail_closed", func(t *testing.T) {
		t.Parallel()
		_, err := auth.ParseIdentityReverifyTTL("not-a-duration", "")
		if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("want invalid, got %v", err)
		}
		_, err = auth.ParseIdentityReverifyTTL("", "5")
		if err == nil {
			t.Fatal("bare number without unit must fail")
		}
	})

	t.Run("negative_fail_closed", func(t *testing.T) {
		t.Parallel()
		_, err := auth.ParseIdentityReverifyTTL("-1m", "")
		if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("want invalid, got %v", err)
		}
	})

	t.Run("whitespace_treated_as_unset", func(t *testing.T) {
		t.Parallel()
		d, err := auth.ParseIdentityReverifyTTL("  ", "  ")
		if err != nil || d != auth.DefaultIdentityCacheTTL {
			t.Fatalf("got %v %v", d, err)
		}
	})
}

// Wave 24: shorter configured TTL expires before a longer one (clock inject).
func TestIdentityCache_ShorterTTLExpiresSooner(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}

	short := auth.NewIdentityCache(30 * time.Second).WithNow(clock)
	long := auth.NewIdentityCache(5 * time.Minute).WithNow(clock)
	short.Set(auth.Principal{ID: "alice"})
	long.Set(auth.Principal{ID: "alice"})

	// Still fresh for both at t+20s.
	mu.Lock()
	now = now.Add(20 * time.Second)
	mu.Unlock()
	if _, ok := short.Get(); !ok {
		t.Fatal("short TTL must still be fresh at 20s")
	}
	if _, ok := long.Get(); !ok {
		t.Fatal("long TTL must still be fresh at 20s")
	}

	// At t+31s short expired; long still fresh.
	mu.Lock()
	now = now.Add(11 * time.Second) // total +31s from set
	mu.Unlock()
	if _, ok := short.Get(); ok {
		t.Fatal("short 30s TTL must expire by 31s")
	}
	if _, ok := long.Get(); !ok {
		t.Fatal("long 5m TTL must still be fresh at 31s")
	}
}

func TestVerifyIdentityCaseInsensitiveUserMatch(t *testing.T) {
	t.Parallel()
	srv := whoAmIServer(t, `{"id":"Alice","fullName":"Alice","anonymous":false}`, 0, false)
	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "alice"}
	sess := auth.Session{User: "alice", Secret: identityCanary}
	p, err := auth.VerifyIdentityHTTP(context.Background(), pr, sess, srv.Client())
	if err != nil || p.ID != "Alice" {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestLoginVerifyThenStoreDoesNotKeepBadToken(t *testing.T) {
	t.Parallel()
	// Regression: failed verification must not leave a keyring credential.
	srv := whoAmIServer(t, `{"id":"anonymous","anonymous":true}`, 0, false)
	p := auth.NewAPITokenProvider(keyring.NewStore(keyring.NewMemory()))
	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "alice"}
	sess := auth.Session{User: "alice", Secret: identityCanary}
	_, err := auth.VerifyIdentityHTTP(context.Background(), pr, sess, srv.Client())
	if err == nil {
		t.Fatal("expected verify failure")
	}
	// Simulate login path: only StoreAPIToken after success — so no store here.
	_, err = p.Authenticate(context.Background(), pr)
	if err == nil {
		t.Fatal("credential must not exist after failed verify-before-store")
	}
	if strings.Contains(err.Error(), identityCanary) {
		t.Fatalf("token leaked: %v", err)
	}
}

func TestVerifyIdentity_OIDCBearer(t *testing.T) {
	t.Parallel()
	// Regression (OAUTH-005): OIDC sessions must use Bearer, not Basic.
	const bearer = "CANARY_OIDC_BEARER_identity_ZZZ"
	var sawAuth string
	var sawBasic bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jenkins.WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		sawAuth = r.Header.Get("Authorization")
		if _, _, ok := r.BasicAuth(); ok {
			sawBasic = true
		}
		if sawAuth != "Bearer "+bearer {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice","fullName":"Alice","anonymous":false}`))
	}))
	t.Cleanup(srv.Close)

	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "alice"}
	sess := auth.Session{
		ProfileID: pr.ID,
		Method:    auth.MethodOIDC,
		User:      "alice",
		Secret:    bearer,
	}
	p, err := auth.VerifyIdentityHTTP(context.Background(), pr, sess, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "alice" {
		t.Fatalf("%+v", p)
	}
	if sawBasic {
		t.Fatal("OIDC whoAmI must not use Basic")
	}
	if sawAuth != "Bearer "+bearer {
		t.Fatalf("auth=%q", sawAuth)
	}
}

func TestVerifyIdentity_OIDCBearer_SecretCanary(t *testing.T) {
	t.Parallel()
	const bearer = "CANARY_OIDC_BEARER_fail_ZZZ"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad " + bearer))
	}))
	t.Cleanup(srv.Close)
	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "alice"}
	sess := auth.Session{Method: auth.MethodOIDC, User: "alice", Secret: bearer}
	_, err := auth.VerifyIdentityHTTP(context.Background(), pr, sess, srv.Client())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), bearer) {
		t.Fatalf("token leaked: %v", err)
	}
}
