package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

const reverifyCanary = "CANARY_TOKEN_reverify_must_not_appear_ZZZ"

func reverifyWhoAmIServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func fixedSession(user, secret string, method auth.Method) func(context.Context) (auth.Session, error) {
	return func(ctx context.Context) (auth.Session, error) {
		if err := ctx.Err(); err != nil {
			return auth.Session{}, err
		}
		return auth.Session{User: user, Secret: secret, Method: method}, nil
	}
}

// Regression: cache hit within TTL must not trigger a second whoAmI.
func TestIdentityReverifyGate_CacheHitNoSecondWhoAmI(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := reverifyWhoAmIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jenkins.WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice","fullName":"Alice","anonymous":false}`))
	})

	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "alice"}
	sess := auth.Session{User: "alice", Secret: reverifyCanary, Method: auth.MethodAPIToken}
	cache := auth.NewIdentityCache(time.Hour)
	// Populate as serve-start does.
	p, err := auth.VerifyIdentityCachedHTTP(context.Background(), pr, sess, cache, srv.Client())
	if err != nil || p.ID != "alice" {
		t.Fatalf("%+v %v", p, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("setup whoAmI calls=%d", calls.Load())
	}

	gate := auth.NewIdentityReverifyGate(auth.IdentityReverifyConfig{
		Profile:          pr,
		Session:          fixedSession("alice", reverifyCanary, auth.MethodAPIToken),
		Cache:            cache,
		HTTP:             srv.Client(),
		BoundPrincipalID: "alice",
	})
	if err := gate.Check(); err != nil {
		t.Fatal(err)
	}
	if err := gate.Check(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("cache hit must not re-call whoAmI; calls=%d", calls.Load())
	}
}

// Regression: TTL expiry triggers a fresh whoAmI re-verify.
func TestIdentityReverifyGate_TTLExpiryReverifies(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := reverifyWhoAmIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jenkins.WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice","anonymous":false}`))
	})

	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}

	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "alice"}
	sess := auth.Session{User: "alice", Secret: reverifyCanary}
	cache := auth.NewIdentityCache(5 * time.Minute).WithNow(clock)
	if _, err := auth.VerifyIdentityCachedHTTP(context.Background(), pr, sess, cache, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}

	gate := auth.NewIdentityReverifyGate(auth.IdentityReverifyConfig{
		Profile:          pr,
		Session:          fixedSession("alice", reverifyCanary, auth.MethodAPIToken),
		Cache:            cache,
		HTTP:             srv.Client(),
		BoundPrincipalID: "alice",
		Now:              clock,
	})
	if err := gate.Check(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("still within TTL: calls=%d", calls.Load())
	}

	mu.Lock()
	now = now.Add(5*time.Minute + time.Second)
	mu.Unlock()

	if err := gate.Check(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("TTL expiry must re-verify; calls=%d", calls.Load())
	}
}

// Wave 24: shorter re-verify TTL triggers whoAmI sooner than default 5m (clock inject).
// Regression: revoked api_token residual window is the configured TTL, not fixed 5m.
func TestIdentityReverifyGate_ShorterTTLReverifiesSooner(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := reverifyWhoAmIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jenkins.WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice","anonymous":false}`))
	})

	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}

	// Operator-configured short TTL (ParseIdentityReverifyTTL would accept 30s).
	const shortTTL = 30 * time.Second
	ttl, err := auth.ParseIdentityReverifyTTL(shortTTL.String(), "")
	if err != nil || ttl != shortTTL {
		t.Fatalf("parse: %v %v", ttl, err)
	}

	pr := auth.Profile{ID: "corp", URL: srv.URL, User: "alice"}
	sess := auth.Session{User: "alice", Secret: reverifyCanary}
	cache := auth.NewIdentityCache(ttl).WithNow(clock)
	if cache.TTL() != shortTTL {
		t.Fatalf("cache TTL=%v want %v", cache.TTL(), shortTTL)
	}
	if _, err := auth.VerifyIdentityCachedHTTP(context.Background(), pr, sess, cache, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("setup calls=%d", calls.Load())
	}

	gate := auth.NewIdentityReverifyGate(auth.IdentityReverifyConfig{
		Profile:          pr,
		Session:          fixedSession("alice", reverifyCanary, auth.MethodAPIToken),
		Cache:            cache,
		HTTP:             srv.Client(),
		BoundPrincipalID: "alice",
		Now:              clock,
	})
	if err := gate.Check(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("within short TTL: calls=%d", calls.Load())
	}

	// Advance past short TTL but well under DefaultIdentityCacheTTL (5m).
	mu.Lock()
	now = now.Add(shortTTL + time.Second)
	mu.Unlock()

	if err := gate.Check(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("short TTL must re-verify before 5m default; calls=%d", calls.Load())
	}
}

// Regression: principal id change fail-closes sticky.
func TestIdentityReverifyGate_PrincipalChangeFailClosed(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := reverifyWhoAmIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jenkins.WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// Credential now maps to a different Jenkins user (token reuse / swap).
		_, _ = w.Write([]byte(`{"id":"bob","anonymous":false}`))
	})

	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}

	// Empty profile/session user labels so VerifyIdentity binds solely to whoAmI
	// (OIDC-style). Gate still enforces serve-time BoundPrincipalID=alice.
	pr := auth.Profile{ID: "corp", URL: srv.URL}
	cache := auth.NewIdentityCache(time.Minute).WithNow(clock)
	cache.Set(auth.Principal{ID: "alice"})

	gate := auth.NewIdentityReverifyGate(auth.IdentityReverifyConfig{
		Profile:          pr,
		Session:          fixedSession("", reverifyCanary, auth.MethodAPIToken),
		Cache:            cache,
		HTTP:             srv.Client(),
		BoundPrincipalID: "alice",
		Now:              clock,
	})
	// Cache hit OK (bound alice still fresh).
	if err := gate.Check(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("cache hit must not whoAmI; calls=%d", calls.Load())
	}

	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()

	err := gate.Check()
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("want auth fail on principal change, got %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "principal") &&
		!strings.Contains(strings.ToLower(err.Error()), "re-authenticate") {
		t.Fatalf("unexpected msg: %v", err)
	}
	if strings.Contains(err.Error(), reverifyCanary) {
		t.Fatalf("token leaked: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one re-verify whoAmI, got %d", calls.Load())
	}
	// Sticky: further checks fail without another whoAmI.
	if err2 := gate.Check(); err2 == nil {
		t.Fatal("expected sticky fail closed")
	}
	if calls.Load() != 1 {
		t.Fatalf("sticky must not re-whoAmI; calls=%d", calls.Load())
	}
}

// Regression: HTTP 401 during re-verify fail-closes (and never leaks token).
func TestIdentityReverifyGate_401FailClosed(t *testing.T) {
	t.Parallel()
	srv := reverifyWhoAmIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jenkins.WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("rejected " + reverifyCanary))
	})

	// Empty cache forces whoAmI on Check.
	cache := auth.NewIdentityCache(time.Hour)
	gate := auth.NewIdentityReverifyGate(auth.IdentityReverifyConfig{
		Profile:          auth.Profile{ID: "corp", URL: srv.URL, User: "alice"},
		Session:          fixedSession("alice", reverifyCanary, auth.MethodAPIToken),
		Cache:            cache,
		HTTP:             srv.Client(),
		BoundPrincipalID: "alice",
	})
	err := gate.Check()
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("want auth fail, got %v", err)
	}
	if strings.Contains(err.Error(), reverifyCanary) {
		t.Fatalf("token leaked: %v", err)
	}
	msg := apperr.ModelMessage(err)
	if strings.Contains(msg, reverifyCanary) {
		t.Fatalf("token in model message: %s", msg)
	}
}

// Wave 28: principal drift emits one auth_fail with identity_principal_drift;
// sticky subsequent Check does not flood; PrincipalID is bound id only.
func TestIdentityReverifyGate_AuditPrincipalDriftOnce(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := reverifyWhoAmIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jenkins.WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// Unexpected principal — must not appear in audit free text.
		_, _ = w.Write([]byte(`{"id":"bob-unexpected","anonymous":false}`))
	})

	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}

	mem := &audit.Memory{}
	pr := auth.Profile{ID: "corp", URL: srv.URL}
	cache := auth.NewIdentityCache(time.Minute).WithNow(clock)
	cache.Set(auth.Principal{ID: "alice"})

	gate := auth.NewIdentityReverifyGate(auth.IdentityReverifyConfig{
		Profile:          pr,
		Session:          fixedSession("", reverifyCanary, auth.MethodAPIToken),
		Cache:            cache,
		HTTP:             srv.Client(),
		BoundPrincipalID: "alice",
		Now:              clock,
		Audit:            mem,
		ProfileID:        "corp",
	})
	// Cache hit OK.
	if err := gate.Check(); err != nil {
		t.Fatal(err)
	}
	if mem.Len() != 0 {
		t.Fatalf("no audit on success; events=%+v", mem.Events())
	}

	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()

	err := gate.Check()
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("want auth fail on principal change, got %v", err)
	}
	// Sticky re-checks must not flood audit.
	for i := 0; i < 5; i++ {
		if err2 := gate.Check(); err2 == nil {
			t.Fatal("expected sticky fail closed")
		}
	}
	evs := mem.Events()
	if len(evs) != 1 {
		t.Fatalf("want exactly one audit event on sticky drift, got %d: %+v", len(evs), evs)
	}
	e := evs[0]
	if e.Type != audit.TypeAuthFail || e.Decision != audit.DecisionFail {
		t.Fatalf("type/decision: %+v", e)
	}
	if e.Action != "identity_reverify" || e.ReasonCode != auth.ReasonIdentityPrincipalDrift {
		t.Fatalf("action/reason: %+v", e)
	}
	if e.PrincipalID != "alice" {
		t.Fatalf("PrincipalID must be bound serve-time id, got %q", e.PrincipalID)
	}
	if e.ProfileID != "corp" {
		t.Fatalf("ProfileID=%q", e.ProfileID)
	}
	// No unexpected principal id, no token canary in any string field.
	for _, s := range []string{e.Type, e.Tool, e.ReasonCode, e.ProfileID, e.PrincipalID, e.Action, e.Decision, e.RequestID, e.TargetHash} {
		if strings.Contains(s, reverifyCanary) {
			t.Fatalf("token canary in audit field %q", s)
		}
		if strings.Contains(strings.ToLower(s), "bob") {
			t.Fatalf("unexpected principal must not appear in audit: %q", s)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("whoAmI calls=%d want 1", calls.Load())
	}
}

// Wave 28: 401 path emits identity_reverify_fail once; further Checks do not flood.
func TestIdentityReverifyGate_Audit401Once(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := reverifyWhoAmIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jenkins.WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("rejected " + reverifyCanary))
	})

	mem := &audit.Memory{}
	// Empty cache forces whoAmI every Check (non-sticky 401 path).
	cache := auth.NewIdentityCache(time.Hour)
	gate := auth.NewIdentityReverifyGate(auth.IdentityReverifyConfig{
		Profile:          auth.Profile{ID: "corp", URL: srv.URL, User: "alice"},
		Session:          fixedSession("alice", reverifyCanary, auth.MethodAPIToken),
		Cache:            cache,
		HTTP:             srv.Client(),
		BoundPrincipalID: "alice",
		Audit:            mem,
		ProfileID:        "corp",
	})
	for i := 0; i < 3; i++ {
		err := gate.Check()
		if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
			t.Fatalf("want auth fail, got %v", err)
		}
		if strings.Contains(err.Error(), reverifyCanary) {
			t.Fatalf("token leaked: %v", err)
		}
	}
	evs := mem.Events()
	if len(evs) != 1 {
		t.Fatalf("want one reverify_fail event, got %d: %+v", len(evs), evs)
	}
	e := evs[0]
	if e.Type != audit.TypeAuthFail || e.ReasonCode != auth.ReasonIdentityReverifyFail {
		t.Fatalf("event=%+v", e)
	}
	if e.Action != "identity_reverify" || e.Decision != audit.DecisionFail {
		t.Fatalf("event=%+v", e)
	}
	if e.PrincipalID != "alice" || e.ProfileID != "corp" {
		t.Fatalf("attribution=%+v", e)
	}
	for _, s := range []string{e.Type, e.Tool, e.ReasonCode, e.ProfileID, e.PrincipalID, e.Action, e.Decision} {
		if strings.Contains(s, reverifyCanary) {
			t.Fatalf("canary in audit field %q", s)
		}
	}
	if calls.Load() < 3 {
		t.Fatalf("expected repeated whoAmI on non-sticky 401; calls=%d", calls.Load())
	}
}

// Wave 28: unbound principal emits identity_unbound once (sticky).
func TestIdentityReverifyGate_AuditUnboundOnce(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	gate := auth.NewIdentityReverifyGate(auth.IdentityReverifyConfig{
		Profile: auth.Profile{ID: "corp", URL: "https://jenkins.example.invalid"},
		Session: fixedSession("alice", reverifyCanary, auth.MethodAPIToken),
		// Empty BoundPrincipalID → fail closed unbound.
		Audit:     mem,
		ProfileID: "corp",
	})
	for i := 0; i < 3; i++ {
		err := gate.Check()
		if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
			t.Fatalf("want unbound auth fail, got %v", err)
		}
	}
	evs := mem.Events()
	if len(evs) != 1 {
		t.Fatalf("want one unbound event, got %d: %+v", len(evs), evs)
	}
	e := evs[0]
	if e.ReasonCode != auth.ReasonIdentityUnbound || e.Type != audit.TypeAuthFail {
		t.Fatalf("event=%+v", e)
	}
	if e.Action != "identity_reverify" || e.Decision != audit.DecisionFail {
		t.Fatalf("event=%+v", e)
	}
	// Bound id empty — PrincipalID may be empty; still no canary.
	for _, s := range []string{e.Type, e.ReasonCode, e.ProfileID, e.PrincipalID, e.Action, e.Decision} {
		if strings.Contains(s, reverifyCanary) {
			t.Fatalf("canary in %q", s)
		}
	}
}

// Wave 28: nil audit sink — no panic, same fail-closed behavior.
func TestIdentityReverifyGate_NilAuditNoPanic(t *testing.T) {
	t.Parallel()
	srv := reverifyWhoAmIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jenkins.WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"bob","anonymous":false}`))
	})

	// Drift path with nil Audit.
	cache := auth.NewIdentityCache(time.Nanosecond) // force miss immediately after set
	// Empty cache → whoAmI returns bob ≠ alice.
	gate := auth.NewIdentityReverifyGate(auth.IdentityReverifyConfig{
		Profile:          auth.Profile{ID: "corp", URL: srv.URL},
		Session:          fixedSession("", reverifyCanary, auth.MethodAPIToken),
		Cache:            cache,
		HTTP:             srv.Client(),
		BoundPrincipalID: "alice",
		// Audit: nil
	})
	err := gate.Check()
	if err == nil {
		t.Fatal("want fail closed on principal drift")
	}
	if err2 := gate.Check(); err2 == nil {
		t.Fatal("want sticky fail closed")
	}

	// 401 path with nil Audit.
	srv401 := reverifyWhoAmIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	gate401 := auth.NewIdentityReverifyGate(auth.IdentityReverifyConfig{
		Profile:          auth.Profile{ID: "corp", URL: srv401.URL, User: "alice"},
		Session:          fixedSession("alice", reverifyCanary, auth.MethodAPIToken),
		Cache:            auth.NewIdentityCache(time.Hour),
		HTTP:             srv401.Client(),
		BoundPrincipalID: "alice",
	})
	if err := gate401.Check(); err == nil {
		t.Fatal("want 401 fail closed")
	}

	// Unbound with nil Audit.
	gateUnbound := auth.NewIdentityReverifyGate(auth.IdentityReverifyConfig{
		Session: fixedSession("alice", reverifyCanary, auth.MethodAPIToken),
	})
	if err := gateUnbound.Check(); err == nil {
		t.Fatal("want unbound fail closed")
	}
}

// MultiGate short-circuits: first gate error prevents later gates from running.
func TestMultiGate_ShortCircuits(t *testing.T) {
	t.Parallel()
	var secondCalls atomic.Int32
	first := &stubGate{err: apperr.New(apperr.CodeAuthentication, "first gate denied")}
	second := &stubGate{onCheck: func() {
		secondCalls.Add(1)
	}}
	m := auth.MultiGates(first, second)
	err := m.Check()
	if err == nil || !strings.Contains(err.Error(), "first gate") {
		t.Fatalf("got %v", err)
	}
	if secondCalls.Load() != 0 {
		t.Fatalf("second gate must not run after short-circuit; calls=%d", secondCalls.Load())
	}

	// All success.
	ok := auth.MultiGates(&stubGate{}, &stubGate{})
	if err := ok.Check(); err != nil {
		t.Fatal(err)
	}

	// Empty / nil fail closed.
	if err := (*auth.MultiGate)(nil).Check(); err == nil {
		t.Fatal("nil multi-gate must fail closed")
	}
	if err := auth.MultiGates().Check(); err == nil {
		t.Fatal("empty multi-gate must fail closed")
	}
}

// MultiGate runs Live-style first then reverify (order preserves epoch-before-whoAmI).
func TestMultiGate_OrderLiveThenReverify(t *testing.T) {
	t.Parallel()
	var order []string
	var mu sync.Mutex
	g1 := &stubGate{onCheck: func() {
		mu.Lock()
		order = append(order, "live")
		mu.Unlock()
	}}
	g2 := &stubGate{onCheck: func() {
		mu.Lock()
		order = append(order, "reverify")
		mu.Unlock()
	}}
	if err := auth.MultiGates(g1, g2).Check(); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "live" || order[1] != "reverify" {
		t.Fatalf("order=%v", order)
	}
}

type stubGate struct {
	err     error
	onCheck func()
}

func (s *stubGate) Check() error {
	if s.onCheck != nil {
		s.onCheck()
	}
	return s.err
}
