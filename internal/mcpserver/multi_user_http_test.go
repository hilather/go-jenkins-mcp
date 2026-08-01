package mcpserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// HOST multi-user Streamable HTTP contract: RequireSubject + LabIdentity +
// AfterIdentity injects gateway.Caller + policy.Subject; mock next hop (simulating
// AuthProviderCtx / tool SubjectFromContext) sees Alice then Bob on independent
// sessions; mid-session subject swap on the same Mcp-Session-Id still 401s;
// 401 bodies never echo transport secrets or subjects.
//
// tools/call JSON-RPC multi-user e2e (session-scoped Connect context + Mode A
// AuthProviderCtx) lives in multi_user_tools_call_test.go. These tests prove
// protectHandler → next hop context flow (the boundary serve wires via
// AfterIdentity + AuthProviderCtx / PolicySubjectFromContext).

const multiUserCanaryToken = "mu-http-canary-token-xyz-never-echo"

// multiUserAfterIdentity mirrors cmd/jenkins-mcp serve multi-user AfterIdentity:
// map trusted RequestIdentity → Caller + policy.Subject on the request context.
func multiUserAfterIdentity(
	defaultCaller gateway.Caller,
	processSubject policy.Subject,
	profileID contracts.ProfileID,
) func(ctx context.Context, id mcpserver.RequestIdentity) context.Context {
	return func(ctx context.Context, id mcpserver.RequestIdentity) context.Context {
		in := gateway.HTTPInbound{
			ExternalSubject:  id.ExternalSubject,
			Tenant:           id.Tenant,
			WorkloadID:       id.WorkloadID,
			JenkinsPrincipal: id.JenkinsPrincipal,
			Source:           string(id.Source),
			Verified:         id.Verified,
		}
		c := gateway.MergeCallerDefaults(gateway.CallerFromHTTPInbound(in, profileID), defaultCaller)
		ps := gateway.PolicySubjectFromHTTPInbound(in, profileID, processSubject)
		return gateway.ContextWithCallerAndPolicySubject(ctx, c, ps)
	}
}

type multiUserSeen struct {
	mu       sync.Mutex
	callers  []gateway.Caller
	subjects []policy.Subject
	ids      []mcpserver.RequestIdentity
}

func (s *multiUserSeen) record(ctx context.Context) {
	id := mcpserver.IdentityFromContext(ctx)
	c, _ := gateway.CallerFromContext(ctx)
	ps, _ := gateway.PolicySubjectFromContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ids = append(s.ids, id)
	s.callers = append(s.callers, c)
	s.subjects = append(s.subjects, ps)
}

func (s *multiUserSeen) snapshot() (ids []mcpserver.RequestIdentity, callers []gateway.Caller, subjects []policy.Subject) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids = append([]mcpserver.RequestIdentity(nil), s.ids...)
	callers = append([]gateway.Caller(nil), s.callers...)
	subjects = append([]policy.Subject(nil), s.subjects...)
	return ids, callers, subjects
}

// mockInner asserts multi-user context values (CallerFromContext + PolicySubject
// + RequestIdentity) then returns 200. Simulates AuthProviderCtx / tool path
// reading the HTTP request context after protectHandler AfterIdentity.
func multiUserMockInner(t *testing.T, seen *multiUserSeen) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		seen.record(r.Context())
		// Simulated AuthProviderCtx path: require CallerFromContext Valid.
		c, ok := gateway.CallerFromContext(r.Context())
		if !ok || !c.Valid() {
			http.Error(w, "missing caller", http.StatusInternalServerError)
			return
		}
		ps, okPS := gateway.PolicySubjectFromContext(r.Context())
		if !okPS || strings.TrimSpace(ps.ExternalSubject) == "" {
			http.Error(w, "missing policy subject", http.StatusInternalServerError)
			return
		}
		if !mcpserver.IdentityFromContext(r.Context()).Present() {
			http.Error(w, "missing identity", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}` + "\n"))
	})
}

func multiUserProtectCfg(t *testing.T, after func(context.Context, mcpserver.RequestIdentity) context.Context) mcpserver.HTTPConfig {
	t.Helper()
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	cfg.BearerToken = multiUserCanaryToken
	// Multi-user: no ExpectedExternalSubject pin.
	cfg.ExpectedExternalSubject = ""
	cfg.AfterIdentity = after
	return cfg
}

func multiUserPost(t *testing.T, h http.Handler, sessionID, subject, tenant, jenkinsPrincipal string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{}`))
	req.Host = "127.0.0.1:8765"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+multiUserCanaryToken)
	if sessionID != "" {
		req.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
	}
	req.Header.Set(mcpserver.HeaderLabSubject, subject)
	if tenant != "" {
		req.Header.Set(mcpserver.HeaderLabTenant, tenant)
	}
	if jenkinsPrincipal != "" {
		req.Header.Set(mcpserver.HeaderLabJenkinsPrincipal, jenkinsPrincipal)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func assertNoSecretOrSubjectLeak(t *testing.T, body string, subjects ...string) {
	t.Helper()
	if strings.Contains(body, multiUserCanaryToken) {
		t.Fatalf("Regression: canary transport secret leaked in body: %s", body)
	}
	if strings.Contains(body, "Bearer ") {
		t.Fatalf("Regression: Bearer material in body: %s", body)
	}
	for _, s := range subjects {
		if s != "" && strings.Contains(body, s) {
			t.Fatalf("Regression: subject %q leaked in body: %s", s, body)
		}
	}
}

// End-to-end protect layer: Alice then Bob on different sessions; mock inner
// (AuthProviderCtx stand-in) sees matching Caller + policy.Subject each time.
func TestMultiUserHTTP_AliceBobIndependentSessions_ContextFlow(t *testing.T) {
	t.Parallel()

	defaultCaller := gateway.Caller{
		Subject:   "process-default",
		Tenant:    "tid-default",
		ProfileID: contracts.ProfileID("corp"),
	}
	processSubject := policy.Subject{
		ProfileID:       contracts.ProfileID("corp"),
		JenkinsUserID:   "process-j",
		ExternalSubject: "process-default",
		Tenant:          "tid-default",
		Verified:        true,
	}
	after := multiUserAfterIdentity(defaultCaller, processSubject, contracts.ProfileID("corp"))

	var seen multiUserSeen
	h, err := mcpserver.NewHTTPProtectHandler(multiUserMockInner(t, &seen), multiUserProtectCfg(t, after))
	if err != nil {
		t.Fatal(err)
	}

	// Session A: Alice.
	rrA := multiUserPost(t, h, "sess-alice", "alice", "tid-a", "j-alice")
	if rrA.Code != http.StatusOK {
		t.Fatalf("alice want 200, got %d body=%s", rrA.Code, rrA.Body.String())
	}
	assertNoSecretOrSubjectLeak(t, rrA.Body.String())

	// Session B: Bob (independent; same process, no pin).
	rrB := multiUserPost(t, h, "sess-bob", "bob", "tid-b", "j-bob")
	if rrB.Code != http.StatusOK {
		t.Fatalf("bob want 200, got %d body=%s", rrB.Code, rrB.Body.String())
	}

	ids, callers, subjects := seen.snapshot()
	if len(callers) != 2 || len(subjects) != 2 || len(ids) != 2 {
		t.Fatalf("hits: ids=%d callers=%d subjects=%d want 2 each", len(ids), len(callers), len(subjects))
	}

	// Alice hop.
	if ids[0].ExternalSubject != "alice" || !ids[0].Verified {
		t.Fatalf("alice identity: %+v", ids[0])
	}
	if callers[0].Subject != "alice" || callers[0].Tenant != "tid-a" || string(callers[0].ProfileID) != "corp" {
		t.Fatalf("alice caller: %+v", callers[0])
	}
	if !callers[0].Valid() {
		t.Fatal("alice caller must be Valid for AuthProviderCtx Obtain")
	}
	if subjects[0].ExternalSubject != "alice" || subjects[0].JenkinsUserID != "j-alice" {
		t.Fatalf("alice policy subject: %+v", subjects[0])
	}
	if !subjects[0].Verified { // lab verified + jenkins principal present
		t.Fatalf("alice policy subject Verified want true: %+v", subjects[0])
	}
	// Must not inherit process Jenkins principal when lab principal present.
	if subjects[0].JenkinsUserID == "process-j" {
		t.Fatal("alice must not use process Jenkins principal")
	}

	// Bob hop — different session, rebind identity (no cross-session pin).
	if ids[1].ExternalSubject != "bob" {
		t.Fatalf("bob identity: %+v", ids[1])
	}
	if callers[1].Subject != "bob" || callers[1].Tenant != "tid-b" {
		t.Fatalf("bob caller: %+v", callers[1])
	}
	if subjects[1].ExternalSubject != "bob" || subjects[1].JenkinsUserID != "j-bob" {
		t.Fatalf("bob policy subject: %+v", subjects[1])
	}
	if callers[0].Subject == callers[1].Subject {
		t.Fatal("Alice and Bob callers must differ")
	}
	if subjects[0].JenkinsUserID == subjects[1].JenkinsUserID {
		t.Fatal("Alice and Bob policy subjects must differ")
	}
}

// Same session id: Alice establishes fingerprint; Bob mid-session swap → 401;
// mock inner never sees Bob; canary-free 401 body.
func TestMultiUserHTTP_MidSessionSubjectSwap_401Canary(t *testing.T) {
	t.Parallel()

	defaultCaller := gateway.Caller{
		Subject:   "process-default",
		ProfileID: contracts.ProfileID("corp"),
	}
	processSubject := policy.Subject{
		ProfileID: contracts.ProfileID("corp"),
	}
	after := multiUserAfterIdentity(defaultCaller, processSubject, contracts.ProfileID("corp"))

	var seen multiUserSeen
	h, err := mcpserver.NewHTTPProtectHandler(multiUserMockInner(t, &seen), multiUserProtectCfg(t, after))
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "sess-mu-mid-swap"

	rrAlice := multiUserPost(t, h, sessionID, "alice", "tid-a", "j-alice")
	if rrAlice.Code != http.StatusOK {
		t.Fatalf("alice establish: want 200, got %d body=%s", rrAlice.Code, rrAlice.Body.String())
	}

	// Same subject rebind OK.
	rrSame := multiUserPost(t, h, sessionID, "alice", "tid-a", "j-alice")
	if rrSame.Code != http.StatusOK {
		t.Fatalf("alice rebind: want 200, got %d body=%s", rrSame.Code, rrSame.Body.String())
	}

	// Bob on Alice's session → fail closed before AfterIdentity / inner.
	rrSwap := multiUserPost(t, h, sessionID, "bob", "tid-a", "j-bob")
	if rrSwap.Code != http.StatusUnauthorized {
		t.Fatalf("Regression: mid-session subject swap must 401, got %d body=%s",
			rrSwap.Code, rrSwap.Body.String())
	}
	assertNoSecretOrSubjectLeak(t, rrSwap.Body.String(), "alice", "bob", "j-alice", "j-bob")

	ids, callers, _ := seen.snapshot()
	// Only Alice hops reached the mock inner (establish + same-subject).
	for _, id := range ids {
		if id.ExternalSubject == "bob" {
			t.Fatal("Regression: Bob must not reach next hop after session fingerprint fail")
		}
	}
	for _, c := range callers {
		if c.Subject == "bob" {
			t.Fatal("Regression: Bob Caller must not reach AuthProviderCtx stand-in")
		}
	}
	if len(callers) < 2 {
		t.Fatalf("want at least two Alice inner hits, got %d", len(callers))
	}
}

// RequireSubject without lab subject: 401 even with transport secret; no leak.
func TestMultiUserHTTP_RequireSubject_SecretAlone401Canary(t *testing.T) {
	t.Parallel()

	defaultCaller := gateway.Caller{
		Subject:   "process-default",
		ProfileID: contracts.ProfileID("corp"),
	}
	after := multiUserAfterIdentity(defaultCaller, policy.Subject{ProfileID: "corp"}, "corp")

	var seen multiUserSeen
	h, err := mcpserver.NewHTTPProtectHandler(multiUserMockInner(t, &seen), multiUserProtectCfg(t, after))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{}`))
	req.Host = "127.0.0.1:8765"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+multiUserCanaryToken)
	req.Header.Set(mcpserver.HeaderMCPSessionID, "sess-no-subject")
	// LabIdentity is on but no lab subject header → Present() false → 401.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without subject, got %d body=%s", rr.Code, rr.Body.String())
	}
	assertNoSecretOrSubjectLeak(t, rr.Body.String())

	if ids, callers, _ := seen.snapshot(); len(ids) != 0 || len(callers) != 0 {
		t.Fatalf("inner must not run without subject: ids=%d callers=%d", len(ids), len(callers))
	}
}

// Simulated AuthProviderCtx reads CallerFromContext from the request context
// produced by AfterIdentity (Alice then Bob sequential, same handler instance).
func TestMultiUserHTTP_SimulatedAuthProviderCtx_AliceThenBob(t *testing.T) {
	t.Parallel()

	defaultCaller := gateway.Caller{
		Subject:   "process-default",
		Tenant:    "tid-default",
		ProfileID: contracts.ProfileID("corp"),
	}
	processSubject := policy.Subject{
		ProfileID: contracts.ProfileID("corp"),
		Tenant:    "tid-default",
	}
	after := multiUserAfterIdentity(defaultCaller, processSubject, contracts.ProfileID("corp"))

	// Capture Obtain keys the way AuthProviderCtx would via CallerFromContext.
	var obtainKeys []string
	var mu sync.Mutex
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := gateway.CallerFromContext(r.Context())
		if !ok || !c.Valid() {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Merge defaults like attachGatewayObtainAuthProviderDynamic.
		caller := gateway.MergeCallerDefaults(c, defaultCaller)
		mu.Lock()
		obtainKeys = append(obtainKeys, caller.SubjectKey())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	})

	h, err := mcpserver.NewHTTPProtectHandler(inner, multiUserProtectCfg(t, after))
	if err != nil {
		t.Fatal(err)
	}

	if rr := multiUserPost(t, h, "s1", "alice", "tid-a", "j-alice"); rr.Code != http.StatusOK {
		t.Fatalf("alice: %d %s", rr.Code, rr.Body.String())
	}
	if rr := multiUserPost(t, h, "s2", "bob", "tid-b", "j-bob"); rr.Code != http.StatusOK {
		t.Fatalf("bob: %d %s", rr.Code, rr.Body.String())
	}

	mu.Lock()
	keys := append([]string(nil), obtainKeys...)
	mu.Unlock()
	if len(keys) != 2 {
		t.Fatalf("obtain keys=%v want alice+bob", keys)
	}
	if keys[0] == keys[1] {
		t.Fatalf("Alice and Bob SubjectKey must differ: %v", keys)
	}
	if !strings.Contains(keys[0], "alice") || !strings.Contains(keys[1], "bob") {
		t.Fatalf("keys=%v want alice then bob subject material", keys)
	}
	// Cross-check SubjectKey isolation (HOST-004 namespace).
	aliceKey := gateway.SubjectKey(gateway.Caller{
		Subject: "alice", Tenant: "tid-a", ProfileID: "corp",
	})
	bobKey := gateway.SubjectKey(gateway.Caller{
		Subject: "bob", Tenant: "tid-b", ProfileID: "corp",
	})
	if keys[0] != aliceKey || keys[1] != bobKey {
		t.Fatalf("keys=%v want %q then %q", keys, aliceKey, bobKey)
	}
}

// NewHTTPHandler (SDK inner) still runs AfterIdentity for multi-user subjects;
// session independence + swap fail-closed at protect layer. Full tools/call
// context propagation is covered in multi_user_tools_call_test.go.
func TestMultiUserHTTP_NewHTTPHandler_SDKInner_AfterIdentityAndSwap(t *testing.T) {
	t.Parallel()

	defaultCaller := gateway.Caller{
		Subject:   "process-default",
		ProfileID: contracts.ProfileID("corp"),
	}
	var afterSubjects []string
	var mu sync.Mutex
	cfg := multiUserProtectCfg(t, multiUserAfterIdentity(defaultCaller, policy.Subject{ProfileID: "corp"}, "corp"))
	// Wrap to also record subjects while still injecting Caller/PolicySubject.
	baseAfter := cfg.AfterIdentity
	cfg.AfterIdentity = func(ctx context.Context, id mcpserver.RequestIdentity) context.Context {
		mu.Lock()
		afterSubjects = append(afterSubjects, id.ExternalSubject)
		mu.Unlock()
		return baseAfter(ctx, id)
	}

	srv := mcpserver.NewServer("test", "0.0.1")
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}

	rrA := multiUserPost(t, h, "sdk-sess-a", "alice", "tid-a", "j-alice")
	if rrA.Code == http.StatusUnauthorized {
		t.Fatalf("alice must pass protect: %s", rrA.Body.String())
	}
	rrB := multiUserPost(t, h, "sdk-sess-b", "bob", "tid-b", "j-bob")
	if rrB.Code == http.StatusUnauthorized {
		t.Fatalf("bob must pass protect: %s", rrB.Body.String())
	}
	// Same session swap still 401 under full NewHTTPHandler.
	rrSwap := multiUserPost(t, h, "sdk-sess-a", "bob", "tid-b", "j-bob")
	if rrSwap.Code != http.StatusUnauthorized {
		t.Fatalf("Regression: SDK path mid-session swap want 401, got %d body=%s",
			rrSwap.Code, rrSwap.Body.String())
	}
	assertNoSecretOrSubjectLeak(t, rrSwap.Body.String(), "alice", "bob")

	mu.Lock()
	got := append([]string(nil), afterSubjects...)
	mu.Unlock()
	foundA, foundB := false, false
	for _, s := range got {
		if s == "alice" {
			foundA = true
		}
		if s == "bob" {
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Fatalf("AfterIdentity subjects=%v want alice and bob", got)
	}
}

// Nil inner fails closed (API contract for NewHTTPProtectHandler).
func TestNewHTTPProtectHandler_NilInner(t *testing.T) {
	t.Parallel()
	cfg := mcpserver.DefaultHTTPConfig()
	if _, err := mcpserver.NewHTTPProtectHandler(nil, cfg); err == nil {
		t.Fatal("nil inner must fail")
	}
}
