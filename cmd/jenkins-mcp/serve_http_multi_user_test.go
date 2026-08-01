package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wire-level HOST multi-user contract (serve shape):
// RequireSubject + LabIdentity → AfterIdentity (same mapping as main serve) →
// mock next hop runs AuthProviderCtx on r.Context() → Alice then Bob tokens,
// no cross-leak; mid-session swap 401 secret-free.
//
// Full MCP tools/call JSON-RPC multi-user e2e (session-scoped Connect context +
// Mode A AuthProviderCtx Alice/Bob isolation) is in
// internal/mcpserver/multi_user_tools_call_test.go. This test proves the
// protectHandler → AuthProviderCtx boundary that serve wires.

const muWireCanary = "MU_WIRE_CANARY_token_never_echo_xyz"

// serveMultiUserAfterIdentity mirrors cmd AfterIdentity in main (gateway multi-user Ready).
func serveMultiUserAfterIdentity(
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

func TestServeHTTPMultiUser_Wire_AliceBobAuthProviderCtx(t *testing.T) {
	t.Parallel()

	alice := host003Caller("alice-mu-wire")
	bob := host003Caller("bob-mu-wire")
	// Distinct tenants so SubjectKey isolation is visible.
	alice.Tenant = "tid-a"
	bob.Tenant = "tid-b"

	const aliceTok = muWireCanary + "-alice"
	const bobTok = muWireCanary + "-bob"
	v := gateway.NewMemoryAPITokenVault()
	if err := v.Put(context.Background(), gateway.SubjectKey(alice), "alice-j", aliceTok); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(context.Background(), gateway.SubjectKey(bob), "bob-j", bobTok); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}

	defaultCaller := gateway.Caller{
		Subject:   "process-default",
		Tenant:    "tid-default",
		ProfileID: contracts.ProfileID("corp"),
	}
	processSubject := policy.Subject{
		ProfileID: contracts.ProfileID("corp"),
		Tenant:    "tid-default",
	}

	// Jenkins client with multi-user AuthProviderCtx (require context Caller).
	var gotUser, gotPass string
	var gotOK bool
	var mu sync.Mutex
	jenkinsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, pw, ok := r.BasicAuth()
		mu.Lock()
		gotUser, gotPass, gotOK = u, pw, ok
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + u + `","anonymous":false,"authenticated":true}`))
	}))
	t.Cleanup(jenkinsSrv.Close)

	jc := &jenkins.Client{
		URL:    jenkinsSrv.URL,
		Client: jenkinsSrv.Client(),
	}
	attachGatewayObtainAuthProviderDynamic(jc, p, defaultCaller, true /* requireContextCaller */)
	clearGatewayLocalSessionCredentials(jc)

	// Next hop after protect: AuthProviderCtx from request context (tool path stand-in).
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, secret, sch, err := jc.AuthProviderCtx(r.Context())
		if err != nil {
			// Never echo secrets; generic failure for contract body canary.
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if sch != jenkins.AuthSchemeBasic || user == "" || secret == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Also require policy.Subject on context (RBAC rebind wire).
		ps, ok := gateway.PolicySubjectFromContext(r.Context())
		if !ok || strings.TrimSpace(ps.ExternalSubject) == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Drive WhoAmI with the same context to prove end-to-end Obtain.
		if _, err := jc.WhoAmI(r.Context()); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"user":"` + user + `"}` + "\n"))
	})

	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	cfg.BearerToken = muWireCanary
	cfg.ExpectedExternalSubject = "" // multi-user: no pin
	cfg.AfterIdentity = serveMultiUserAfterIdentity(defaultCaller, processSubject, contracts.ProfileID("corp"))

	h, err := mcpserver.NewHTTPProtectHandler(inner, cfg)
	if err != nil {
		t.Fatal(err)
	}

	post := func(session, subject, tenant, jenkinsUser string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{}`))
		req.Host = "127.0.0.1:8765"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+muWireCanary)
		req.Header.Set(mcpserver.HeaderMCPSessionID, session)
		req.Header.Set(mcpserver.HeaderLabSubject, subject)
		req.Header.Set(mcpserver.HeaderLabTenant, tenant)
		req.Header.Set(mcpserver.HeaderLabJenkinsPrincipal, jenkinsUser)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// Alice session.
	rrA := post("wire-sess-a", "alice-mu-wire", "tid-a", "alice-j")
	if rrA.Code != http.StatusOK {
		t.Fatalf("alice want 200, got %d body=%s", rrA.Code, rrA.Body.String())
	}
	if !strings.Contains(rrA.Body.String(), "alice-j") {
		t.Fatalf("alice body: %s", rrA.Body.String())
	}
	mu.Lock()
	aUser, aPass, aOK := gotUser, gotPass, gotOK
	mu.Unlock()
	if !aOK || aUser != "alice-j" || aPass != aliceTok {
		t.Fatalf("alice jenkins: ok=%v user=%q pass_ok=%v", aOK, aUser, aPass == aliceTok)
	}
	if aPass == bobTok {
		t.Fatal("cross leak: bob token used for alice")
	}

	// Bob independent session.
	rrB := post("wire-sess-b", "bob-mu-wire", "tid-b", "bob-j")
	if rrB.Code != http.StatusOK {
		t.Fatalf("bob want 200, got %d body=%s", rrB.Code, rrB.Body.String())
	}
	mu.Lock()
	bUser, bPass, bOK := gotUser, gotPass, gotOK
	mu.Unlock()
	if !bOK || bUser != "bob-j" || bPass != bobTok {
		t.Fatalf("bob jenkins: ok=%v user=%q pass_ok=%v", bOK, bUser, bPass == bobTok)
	}
	if bPass == aliceTok {
		t.Fatal("cross leak: alice token used for bob")
	}

	// Mid-session swap on Alice's session → 401; no secrets/subjects in body.
	rrSwap := post("wire-sess-a", "bob-mu-wire", "tid-b", "bob-j")
	if rrSwap.Code != http.StatusUnauthorized {
		t.Fatalf("Regression: mid-session swap want 401, got %d body=%s", rrSwap.Code, rrSwap.Body.String())
	}
	body := rrSwap.Body.String()
	for _, leak := range []string{muWireCanary, aliceTok, bobTok, "alice-mu-wire", "bob-mu-wire", "alice-j", "bob-j"} {
		if strings.Contains(body, leak) {
			t.Fatalf("Regression: secret/subject leaked in 401 body: %q in %q", leak, body)
		}
	}

	// Static credentials must remain clear (AuthProviderCtx path).
	if jc.User != "" || jc.Token != "" {
		t.Fatalf("static write-back residual user=%q token_set=%v", jc.User, jc.Token != "")
	}
}
