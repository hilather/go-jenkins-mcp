package mcpserver_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/mcpserver"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// tools/call multi-user JSON-RPC e2e over Streamable HTTP (HOST residual close):
//
// Real MCP Streamable client → NewHTTPHandler with RequireSubject + LabIdentity +
// AfterIdentity (Caller + policy.Subject) → CallTool that exercises AuthProviderCtx
// Mode A vault Obtain (or context-only path). Alice and Bob use independent sessions.
//
// Session model (SDK go-sdk v1.1.0): server.Connect(req.Context()) on the first
// HTTP request that creates the session (initialize) preserves context Values
// via jsonrpc2 notDone; tool handlers inherit session-scoped Caller/Subject from
// that Connect context. Mid-session fingerprint still 401s subject swaps at the
// protect layer. Per-tools/call rebind of Caller from a later POST's r.Context()
// is NOT the multi-user model — session-scoped multi-user is the supported path.
//
// Residual if this test fails on missing Caller in tool ctx: document as SDK
// context propagation gap (should not happen on go-sdk v1.1.0 Connect path).

const muToolsCallCanary = "MU_TOOLS_CALL_CANARY_token_never_echo_xyz"

// labIdentityRoundTripper injects transport secret + lab identity headers on
// every Streamable client HTTP request (initialize, tools/call, GET SSE, DELETE).
type labIdentityRoundTripper struct {
	base             http.RoundTripper
	bearer           string
	subject          string
	tenant           string
	jenkinsPrincipal string
}

func (rt *labIdentityRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("nil request")
	}
	r2 := req.Clone(req.Context())
	if r2.Header == nil {
		r2.Header = make(http.Header)
	}
	if rt.bearer != "" {
		r2.Header.Set("Authorization", "Bearer "+rt.bearer)
	}
	if rt.subject != "" {
		r2.Header.Set(mcpserver.HeaderLabSubject, rt.subject)
	}
	if rt.tenant != "" {
		r2.Header.Set(mcpserver.HeaderLabTenant, rt.tenant)
	}
	if rt.jenkinsPrincipal != "" {
		r2.Header.Set(mcpserver.HeaderLabJenkinsPrincipal, rt.jenkinsPrincipal)
	}
	base := rt.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r2)
}

func muToolsCallAfterIdentity(
	defaultCaller gateway.Caller,
	processSubject policy.Subject,
	profileID contracts.ProfileID,
) func(ctx context.Context, id mcpserver.RequestIdentity) context.Context {
	return multiUserAfterIdentity(defaultCaller, processSubject, profileID)
}

// attachTestAuthProviderCtx mirrors cmd attachGatewayObtainAuthProviderDynamic
// (require context Caller) for offline multi-user Mode A vault tests without
// importing package main.
func attachTestAuthProviderCtx(jc *jenkins.Client, p gateway.CredentialProvider, defaultCaller gateway.Caller) {
	if jc == nil || p == nil {
		return
	}
	prov := p
	def := defaultCaller
	jc.WithAuthProvider(nil)
	jc.WithAuthProviderCtx(func(ctx context.Context) (user, secret string, sch jenkins.AuthScheme, err error) {
		if err := ctx.Err(); err != nil {
			return "", "", "", err
		}
		c, ok := gateway.CallerFromContext(ctx)
		if !ok || strings.TrimSpace(c.Subject) == "" {
			return "", "", "", fmt.Errorf("gateway multi-user Obtain requires caller in context")
		}
		caller := gateway.MergeCallerDefaults(c, def)
		if !caller.Valid() {
			return "", "", "", fmt.Errorf("gateway multi-user caller subject and profile are required")
		}
		ha, err := gateway.ObtainHTTPAuth(ctx, prov, caller)
		if err != nil {
			return "", "", "", err
		}
		scheme := jenkins.AuthSchemeBasic
		if strings.EqualFold(strings.TrimSpace(ha.Scheme), gateway.HTTPAuthSchemeBearer) {
			scheme = jenkins.AuthSchemeBearer
		}
		return strings.TrimSpace(ha.Username), ha.Token, scheme, nil
	})
	jc.User = ""
	jc.Token = ""
}

func assertNoMUCanaryLeak(t *testing.T, label, s string, extra ...string) {
	t.Helper()
	if strings.Contains(s, muToolsCallCanary) {
		t.Fatalf("Regression: canary leaked in %s: %q", label, s)
	}
	for _, e := range extra {
		if e != "" && strings.Contains(s, e) {
			t.Fatalf("Regression: secret/subject %q leaked in %s: %q", e, label, s)
		}
	}
}

// TestMultiUserHTTP_ToolsCall_JSONRPC_AliceBobAuthProviderCtx is the deepest
// offline tools/call multi-user e2e: Streamable client, two sessions, CallTool
// → AuthProviderCtx Mode A vault Obtain isolation + secret canaries.
func TestMultiUserHTTP_ToolsCall_JSONRPC_AliceBobAuthProviderCtx(t *testing.T) {
	t.Parallel()

	alice := gateway.Caller{
		Subject:   "alice-tools-mu",
		Tenant:    "tid-a",
		ProfileID: contracts.ProfileID("corp"),
	}
	bob := gateway.Caller{
		Subject:   "bob-tools-mu",
		Tenant:    "tid-b",
		ProfileID: contracts.ProfileID("corp"),
	}
	const aliceTok = muToolsCallCanary + "-alice"
	const bobTok = muToolsCallCanary + "-bob"
	const aliceJ = "alice-j-mu"
	const bobJ = "bob-j-mu"

	v := gateway.NewMemoryAPITokenVault()
	if err := v.Put(context.Background(), gateway.SubjectKey(alice), aliceJ, aliceTok); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(context.Background(), gateway.SubjectKey(bob), bobJ, bobTok); err != nil {
		t.Fatal(err)
	}
	prov, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}

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

	// Mock Jenkins: capture BasicAuth per WhoAmI; return principal = Basic user.
	var mu sync.Mutex
	var lastUser, lastPass string
	var lastOK bool
	var authHits []string // "user:token_fingerprint" non-secret: user only
	jenkinsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, pw, ok := r.BasicAuth()
		mu.Lock()
		lastUser, lastPass, lastOK = u, pw, ok
		if ok {
			authHits = append(authHits, u)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + u + `","anonymous":false,"authenticated":true}`))
	}))
	t.Cleanup(jenkinsSrv.Close)

	jc := &jenkins.Client{
		URL:    jenkinsSrv.URL,
		Client: jenkinsSrv.Client(),
	}
	attachTestAuthProviderCtx(jc, prov, defaultCaller)

	// Probe tool: context Caller + PolicySubject + AuthProviderCtx WhoAmI.
	// Structured fields are non-secret labels only.
	type probeArgs struct{}
	type probeOut struct {
		CallerSubject    string `json:"caller_subject"`
		CallerTenant     string `json:"caller_tenant"`
		PolicySubject    string `json:"policy_subject"`
		PolicyJenkins    string `json:"policy_jenkins"`
		JenkinsWhoAmI    string `json:"jenkins_whoami"`
		ContextHasCaller bool   `json:"context_has_caller"`
	}

	srv := mcpserver.NewServer("mu-tools-call", "test")
	var toolCtxHasCaller []bool
	var toolCtxMu sync.Mutex
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "mu_whoami_ctx",
		Description: "multi-user tools/call probe: CallerFromContext + AuthProviderCtx WhoAmI (test-only)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ probeArgs) (*mcp.CallToolResult, probeOut, error) {
		c, okC := gateway.CallerFromContext(ctx)
		ps, okPS := gateway.PolicySubjectFromContext(ctx)
		toolCtxMu.Lock()
		toolCtxHasCaller = append(toolCtxHasCaller, okC && c.Valid())
		toolCtxMu.Unlock()

		out := probeOut{
			ContextHasCaller: okC && c.Valid(),
		}
		if okC {
			out.CallerSubject = c.Subject
			out.CallerTenant = c.Tenant
		}
		if okPS {
			out.PolicySubject = ps.ExternalSubject
			out.PolicyJenkins = ps.JenkinsUserID
		}
		// AuthProviderCtx path (same as CallJenkins applyAuth).
		if !out.ContextHasCaller {
			// Fail closed with tool error (no secret). Residual signal if SDK
			// did not propagate Connect-time context Values into the handler.
			return &mcp.CallToolResult{IsError: true}, out, fmt.Errorf(
				"tool context missing gateway.Caller (session Connect context not propagated)")
		}
		who, err := jc.WhoAmI(ctx)
		if err != nil {
			// Never include err strings that might carry secrets from lower layers.
			return &mcp.CallToolResult{IsError: true}, out, fmt.Errorf("whoami failed closed")
		}
		out.JenkinsWhoAmI = strings.TrimSpace(who.ID)
		return &mcp.CallToolResult{}, out, nil
	})

	cfg := multiUserProtectCfg(t, muToolsCallAfterIdentity(defaultCaller, processSubject, contracts.ProfileID("corp")))
	// Align transport secret with tools/call canary (multiUserProtectCfg default is another canary).
	cfg.BearerToken = muToolsCallCanary
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewServer(h)
	t.Cleanup(httpSrv.Close)

	connectSubject := func(t *testing.T, subject, tenant, jenkinsUser string) *mcp.ClientSession {
		t.Helper()
		client := mcp.NewClient(&mcp.Implementation{Name: "mu-tools-client-" + subject, Version: "test"}, nil)
		tr := &mcp.StreamableClientTransport{
			Endpoint: httpSrv.URL,
			HTTPClient: &http.Client{
				Transport: &labIdentityRoundTripper{
					base:             http.DefaultTransport,
					bearer:           muToolsCallCanary,
					subject:          subject,
					tenant:           tenant,
					jenkinsPrincipal: jenkinsUser,
				},
				Timeout: 15 * time.Second,
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		t.Cleanup(cancel)
		cs, err := client.Connect(ctx, tr, nil)
		if err != nil {
			t.Fatalf("Streamable Connect subject=%s: %v", subject, err)
		}
		t.Cleanup(func() { _ = cs.Close() })
		if cs.InitializeResult() == nil {
			t.Fatal("InitializeResult nil")
		}
		return cs
	}

	// --- Alice session ---
	csAlice := connectSubject(t, alice.Subject, alice.Tenant, aliceJ)
	ctxA, cancelA := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelA()
	resA, err := csAlice.CallTool(ctxA, &mcp.CallToolParams{Name: "mu_whoami_ctx"})
	if err != nil {
		t.Fatalf("alice CallTool transport: %v", err)
	}
	if resA == nil || resA.IsError {
		// If tool context lacks Caller, this is the documented residual path.
		toolCtxMu.Lock()
		has := append([]bool(nil), toolCtxHasCaller...)
		toolCtxMu.Unlock()
		if len(has) > 0 && !has[len(has)-1] {
			t.Fatalf("Residual: tools/call handler context missing gateway.Caller after session Connect "+
				"(SDK did not propagate r.Context() Values into tool handlers). hits=%v res=%#v", has, resA)
		}
		t.Fatalf("alice CallTool error: %#v", resA)
	}
	// Structured content may be in Content text and/or StructuredContent depending on SDK.
	aliceText := toolResultBlob(resA)
	assertNoMUCanaryLeak(t, "alice CallTool result", aliceText, aliceTok, bobTok)
	if !strings.Contains(aliceText, alice.Subject) {
		t.Fatalf("alice result missing caller subject: %s", aliceText)
	}
	if !strings.Contains(aliceText, aliceJ) {
		t.Fatalf("alice result missing jenkins whoami: %s", aliceText)
	}
	if strings.Contains(aliceText, bob.Subject) || strings.Contains(aliceText, bobJ) {
		t.Fatalf("alice result must not include bob: %s", aliceText)
	}

	mu.Lock()
	aUser, aPass, aOK := lastUser, lastPass, lastOK
	mu.Unlock()
	if !aOK || aUser != aliceJ || aPass != aliceTok {
		t.Fatalf("alice jenkins basic: ok=%v user=%q pass_ok=%v", aOK, aUser, aPass == aliceTok)
	}
	if aPass == bobTok {
		t.Fatal("cross leak: bob token used for alice WhoAmI")
	}

	// --- Bob independent session ---
	csBob := connectSubject(t, bob.Subject, bob.Tenant, bobJ)
	ctxB, cancelB := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelB()
	resB, err := csBob.CallTool(ctxB, &mcp.CallToolParams{Name: "mu_whoami_ctx"})
	if err != nil {
		t.Fatalf("bob CallTool transport: %v", err)
	}
	if resB == nil || resB.IsError {
		t.Fatalf("bob CallTool error: %#v", resB)
	}
	bobText := toolResultBlob(resB)
	assertNoMUCanaryLeak(t, "bob CallTool result", bobText, aliceTok, bobTok)
	if !strings.Contains(bobText, bob.Subject) {
		t.Fatalf("bob result missing caller subject: %s", bobText)
	}
	if !strings.Contains(bobText, bobJ) {
		t.Fatalf("bob result missing jenkins whoami: %s", bobText)
	}
	if strings.Contains(bobText, alice.Subject) || strings.Contains(bobText, aliceJ) {
		t.Fatalf("bob result must not include alice: %s", bobText)
	}

	mu.Lock()
	bUser, bPass, bOK := lastUser, lastPass, lastOK
	hits := append([]string(nil), authHits...)
	mu.Unlock()
	if !bOK || bUser != bobJ || bPass != bobTok {
		t.Fatalf("bob jenkins basic: ok=%v user=%q pass_ok=%v", bOK, bUser, bPass == bobTok)
	}
	if bPass == aliceTok {
		t.Fatal("cross leak: alice token used for bob WhoAmI")
	}
	// Both principals must have hit Jenkins (order: alice then bob).
	if len(hits) < 2 {
		t.Fatalf("want at least 2 WhoAmI hits, got %v", hits)
	}
	foundAlice, foundBob := false, false
	for _, u := range hits {
		if u == aliceJ {
			foundAlice = true
		}
		if u == bobJ {
			foundBob = true
		}
	}
	if !foundAlice || !foundBob {
		t.Fatalf("jenkins principals seen=%v want both %s and %s", hits, aliceJ, bobJ)
	}

	// Tool context must have seen Valid Caller for both sessions.
	toolCtxMu.Lock()
	hasCaller := append([]bool(nil), toolCtxHasCaller...)
	toolCtxMu.Unlock()
	if len(hasCaller) < 2 {
		t.Fatalf("tool context hits=%v want ≥2", hasCaller)
	}
	for i, ok := range hasCaller {
		if !ok {
			t.Fatalf("tool ctx[%d] missing Valid Caller — session-scoped multi-user failed", i)
		}
	}

	// Static Client fields must remain clear (AuthProviderCtx path).
	if jc.User != "" || jc.Token != "" {
		t.Fatalf("static write-back residual user=%q token_set=%v", jc.User, jc.Token != "")
	}

	// ListTools still works on Alice session; no canary.
	list, err := csAlice.ListTools(ctxA, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	foundTool := false
	for _, tool := range list.Tools {
		if tool != nil && tool.Name == "mu_whoami_ctx" {
			foundTool = true
			break
		}
	}
	if !foundTool {
		t.Fatal("mu_whoami_ctx not listed")
	}
}

// TestMultiUserHTTP_ToolsCall_JSONRPC_MissingCallerFailClosed proves CallTool
// fails closed (tool error) when AfterIdentity does not inject Caller — no
// silent fallthrough to process default vault credentials.
func TestMultiUserHTTP_ToolsCall_JSONRPC_MissingCallerFailClosed(t *testing.T) {
	t.Parallel()

	// Vault only has a default subject — tool must not Obtain it without ctx Caller.
	def := gateway.Caller{
		Subject:   "only-default",
		Tenant:    "tid-d",
		ProfileID: contracts.ProfileID("corp"),
	}
	const defTok = muToolsCallCanary + "-default-only"
	v := gateway.NewMemoryAPITokenVault()
	if err := v.Put(context.Background(), gateway.SubjectKey(def), "default-j", defTok); err != nil {
		t.Fatal(err)
	}
	prov, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}

	var whoHits int
	var mu sync.Mutex
	jenkinsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		whoHits++
		mu.Unlock()
		u, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + u + `","anonymous":false,"authenticated":true}`))
	}))
	t.Cleanup(jenkinsSrv.Close)

	jc := &jenkins.Client{URL: jenkinsSrv.URL, Client: jenkinsSrv.Client()}
	attachTestAuthProviderCtx(jc, prov, def)

	srv := mcpserver.NewServer("mu-tools-fail", "test")
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "mu_require_caller",
		Description: "requires CallerFromContext (test-only)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		if _, ok := gateway.CallerFromContext(ctx); !ok {
			return &mcp.CallToolResult{IsError: true}, map[string]any{"ok": false}, fmt.Errorf("missing caller")
		}
		// If Caller present but wrong identity without vault entry, WhoAmI fails.
		who, err := jc.WhoAmI(ctx)
		if err != nil {
			return &mcp.CallToolResult{IsError: true}, map[string]any{"ok": false}, fmt.Errorf("whoami failed")
		}
		return &mcp.CallToolResult{}, map[string]any{"ok": true, "id": who.ID}, nil
	})

	// No AfterIdentity — Connect context has no Caller.
	cfg := multiUserProtectCfg(t, nil)
	cfg.BearerToken = muToolsCallCanary
	cfg.AfterIdentity = nil
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewServer(h)
	t.Cleanup(httpSrv.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "mu-fail-client", Version: "test"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: httpSrv.URL,
		HTTPClient: &http.Client{
			Transport: &labIdentityRoundTripper{
				bearer:  muToolsCallCanary,
				subject: "orphan-subject",
				tenant:  "tid-x",
			},
			Timeout: 10 * time.Second,
		},
	}, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "mu_require_caller"})
	if err != nil {
		// Transport error is acceptable fail-closed; canary check.
		assertNoMUCanaryLeak(t, "CallTool transport err", err.Error(), defTok)
		return
	}
	if res == nil || !res.IsError {
		t.Fatalf("want tool error without AfterIdentity Caller, got %#v", res)
	}
	assertNoMUCanaryLeak(t, "tool error body", toolResultBlob(res), defTok, "only-default", "default-j")

	mu.Lock()
	hits := whoHits
	mu.Unlock()
	if hits != 0 {
		t.Fatalf("Jenkins must not be called without Caller in tool ctx; hits=%d", hits)
	}
	if jc.User != "" || jc.Token != "" {
		t.Fatalf("static residual user=%q token_set=%v", jc.User, jc.Token != "")
	}
}

// toolResultBlob flattens CallTool result text + structured JSON for assertions.
func toolResultBlob(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok && tc != nil {
			b.WriteString(tc.Text)
			b.WriteByte(' ')
		}
	}
	if res.StructuredContent != nil {
		b.WriteString(fmt.Sprintf("%v", res.StructuredContent))
	}
	return b.String()
}
