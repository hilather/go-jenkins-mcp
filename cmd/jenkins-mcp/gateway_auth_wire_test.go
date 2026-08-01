package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

const host003WireCanary = "HOST003_WIRE_CANARY_token_never_in_errors_xyz654"

func host003Caller(subject string) gateway.Caller {
	return gateway.Caller{
		Subject:    subject,
		Tenant:     "tenant-a",
		WorkloadID: "wl-1",
		ProfileID:  contracts.ProfileID("corp"),
	}
}

// Regression: HOST-003 Mode A AuthProvider returns Basic vault username/token.
func TestAttachGatewayObtainAuthProvider_ModeABasic(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	caller := host003Caller("alice-sub")
	if err := v.Put(context.Background(), gateway.SubjectKey(caller), "alice-j", host003WireCanary); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	// Static fields must NOT be used when AuthProvider is installed.
	c := &jenkins.Client{
		User:  "stale-keyring-user",
		Token: "stale-keyring-token-must-not-be-sent",
	}
	attachGatewayObtainAuthProvider(c, p, caller)
	if c.AuthProvider == nil {
		t.Fatal("AuthProvider not installed")
	}
	user, secret, sch, err := c.AuthProvider()
	if err != nil {
		t.Fatal(err)
	}
	if sch != jenkins.AuthSchemeBasic {
		t.Fatalf("scheme %q", sch)
	}
	if user != "alice-j" || secret != host003WireCanary {
		t.Fatalf("user=%q secret_set=%v", user, secret != "")
	}
}

// Regression: missing vault entry fails closed; no request when used with CallJenkins.
func TestAttachGatewayObtainAuthProvider_MissingFailsClosedNoRequest(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	v := gateway.NewMemoryAPITokenVault()
	// Vault has bob only.
	bob := host003Caller("bob-sub")
	if err := v.Put(context.Background(), gateway.SubjectKey(bob), "bob-j", host003WireCanary); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	c := &jenkins.Client{
		URL:    srv.URL,
		User:   "stale",
		Token:  host003WireCanary, // must not fall through on Obtain miss
		Client: srv.Client(),
	}
	attachGatewayObtainAuthProvider(c, p, host003Caller("alice-sub"))
	_, err = c.CallJenkins(context.Background(), srv.Client(), http.MethodGet, jenkins.WhoAmIPath, nil, nil)
	if err == nil {
		t.Fatal("expected Obtain fail closed")
	}
	if hits.Load() != 0 {
		t.Fatalf("request must not be sent; hits=%d", hits.Load())
	}
	if apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	if strings.Contains(err.Error(), host003WireCanary) {
		t.Fatalf("canary leak: %v", err)
	}
}

// Regression: vault for subject A is not used when AuthProvider captures subject B.
func TestAttachGatewayObtainAuthProvider_CrossSubjectNoLeak(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	alice := host003Caller("alice-sub")
	bob := host003Caller("bob-sub")
	if err := v.Put(context.Background(), gateway.SubjectKey(alice), "alice-j", host003WireCanary+"-a"); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(context.Background(), gateway.SubjectKey(bob), "bob-j", host003WireCanary+"-b"); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}

	var gotUser, gotPass string
	var gotOK bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOK = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"bob-j","anonymous":false,"authenticated":true}`))
	}))
	t.Cleanup(srv.Close)

	// Wire AuthProvider for bob only — alice vault entry must never be sent.
	c := &jenkins.Client{
		URL:    srv.URL,
		User:   "alice-j", // stale static must not win
		Token:  host003WireCanary + "-a",
		Client: srv.Client(),
	}
	attachGatewayObtainAuthProvider(c, p, bob)
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !gotOK || gotUser != "bob-j" || gotPass != host003WireCanary+"-b" {
		t.Fatalf("basic auth: ok=%v user=%q pass_is_bob=%v", gotOK, gotUser, gotPass == host003WireCanary+"-b")
	}
	// Explicitly ensure alice token was not used.
	if gotPass == host003WireCanary+"-a" {
		t.Fatal("cross-subject: alice token used for bob caller")
	}
}

// Regression: Mode A end-to-end CallJenkins Authorization is Basic (not Bearer).
func TestAttachGatewayObtainAuthProvider_ModeAHTTPBasicHeader(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	caller := host003Caller("alice-sub")
	if err := v.Put(context.Background(), gateway.SubjectKey(caller), "alice-j", host003WireCanary); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}

	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice-j","anonymous":false}`))
	}))
	t.Cleanup(srv.Close)

	c := &jenkins.Client{URL: srv.URL, Client: srv.Client()}
	attachGatewayObtainAuthProvider(c, p, caller)
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantPrefix := "Basic "
	if !strings.HasPrefix(authHeader, wantPrefix) {
		t.Fatalf("Authorization=%q", authHeader)
	}
	// Decode and confirm credentials (Basic user:token).
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, wantPrefix))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 || parts[0] != "alice-j" || parts[1] != host003WireCanary {
		t.Fatalf("decoded basic %q", string(raw))
	}
	if strings.HasPrefix(authHeader, "Bearer ") {
		t.Fatal("Mode A must not send Bearer")
	}
}

func TestAttachGatewayObtainAuthProvider_NilSafe(t *testing.T) {
	t.Parallel()
	attachGatewayObtainAuthProvider(nil, nil, gateway.Caller{})
	c := &jenkins.Client{}
	attachGatewayObtainAuthProvider(c, nil, gateway.Caller{})
	if c.AuthProvider != nil {
		t.Fatal("nil provider must not install AuthProvider")
	}
}

func TestGatewayObtainReady(t *testing.T) {
	t.Parallel()
	if gatewayObtainReady(nil) {
		t.Fatal("nil")
	}
	v := gateway.NewMemoryAPITokenVault()
	// Live=false default.
	p := gateway.NewAPITokenVaultProvider(v)
	if gatewayObtainReady(p) {
		t.Fatal("Live=false must not be Ready")
	}
	ready, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	if !gatewayObtainReady(ready) {
		t.Fatal("RequireAPITokenVaultSetup must be Ready")
	}
}

func TestCallerFromBoundSubject_ServeShape(t *testing.T) {
	t.Parallel()
	// Mirrors bindGatewaySubject → CallerFromBoundSubject used in serve.
	s := policy.Subject{
		ProfileID:       "corp",
		ExternalSubject: "entra-sub",
		Tenant:          "t1",
		WorkloadID:      "w1",
		JenkinsUserID:   "alice",
		Verified:        true,
	}
	c := gateway.CallerFromBoundSubject(s)
	if c.Subject != "entra-sub" || string(c.ProfileID) != "corp" {
		t.Fatalf("%+v", c)
	}
}

func TestHttpAuthToJenkins_Schemes(t *testing.T) {
	t.Parallel()
	u, s, sch, err := httpAuthToJenkins(gateway.HTTPAuth{
		Scheme: gateway.HTTPAuthSchemeBearer,
		Token:  "tok",
	})
	if err != nil || sch != jenkins.AuthSchemeBearer || s != "tok" || u != "" {
		t.Fatalf("bearer: u=%q s=%q sch=%q err=%v", u, s, sch, err)
	}
	u, s, sch, err = httpAuthToJenkins(gateway.HTTPAuth{
		Scheme:   gateway.HTTPAuthSchemeBasic,
		Username: "u1",
		Token:    "tok2",
	})
	if err != nil || sch != jenkins.AuthSchemeBasic || u != "u1" || s != "tok2" {
		t.Fatalf("basic: u=%q s=%q sch=%q err=%v", u, s, sch, err)
	}
}

// Regression: HOST-003 Ready path clears static keyring material after attach.
func TestClearGatewayLocalSessionCredentials(t *testing.T) {
	t.Parallel()
	c := &jenkins.Client{User: "stale", Token: host003WireCanary}
	clearGatewayLocalSessionCredentials(c)
	if c.User != "" || c.Token != "" {
		t.Fatalf("static residual remains user=%q token_set=%v", c.User, c.Token != "")
	}
	clearGatewayLocalSessionCredentials(nil) // nil-safe
}

// Regression: Obtain failure for subject A never returns subject B's credential
// even when B's token is cached / present in vault (HOST-003).
func TestAttachGatewayObtainAuthProvider_ObtainFailDoesNotReturnOtherSubject(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	alice := host003Caller("alice-sub")
	bob := host003Caller("bob-sub")
	if err := v.Put(context.Background(), gateway.SubjectKey(alice), "alice-j", host003WireCanary+"-a"); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(context.Background(), gateway.SubjectKey(bob), "bob-j", host003WireCanary+"-b"); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	// Wire for a third subject with no vault entry; Obtain must fail closed.
	missing := host003Caller("missing-sub")
	c := &jenkins.Client{
		User:  "bob-j",
		Token: host003WireCanary + "-b", // must never be returned on Obtain fail
	}
	attachGatewayObtainAuthProvider(c, p, missing)
	clearGatewayLocalSessionCredentials(c)
	user, secret, _, err := c.AuthProvider()
	if err == nil {
		t.Fatalf("expected Obtain fail; got user=%q secret_set=%v", user, secret != "")
	}
	if user != "" || secret != "" {
		t.Fatal("Obtain failure must not return any credential fields")
	}
	if strings.Contains(err.Error(), host003WireCanary) {
		t.Fatalf("canary leak: %v", err)
	}
	// Static still empty after fail (no other-subject write-back).
	if c.User != "" || c.Token != "" {
		t.Fatalf("static after fail user=%q token_set=%v", c.User, c.Token != "")
	}
	// Bob's Obtain still works on a separate attach (isolation).
	cBob := &jenkins.Client{}
	attachGatewayObtainAuthProvider(cBob, p, bob)
	u, s, sch, err := cBob.AuthProvider()
	if err != nil || sch != jenkins.AuthSchemeBasic || u != "bob-j" || s != host003WireCanary+"-b" {
		t.Fatalf("bob obtain: u=%q s_ok=%v sch=%q err=%v", u, s == host003WireCanary+"-b", sch, err)
	}
}

// Regression: Mode C ConsentRequired surfaces auth URL metadata only through AuthProvider.
func TestAttachGatewayObtainAuthProvider_ConsentRequiredMetadataOnly(t *testing.T) {
	t.Parallel()
	const (
		authURL = "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?state=consent-test"
		sessID  = "sess-host003-consent-1"
	)
	cfg := gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://login.microsoftonline.com/t/v2.0",
		Audience:                   "api://jenkins-api",
		ClientID:                   "cid",
		Mode:                       gateway.ModeAuthorizationCode,
		JenkinsBaseURL:             "https://jenkins.example.com",
		TokenEndpoint:              "https://login.microsoftonline.com/t/oauth2/v2.0/token",
	}
	p, err := gateway.NewAgentCoreProvider(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, c gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{}, gateway.NewConsentRequired(gateway.ConsentInfo{
			AuthorizationURL: authURL,
			SessionID:        sessID,
			Provider:         "agentcore",
		})
	})
	if !gatewayObtainReady(p) {
		t.Fatal("Live+Fetcher must be Ready")
	}
	c := &jenkins.Client{User: "stale", Token: host003WireCanary}
	attachGatewayObtainAuthProvider(c, p, host003Caller("alice-sub"))
	clearGatewayLocalSessionCredentials(c)
	_, _, _, err = c.AuthProvider()
	if err == nil {
		t.Fatal("expected ConsentRequired")
	}
	cr, ok := gateway.AsConsentRequired(err)
	if !ok || cr == nil {
		t.Fatalf("want ConsentRequired got %T %v", err, err)
	}
	if cr.Info.AuthorizationURL != authURL || cr.Info.SessionID != sessID {
		t.Fatalf("consent metadata: %+v", cr.Info)
	}
	if !cr.Info.Valid() {
		t.Fatal("consent must be Valid")
	}
	// Metadata only — never tokens / canary.
	blob := err.Error() + cr.Info.AuthorizationURL + cr.Info.SessionID + cr.Info.Provider
	if strings.Contains(blob, host003WireCanary) {
		t.Fatal("canary in consent surfaces")
	}
	sm := cr.Info.StatusMap()
	if sm["has_authorization_url"] != true || sm["has_session_id"] != true {
		t.Fatalf("status map: %+v", sm)
	}
}

// Regression: Mode C Obtain failure (Fetcher auth error) does not yield another
// caller's cached token via AuthProvider (HOST-003 / GWY-001).
func TestAttachGatewayObtainAuthProvider_ModeCObtainFailNoOtherSubjectCache(t *testing.T) {
	t.Parallel()
	cfg := gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://login.microsoftonline.com/t/v2.0",
		Audience:                   "api://jenkins-api",
		ClientID:                   "cid",
		Mode:                       gateway.ModeTokenExchange,
		JenkinsBaseURL:             "https://jenkins.example.com",
		TokenEndpoint:              "https://login.microsoftonline.com/t/oauth2/v2.0/token",
	}
	cache := gateway.NewMemoryTokenCache(0)
	// Poison-style: pre-cache bob only (non-expired entry).
	bob := host003Caller("bob-sub")
	cache.Set(bob.CacheKey(), gateway.CachedToken{
		AccessToken:      host003WireCanary + "-bob-bearer",
		ExpiresAt:        time.Now().Add(time.Hour),
		JenkinsPrincipal: "bob-j",
		Mode:             gateway.ModeTokenExchange,
	})
	p, err := gateway.NewAgentCoreProvider(cfg, cache)
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, c gateway.AgentCoreConfig) (gateway.Credential, error) {
		// Alice is never issued a token.
		if caller.Subject == "bob-sub" {
			return gateway.Credential{
				AccessToken:      host003WireCanary + "-bob-bearer",
				JenkinsPrincipal: "bob-j",
				Mode:             gateway.ModeTokenExchange,
			}, nil
		}
		return gateway.Credential{}, apperr.New(apperr.CodeAuthentication, "fetch denied for subject")
	})

	c := &jenkins.Client{User: "bob-j", Token: host003WireCanary + "-bob-bearer"}
	attachGatewayObtainAuthProvider(c, p, host003Caller("alice-sub"))
	clearGatewayLocalSessionCredentials(c)
	user, secret, _, err := c.AuthProvider()
	if err == nil {
		t.Fatalf("alice must fail closed; got user=%q secret_is_bob=%v", user, secret == host003WireCanary+"-bob-bearer")
	}
	if secret == host003WireCanary+"-bob-bearer" || user != "" || secret != "" {
		t.Fatal("must not return bob cached credential for alice")
	}
	if strings.Contains(err.Error(), host003WireCanary) {
		t.Fatalf("canary leak: %v", err)
	}
}

// Regression: whoAmI via Obtain AuthProvider for bound caller (HOST-003 session start).
func TestVerifyGatewayObtainWhoAmI_SuccessAndMismatch(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	caller := host003Caller("alice-sub")
	if err := v.Put(context.Background(), gateway.SubjectKey(caller), "alice-j", host003WireCanary); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}

	var gotUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		gotUser = u
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice-j","anonymous":false,"authenticated":true}`))
	}))
	t.Cleanup(srv.Close)

	c := &jenkins.Client{
		URL:    srv.URL,
		User:   "stale-keyring",
		Token:  "stale-keyring-token",
		Client: srv.Client(),
	}
	attachGatewayObtainAuthProvider(c, p, caller)
	clearGatewayLocalSessionCredentials(c)

	who, err := verifyGatewayObtainWhoAmI(context.Background(), c, "alice-j")
	if err != nil {
		t.Fatal(err)
	}
	if who.ID != "alice-j" || gotUser != "alice-j" {
		t.Fatalf("who=%+v gotUser=%q", who, gotUser)
	}
	// Mismatch expected principal fails closed.
	_, err = verifyGatewayObtainWhoAmI(context.Background(), c, "other-user")
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("want mismatch authentication: %v", err)
	}
	if strings.Contains(err.Error(), host003WireCanary) {
		t.Fatal("canary leak")
	}
}

// Regression: whoAmI refuses local session when AuthProvider not installed.
func TestVerifyGatewayObtainWhoAmI_RequiresAuthProvider(t *testing.T) {
	t.Parallel()
	c := &jenkins.Client{User: "u", Token: host003WireCanary}
	_, err := verifyGatewayObtainWhoAmI(context.Background(), c, "u")
	if err == nil || apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), host003WireCanary) {
		t.Fatal("canary")
	}
}

// Regression: multi-user AuthProviderCtx selects Alice vs Bob tokens with no cross leak.
func TestAttachGatewayObtainAuthProviderDynamic_AliceBobNoCrossLeak(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	alice := host003Caller("alice-sub")
	bob := host003Caller("bob-sub")
	const aliceTok = host003WireCanary + "-alice-mu"
	const bobTok = host003WireCanary + "-bob-mu"
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

	var gotUser, gotPass string
	var gotOK bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOK = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + gotUser + `","anonymous":false,"authenticated":true}`))
	}))
	t.Cleanup(srv.Close)

	// Process default = alice; Bob requests must rebind via context.
	c := &jenkins.Client{
		URL:    srv.URL,
		User:   "stale",
		Token:  host003WireCanary,
		Client: srv.Client(),
	}
	attachGatewayObtainAuthProviderDynamic(c, p, alice)
	clearGatewayLocalSessionCredentials(c)
	if c.AuthProvider != nil {
		t.Fatal("multi-user must clear fixed AuthProvider")
	}
	if c.AuthProviderCtx == nil {
		t.Fatal("AuthProviderCtx not installed")
	}

	// Alice via context.
	ctxAlice := gateway.ContextWithCaller(context.Background(), alice)
	if _, err := c.WhoAmI(ctxAlice); err != nil {
		t.Fatal(err)
	}
	if !gotOK || gotUser != "alice-j" || gotPass != aliceTok {
		t.Fatalf("alice: ok=%v user=%q pass_ok=%v", gotOK, gotUser, gotPass == aliceTok)
	}
	if gotPass == bobTok {
		t.Fatal("cross leak: bob token used for alice")
	}
	// Static must not be written by AuthProviderCtx.
	if c.Token != "" || c.User != "" {
		t.Fatalf("static write-back residual user=%q token_set=%v", c.User, c.Token != "")
	}

	// Bob via context — same Client instance, different ctx.
	gotUser, gotPass, gotOK = "", "", false
	ctxBob := gateway.ContextWithCaller(context.Background(), bob)
	if _, err := c.WhoAmI(ctxBob); err != nil {
		t.Fatal(err)
	}
	if !gotOK || gotUser != "bob-j" || gotPass != bobTok {
		t.Fatalf("bob: ok=%v user=%q pass_ok=%v", gotOK, gotUser, gotPass == bobTok)
	}
	if gotPass == aliceTok {
		t.Fatal("cross leak: alice token used for bob")
	}

	// Background (no Caller) → defaultCaller alice.
	gotUser, gotPass, gotOK = "", "", false
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !gotOK || gotUser != "alice-j" || gotPass != aliceTok {
		t.Fatalf("default: ok=%v user=%q pass_ok=%v", gotOK, gotUser, gotPass == aliceTok)
	}
}

// Regression: multi-user Obtain miss fails closed; never returns other vault subject.
func TestAttachGatewayObtainAuthProviderDynamic_MissingNoOtherSubject(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	alice := host003Caller("alice-sub")
	bob := host003Caller("bob-sub")
	if err := v.Put(context.Background(), gateway.SubjectKey(alice), "alice-j", host003WireCanary+"-a"); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(context.Background(), gateway.SubjectKey(bob), "bob-j", host003WireCanary+"-b"); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	c := &jenkins.Client{User: "bob-j", Token: host003WireCanary + "-b"}
	attachGatewayObtainAuthProviderDynamic(c, p, alice)
	clearGatewayLocalSessionCredentials(c)

	missing := host003Caller("missing-sub")
	ctx := gateway.ContextWithCaller(context.Background(), missing)
	user, secret, _, err := c.AuthProviderCtx(ctx)
	if err == nil {
		t.Fatalf("expected fail; got user=%q secret_set=%v", user, secret != "")
	}
	if user != "" || secret != "" {
		t.Fatal("must not return credential fields on Obtain fail")
	}
	if secret == host003WireCanary+"-a" || secret == host003WireCanary+"-b" {
		t.Fatal("must not return another subject's token")
	}
	if strings.Contains(err.Error(), host003WireCanary) {
		t.Fatalf("canary leak: %v", err)
	}
}

func TestAttachGatewayObtainAuthProviderDynamic_NilSafe(t *testing.T) {
	t.Parallel()
	attachGatewayObtainAuthProviderDynamic(nil, nil, gateway.Caller{})
	c := &jenkins.Client{}
	attachGatewayObtainAuthProviderDynamic(c, nil, gateway.Caller{})
	if c.AuthProviderCtx != nil || c.AuthProvider != nil {
		t.Fatal("nil provider must not install")
	}
}

// Regression: multi-user off path still uses fixed AuthProvider (single-subject pin foundation).
func TestAttachGatewayObtainAuthProvider_SingleSubjectStillFixed(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	alice := host003Caller("alice-sub")
	bob := host003Caller("bob-sub")
	if err := v.Put(context.Background(), gateway.SubjectKey(alice), "alice-j", host003WireCanary+"-a"); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(context.Background(), gateway.SubjectKey(bob), "bob-j", host003WireCanary+"-b"); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	c := &jenkins.Client{}
	attachGatewayObtainAuthProvider(c, p, alice)
	if c.AuthProvider == nil {
		t.Fatal("fixed AuthProvider required when multi-user off")
	}
	if c.AuthProviderCtx != nil {
		t.Fatal("multi-user off must not leave AuthProviderCtx")
	}
	// Even with Bob in context, fixed AuthProvider ignores context → Alice only.
	u, s, _, err := c.AuthProvider()
	if err != nil || u != "alice-j" || s != host003WireCanary+"-a" {
		t.Fatalf("fixed obtain: u=%q s_ok=%v err=%v", u, s == host003WireCanary+"-a", err)
	}
}

// Regression: Ready attach + clear means AuthProvider nil would not have static fallback material.
func TestAttachGatewayObtainAuthProvider_ReadyClearsStaticNoFallthrough(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// If static fallthrough happened, Basic would be present with canary.
		if u, p, ok := r.BasicAuth(); ok && p == host003WireCanary {
			t.Errorf("static canary sent user=%q", u)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	// Provider always fails Obtain.
	p := gateway.UnconfiguredProvider{Reason: "test not ready path simulation"}
	// Actually Ready=false for Unconfigured — use Mode A missing entry instead.
	v := gateway.NewMemoryAPITokenVault()
	ready, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	_ = p
	c := &jenkins.Client{
		URL:    srv.URL,
		User:   "stale",
		Token:  host003WireCanary,
		Client: srv.Client(),
	}
	attachGatewayObtainAuthProvider(c, ready, host003Caller("no-entry"))
	clearGatewayLocalSessionCredentials(c)
	_, err = c.CallJenkins(context.Background(), srv.Client(), http.MethodGet, jenkins.WhoAmIPath, nil, nil)
	if err == nil {
		t.Fatal("expected fail closed")
	}
	if hits.Load() != 0 {
		t.Fatalf("hits=%d (must not send request on Obtain fail)", hits.Load())
	}
	if c.Token != "" || c.User != "" {
		t.Fatal("static must remain cleared")
	}
}
