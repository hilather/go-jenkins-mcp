package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

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
