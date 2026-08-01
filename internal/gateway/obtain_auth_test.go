package gateway_test

import (
	"context"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

const host003CanaryToken = "HOST003_CANARY_vault_token_must_never_leak_abc987"

func TestCallerFromBoundSubject(t *testing.T) {
	t.Parallel()
	s := policy.Subject{
		ProfileID:       contracts.ProfileID("corp"),
		ExternalSubject: "entra-sub-1",
		Tenant:          "tenant-a",
		WorkloadID:      "wl-1",
		JenkinsUserID:   "alice",
		Verified:        true,
	}
	c := gateway.CallerFromBoundSubject(s)
	if c.Subject != "entra-sub-1" || c.Tenant != "tenant-a" || c.WorkloadID != "wl-1" || c.ProfileID != "corp" {
		t.Fatalf("caller %+v", c)
	}
	if !c.Valid() {
		t.Fatal("expected valid caller")
	}
	// Jenkins principal is not part of Caller (vault key is tenant|subject|profile).
	if gateway.SubjectKey(c) != gateway.SubjectKeyParts("tenant-a", "entra-sub-1", "corp") {
		t.Fatalf("subject key %q", gateway.SubjectKey(c))
	}
}

func TestObtainHTTPAuth_ModeABasic(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	caller := vaultCaller("alice-sub")
	key := gateway.SubjectKey(caller)
	if err := v.Put(context.Background(), key, "alice-j", host003CanaryToken); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	ha, err := gateway.ObtainHTTPAuth(context.Background(), p, caller)
	if err != nil {
		t.Fatal(err)
	}
	if ha.Scheme != gateway.HTTPAuthSchemeBasic {
		t.Fatalf("scheme %q", ha.Scheme)
	}
	if ha.Username != "alice-j" {
		t.Fatalf("user %q", ha.Username)
	}
	if ha.Token != host003CanaryToken {
		t.Fatal("token mismatch")
	}
	// String() must never include token.
	if strings.Contains(ha.String(), host003CanaryToken) {
		t.Fatalf("canary in String: %s", ha.String())
	}
}

func TestObtainHTTPAuth_MissingVaultEntryFailsClosed(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	// Put only for bob — alice must not fall through.
	bob := vaultCaller("bob-sub")
	if err := v.Put(context.Background(), gateway.SubjectKey(bob), "bob-j", host003CanaryToken); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	alice := vaultCaller("alice-sub")
	ha, err := gateway.ObtainHTTPAuth(context.Background(), p, alice)
	if err == nil {
		t.Fatalf("expected fail closed, got %+v", ha)
	}
	if apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	if strings.Contains(err.Error(), host003CanaryToken) {
		t.Fatalf("canary leak: %v", err)
	}
	if ha.Token != "" {
		t.Fatal("token must be empty on error")
	}
}

func TestObtainHTTPAuth_CrossSubjectIsolation(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	alice := vaultCaller("alice-sub")
	bob := vaultCaller("bob-sub")
	if err := v.Put(context.Background(), gateway.SubjectKey(alice), "alice-j", host003CanaryToken+"-alice"); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(context.Background(), gateway.SubjectKey(bob), "bob-j", host003CanaryToken+"-bob"); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}

	haA, err := gateway.ObtainHTTPAuth(context.Background(), p, alice)
	if err != nil {
		t.Fatal(err)
	}
	haB, err := gateway.ObtainHTTPAuth(context.Background(), p, bob)
	if err != nil {
		t.Fatal(err)
	}
	if haA.Username != "alice-j" || haA.Token != host003CanaryToken+"-alice" {
		t.Fatalf("alice auth leaked: user=%q", haA.Username)
	}
	if haB.Username != "bob-j" || haB.Token != host003CanaryToken+"-bob" {
		t.Fatalf("bob auth leaked: user=%q", haB.Username)
	}
	// Wrong profile must not hit alice vault entry.
	other := alice
	other.ProfileID = contracts.ProfileID("other-profile")
	_, err = gateway.ObtainHTTPAuth(context.Background(), otherProv(t, v), other)
	if err == nil {
		t.Fatal("cross-profile must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
}

func otherProv(t *testing.T, v gateway.APITokenVault) gateway.CredentialProvider {
	t.Helper()
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestObtainHTTPAuth_NilProviderAndCancel(t *testing.T) {
	t.Parallel()
	_, err := gateway.ObtainHTTPAuth(context.Background(), nil, vaultCaller("x"))
	if err == nil || apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("nil provider: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v := gateway.NewMemoryAPITokenVault()
	p, _ := gateway.RequireAPITokenVaultSetup(v)
	_, err = gateway.ObtainHTTPAuth(ctx, p, vaultCaller("x"))
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("cancelled: %v code %v", err, apperr.CodeOf(err))
	}
}

func TestObtainHTTPAuth_ModeCBearer(t *testing.T) {
	t.Parallel()
	// Ready AgentCore mock: Bearer path via Obtain + HTTPAuthFromCredential.
	cfg := gateway.AgentCoreConfig{
		Mode:                       gateway.ModeTokenExchange,
		AuthorizationServerBaseURL: "https://login.microsoftonline.com/tenant",
		Audience:                   "api://jenkins-api",
		ClientID:                   "client-1",
	}
	p, err := gateway.RequireGatewaySetup(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ac, ok := p.(*gateway.AgentCoreProvider)
	if !ok {
		t.Fatalf("type %T", p)
	}
	ac.Live = true
	ac.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, c gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{
			AccessToken:      host003CanaryToken + "-bearer",
			JenkinsPrincipal: "alice",
			Mode:             gateway.ModeTokenExchange,
		}, nil
	})
	ha, err := gateway.ObtainHTTPAuth(context.Background(), ac, vaultCaller("alice-sub"))
	if err != nil {
		t.Fatal(err)
	}
	if ha.Scheme != gateway.HTTPAuthSchemeBearer {
		t.Fatalf("scheme %q", ha.Scheme)
	}
	if ha.Token != host003CanaryToken+"-bearer" {
		t.Fatal("token mismatch")
	}
	if strings.Contains(ha.String(), host003CanaryToken) {
		t.Fatalf("canary in String: %s", ha.String())
	}
}
