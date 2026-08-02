package gateway_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

const canaryAccessToken = "CANARY_GWY_TOKEN_must_never_appear_in_errors_or_string_xyz789"

func validCfg() gateway.AgentCoreConfig {
	return gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://login.microsoftonline.com/tenant/v2.0",
		Audience:                   "api://jenkins-api",
		ClientID:                   "client-public",
		Mode:                       gateway.ModeAuthorizationCode,
		JenkinsBaseURL:             "https://jenkins.example.com",
	}
}

func TestAgentCoreProvider_UnconfiguredFailsClosed(t *testing.T) {
	t.Parallel()
	p := gateway.UnconfiguredProvider{Reason: "not_configured test"}
	_, err := p.Obtain(context.Background(), gateway.Caller{
		Subject:   "user-1",
		ProfileID: "corp",
	})
	if err == nil {
		t.Fatal("expected fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	if !strings.Contains(err.Error(), "not_configured") && !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected not_configured wording: %v", err)
	}
	if strings.Contains(err.Error(), canaryAccessToken) {
		t.Fatal("canary in error")
	}
	st := p.Status(context.Background())
	if st.Configured || st.Ready {
		t.Fatalf("status: %+v", st)
	}
}

func TestAgentCoreProvider_ValidConfigButNotLive(t *testing.T) {
	t.Parallel()
	p, err := gateway.NewAgentCoreProvider(validCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode() != gateway.ModeAuthorizationCode {
		t.Fatalf("mode %s", p.Mode())
	}
	cred, err := p.Obtain(context.Background(), gateway.Caller{
		Subject:    "entra-sub-1",
		Tenant:     "tenant-1",
		WorkloadID: "wl-1",
		ProfileID:  contracts.ProfileID("corp"),
	})
	if err == nil {
		t.Fatal("expected not live fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
	if cred.AccessToken != "" {
		t.Fatal("must not return token on error")
	}
	// Canary: error and String never leak a planted token field.
	if strings.Contains(err.Error(), canaryAccessToken) {
		t.Fatal("canary in error")
	}
	if strings.Contains(cred.String(), canaryAccessToken) {
		t.Fatal("canary in Credential.String")
	}
	st := p.Status(context.Background())
	if !st.Configured || st.Ready {
		t.Fatalf("want configured but not ready: %+v", st)
	}
	if st.ErrorCode != string(apperr.CodeCapabilityMissing) {
		t.Fatalf("status code %s", st.ErrorCode)
	}
}

func TestAgentCoreProvider_RejectsJenkinsConfig(t *testing.T) {
	t.Parallel()
	_, err := gateway.NewAgentCoreProvider(gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://jenkins.example.com",
		Audience:                   "api://jenkins-api",
		JenkinsBaseURL:             "https://jenkins.example.com",
	}, nil)
	if err == nil {
		t.Fatal("expected construct failure")
	}
}

func TestAgentCoreProvider_CallerRequired(t *testing.T) {
	t.Parallel()
	p, err := gateway.NewAgentCoreProvider(validCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Force Live to reach caller validation before capability check.
	p.Live = true
	_, err = p.Obtain(context.Background(), gateway.Caller{})
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("got %v", err)
	}
}

func TestAgentCoreProvider_Cancel(t *testing.T) {
	t.Parallel()
	p, err := gateway.NewAgentCoreProvider(validCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = p.Obtain(ctx, gateway.Caller{Subject: "s", ProfileID: "p"})
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("got %v", err)
	}
}

func TestRequireGatewaySetup(t *testing.T) {
	t.Parallel()
	_, err := gateway.RequireGatewaySetup(gateway.AgentCoreConfig{})
	if err == nil || apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("got %v", err)
	}
	p, err := gateway.RequireGatewaySetup(validCfg())
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("nil provider")
	}
}

func TestCredentialAndCachedTokenStringNoSecrets(t *testing.T) {
	t.Parallel()
	c := gateway.Credential{
		AccessToken:      canaryAccessToken,
		JenkinsPrincipal: "alice",
		Mode:             gateway.ModeTokenExchange,
	}
	if strings.Contains(c.String(), canaryAccessToken) {
		t.Fatalf("Credential.String leaked token: %s", c.String())
	}
	tok := gateway.CachedToken{
		AccessToken:      canaryAccessToken,
		JenkinsPrincipal: "alice",
		Mode:             gateway.ModeOBO,
	}
	if strings.Contains(tok.String(), canaryAccessToken) {
		t.Fatalf("CachedToken.String leaked token: %s", tok.String())
	}
}

func TestConsentRequiredNoSecrets(t *testing.T) {
	t.Parallel()
	const (
		authURL = "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?state=abc"
		sessID  = "sess-1234567890"
	)
	err := gateway.NewConsentRequired(gateway.ConsentInfo{
		AuthorizationURL: authURL,
		SessionID:        sessID,
		Provider:         "agentcore",
	})
	if err == nil {
		t.Fatal("expected error value")
	}
	if strings.Contains(err.Error(), canaryAccessToken) {
		t.Fatal("canary")
	}
	// Error() is log-safe (host + truncated session); full URL is progressive UX only.
	if strings.Contains(err.Error(), "state=abc") {
		t.Fatalf("Error() must not dump full authorize URL with state: %q", err.Error())
	}
	cr, ok := gateway.AsConsentRequired(err)
	if !ok || !cr.Info.Valid() {
		t.Fatalf("%v %v", ok, cr)
	}
	if cr.ConsentAuthorizationURL() != authURL {
		t.Fatalf("ConsentAuthorizationURL=%q", cr.ConsentAuthorizationURL())
	}
	if cr.ConsentSessionID() != sessID {
		t.Fatalf("ConsentSessionID=%q", cr.ConsentSessionID())
	}
	// Incomplete consent rejected.
	if err := gateway.NewConsentRequired(gateway.ConsentInfo{}); err == nil {
		t.Fatal("expected incomplete")
	}
}
