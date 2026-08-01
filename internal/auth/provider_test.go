package auth_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

const canaryToken = "CANARY_TOKEN_do_not_leak_in_errors_abc123XYZ"

func TestAPITokenProviderRoundTrip(t *testing.T) {
	t.Parallel()
	kr := keyring.NewStore(keyring.NewMemory())
	p := auth.NewAPITokenProvider(kr)
	p.SessionTTL = time.Hour

	pr := auth.Profile{
		ID:   contracts.ProfileID("corp"),
		URL:  "https://jenkins.example.com",
		User: "alice",
	}
	if err := p.StoreAPIToken(pr, canaryToken); err != nil {
		t.Fatal(err)
	}

	sess, err := p.Authenticate(context.Background(), pr)
	if err != nil {
		t.Fatal(err)
	}
	if sess.User != "alice" || sess.Secret != canaryToken || sess.Method != auth.MethodAPIToken {
		t.Fatalf("session: %+v", sess)
	}
	if sess.ExpiresAt.Before(time.Now()) {
		t.Fatal("session should not be expired")
	}

	st, err := p.Status(context.Background(), pr)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Authenticated || !st.HasCredential || st.User != "alice" {
		t.Fatalf("status: %+v", st)
	}
	if strings.Contains(st.ErrorMessageSafe, canaryToken) || strings.Contains(st.User, canaryToken) {
		t.Fatal("token leaked in status")
	}

	user, token, pid := auth.ApplySession(sess)
	if user != "alice" || token != canaryToken || pid != "corp" {
		t.Fatal("ApplySession")
	}

	if err := p.Logout(context.Background(), pr); err != nil {
		t.Fatal(err)
	}
	_, err = p.Authenticate(context.Background(), pr)
	if err == nil {
		t.Fatal("expected auth failure after logout")
	}
	if strings.Contains(err.Error(), canaryToken) {
		t.Fatalf("token in error: %v", err)
	}
}

func TestAPITokenProviderMissingUsername(t *testing.T) {
	t.Parallel()
	p := auth.NewAPITokenProvider(keyring.NewStore(keyring.NewMemory()))
	_, err := p.Authenticate(context.Background(), auth.Profile{
		ID:  "corp",
		URL: "https://jenkins.example.com",
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("got %v", err)
	}
}

func TestAPITokenProviderCancel(t *testing.T) {
	t.Parallel()
	p := auth.NewAPITokenProvider(keyring.NewStore(keyring.NewMemory()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.Authenticate(ctx, auth.Profile{ID: "c", URL: "https://j.example", User: "a"})
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("got %v code %v", err, apperr.CodeOf(err))
	}
}

func TestOIDCProviderMissingTokens(t *testing.T) {
	t.Parallel()
	p := auth.NewOIDCProvider(keyring.NewStore(keyring.NewMemory()), nil)
	_, err := p.Authenticate(context.Background(), auth.Profile{ID: "c", URL: "https://j.example"})
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "jenkins-mcp login") {
		t.Fatalf("expected recovery: %v", err)
	}
	st, err := p.Status(context.Background(), auth.Profile{ID: "c"})
	if err != nil || st.Authenticated {
		t.Fatalf("%+v %v", st, err)
	}
	if st.Method != auth.MethodOIDC || st.RecoveryHint == "" {
		t.Fatalf("%+v", st)
	}
}

func TestNewProvider(t *testing.T) {
	t.Parallel()
	kr := keyring.NewStore(keyring.NewMemory())
	cp, err := auth.NewProvider(profile.AuthMethodAPIToken, kr)
	if err != nil || cp == nil {
		t.Fatal(err)
	}
	_, err = auth.NewProvider(profile.AuthMethodOIDC, kr)
	if err != nil {
		t.Fatal(err)
	}
	_, err = auth.NewProvider(profile.AuthMethodAgentCoreDelegated, kr)
	if err == nil {
		t.Fatal("expected not implemented")
	}
}

func TestLegacyParse(t *testing.T) {
	t.Parallel()
	u, tok, err := auth.ParseUserToken("alice:mytoken")
	if err != nil || u != "alice" || tok != "mytoken" {
		t.Fatalf("%q %q %v", u, tok, err)
	}
	// Token may contain colons
	u, tok, err = auth.ParseUserToken("alice:a:b:c")
	if err != nil || tok != "a:b:c" {
		t.Fatalf("%q %v", tok, err)
	}
	_, _, err = auth.ParseUserToken("nocolon")
	if err == nil {
		t.Fatal("expected error")
	}
	sess, err := auth.LegacySessionFromString("legacy", "bob:tok")
	if err != nil || sess.User != "bob" || sess.Secret != "tok" {
		t.Fatal(err)
	}
}

func TestProfileFrom(t *testing.T) {
	t.Parallel()
	pp := &profile.Profile{
		ID:         "corp",
		JenkinsURL: "https://j.example",
		Username:   "alice",
		OIDC: &profile.OIDCConfig{
			Issuer:   "https://login.example.com/t/v2.0",
			ClientID: "mcp-public",
		},
	}
	pr := auth.ProfileFrom(pp)
	if pr.ID != "corp" || pr.User != "alice" || pr.URL != "https://j.example" {
		t.Fatalf("%+v", pr)
	}
	if pr.OIDCIssuer != "https://login.example.com/t/v2.0" || pr.OIDCClientID != "mcp-public" {
		t.Fatalf("oidc fields: %+v", pr)
	}
}

func TestStatusMissingCredentialSanitized(t *testing.T) {
	t.Parallel()
	p := auth.NewAPITokenProvider(keyring.NewStore(keyring.NewMemory()))
	st, err := p.Status(context.Background(), auth.Profile{
		ID:   "corp",
		URL:  "https://jenkins.example.com",
		User: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Authenticated {
		t.Fatal("should not be authenticated")
	}
	if strings.Contains(st.ErrorMessageSafe, canaryToken) {
		t.Fatal("canary in status")
	}
	if st.ErrorCode == "" {
		t.Fatal("expected error code")
	}
}
