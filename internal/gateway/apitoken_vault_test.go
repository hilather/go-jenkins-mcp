package gateway_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

const canaryVaultToken = "CANARY_HOST009_TOKEN_must_never_appear_xyz321"

func vaultCaller(subject string) gateway.Caller {
	return gateway.Caller{
		Subject:    subject,
		Tenant:     "tenant-a",
		WorkloadID: "wl-1",
		ProfileID:  contracts.ProfileID("corp"),
	}
}

func TestSubjectKeyStableAndNotFromArgs(t *testing.T) {
	t.Parallel()
	c := vaultCaller("user-1")
	k1 := gateway.SubjectKey(c)
	k2 := gateway.SubjectKeyParts("tenant-a", "user-1", "corp")
	if k1 != k2 || k1 == "" {
		t.Fatalf("key mismatch %q %q", k1, k2)
	}
	if !strings.Contains(k1, "user-1") || !strings.Contains(k1, "tenant-a") {
		t.Fatalf("key %q", k1)
	}
	// Different subjects isolate.
	if gateway.SubjectKey(vaultCaller("user-2")) == k1 {
		t.Fatal("subjects must not share keys")
	}
	if gateway.SubjectKeyParts("", "", "corp") != "" {
		t.Fatal("empty subject must yield empty key")
	}
	h := gateway.SubjectKeyHash(k1)
	if len(h) != 64 {
		t.Fatalf("hash len %d", len(h))
	}
}

func TestMemoryAPITokenVault_PutGetDeleteIsolation(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	ctx := context.Background()
	a := gateway.SubjectKey(vaultCaller("alice"))
	b := gateway.SubjectKey(vaultCaller("bob"))

	if err := v.Put(ctx, a, "alice-j", canaryVaultToken+"-a"); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(ctx, b, "bob-j", canaryVaultToken+"-b"); err != nil {
		t.Fatal(err)
	}

	u, tok, ok, err := v.Get(ctx, a)
	if err != nil || !ok || u != "alice-j" || tok != canaryVaultToken+"-a" {
		t.Fatalf("alice get: u=%q tok=%q ok=%v err=%v", u, tok, ok, err)
	}
	u, tok, ok, err = v.Get(ctx, b)
	if err != nil || !ok || u != "bob-j" || tok != canaryVaultToken+"-b" {
		t.Fatalf("bob get: u=%q tok=%q ok=%v err=%v", u, tok, ok, err)
	}

	// Wrong subject: miss, not alice's token.
	_, tok, ok, err = v.Get(ctx, gateway.SubjectKey(vaultCaller("carol")))
	if err != nil || ok || tok != "" {
		t.Fatalf("carol should miss: ok=%v tok=%q err=%v", ok, tok, err)
	}

	if err := v.Delete(ctx, a); err != nil {
		t.Fatal(err)
	}
	_, _, ok, err = v.Get(ctx, a)
	if err != nil || ok {
		t.Fatalf("alice deleted: ok=%v err=%v", ok, err)
	}
	// Bob still present.
	_, _, ok, err = v.Get(ctx, b)
	if err != nil || !ok {
		t.Fatalf("bob should remain: ok=%v err=%v", ok, err)
	}
	if v.Len() != 1 {
		t.Fatalf("len=%d", v.Len())
	}
}

func TestMemoryAPITokenVault_RejectEmpty(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	ctx := context.Background()
	err := v.Put(ctx, "", "u", canaryVaultToken)
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("empty key: %v", err)
	}
	err = v.Put(ctx, "k", "", canaryVaultToken)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "username") {
		t.Fatalf("empty user: %v", err)
	}
	err = v.Put(ctx, "k", "u", "")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "token") {
		t.Fatalf("empty token: %v", err)
	}
	// Canary must not appear in validation errors.
	for _, e := range []error{
		v.Put(ctx, "", "u", canaryVaultToken),
		v.Put(ctx, "k", "", canaryVaultToken),
	} {
		if e != nil && strings.Contains(e.Error(), canaryVaultToken) {
			t.Fatalf("canary in error: %v", e)
		}
	}
}

func TestFileAPITokenVault_PutGetMode0600(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	v, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := gateway.SubjectKey(vaultCaller("file-user"))
	if err := v.Put(ctx, key, "fu", canaryVaultToken); err != nil {
		t.Fatal(err)
	}
	// Mode 0600.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm %#o want 0600", st.Mode().Perm())
	}
	u, tok, ok, err := v.Get(ctx, key)
	if err != nil || !ok || u != "fu" || tok != canaryVaultToken {
		t.Fatalf("get: u=%q tok_ok=%v ok=%v err=%v", u, tok == canaryVaultToken, ok, err)
	}
	// Reload from disk.
	v2, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		t.Fatal(err)
	}
	u, tok, ok, err = v2.Get(ctx, key)
	if err != nil || !ok || tok != canaryVaultToken {
		t.Fatalf("reload: ok=%v err=%v", ok, err)
	}
	// File must contain canary (it's the secret store) but errors must not.
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), canaryVaultToken) {
		t.Fatal("expected token on disk for lab vault")
	}
	if err := v2.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	_, _, ok, err = v2.Get(ctx, key)
	if err != nil || ok {
		t.Fatalf("deleted: ok=%v err=%v", ok, err)
	}
}

func TestFileAPITokenVault_CorruptFailsClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = v.Get(context.Background(), "tenant|sub|prof")
	if err == nil || apperr.CodeOf(err) != apperr.CodeCorruptCache {
		t.Fatalf("want corrupt_cache got %v", err)
	}
	if strings.Contains(err.Error(), canaryVaultToken) {
		t.Fatal("canary")
	}
}

func TestAPITokenVaultProvider_LiveFalseNotConfigured(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	_ = v.Put(context.Background(), gateway.SubjectKey(vaultCaller("u1")), "u1", canaryVaultToken)
	p := gateway.NewAPITokenVaultProvider(v)
	// Live=false default.
	_, err := p.Obtain(context.Background(), vaultCaller("u1"))
	if err == nil || apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), canaryVaultToken) {
		t.Fatal("canary in error")
	}
	st := p.Status(context.Background())
	if st.Ready || st.Mode != gateway.ModeAPITokenVault {
		t.Fatalf("status %+v", st)
	}
}

func TestAPITokenVaultProvider_ObtainSuccessAndHTTPAuthBasic(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	caller := vaultCaller("alice")
	key := gateway.SubjectKey(caller)
	if err := v.Put(context.Background(), key, "alice-j", canaryVaultToken); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := p.Obtain(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != canaryVaultToken || cred.JenkinsPrincipal != "alice-j" {
		t.Fatalf("cred principal=%q token_ok=%v", cred.JenkinsPrincipal, cred.AccessToken == canaryVaultToken)
	}
	if cred.Mode != gateway.ModeAPITokenVault {
		t.Fatalf("mode %s", cred.Mode)
	}
	auth, err := gateway.HTTPAuthFromCredential(cred)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Scheme != gateway.HTTPAuthSchemeBasic || auth.Username != "alice-j" || auth.Token != canaryVaultToken {
		t.Fatalf("auth %+v", auth)
	}
	if strings.Contains(auth.String(), canaryVaultToken) {
		t.Fatal("HTTPAuth.String leaked canary")
	}
	if strings.Contains(cred.String(), canaryVaultToken) {
		t.Fatal("Credential.String leaked canary")
	}
	st := p.Status(context.Background())
	if !st.Ready || !st.Configured {
		t.Fatalf("status %+v", st)
	}
	if strings.Contains(fmt.Sprintf("%+v", st), canaryVaultToken) {
		t.Fatal("Status leaked canary")
	}
}

func TestAPITokenVaultProvider_MissingSubjectNotFound(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	// Only bob provisioned.
	_ = v.Put(context.Background(), gateway.SubjectKey(vaultCaller("bob")), "bob-j", canaryVaultToken)
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	// Alice missing → not_found, never bob's token.
	cred, err := p.Obtain(context.Background(), vaultCaller("alice"))
	if err == nil || apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("want not_found got %v", err)
	}
	if cred.AccessToken != "" {
		t.Fatal("must not return token")
	}
	if strings.Contains(err.Error(), canaryVaultToken) {
		t.Fatal("canary in missing-subject error")
	}
	// Bob succeeds.
	cred, err = p.Obtain(context.Background(), vaultCaller("bob"))
	if err != nil || cred.AccessToken != canaryVaultToken {
		t.Fatalf("bob: err=%v", err)
	}
}

// Regression: empty vault + mode A must not use ambient/process default token.
func TestAPITokenVaultProvider_EmptyVaultNoSharedSA(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := p.Obtain(context.Background(), vaultCaller("anyone"))
	if err == nil {
		t.Fatal("empty vault must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeNotFound && apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
	if cred.AccessToken != "" {
		t.Fatal("no ambient token")
	}
	// Nil vault setup.
	_, err = gateway.RequireAPITokenVaultSetup(nil)
	if err == nil || apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("nil vault setup: %v", err)
	}
	// Live + nil vault Obtain.
	p2 := gateway.NewAPITokenVaultProvider(nil)
	p2.Live = true
	_, err = p2.Obtain(context.Background(), vaultCaller("anyone"))
	if err == nil || apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("nil vault obtain: %v", err)
	}
}

func TestAPITokenVaultProvider_WrongSubjectIsolation(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	alice := vaultCaller("alice")
	bob := vaultCaller("bob")
	_ = v.Put(context.Background(), gateway.SubjectKey(alice), "alice-j", canaryVaultToken+"-alice")
	_ = v.Put(context.Background(), gateway.SubjectKey(bob), "bob-j", canaryVaultToken+"-bob")
	p, _ := gateway.RequireAPITokenVaultSetup(v)

	ca, err := p.Obtain(context.Background(), alice)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := p.Obtain(context.Background(), bob)
	if err != nil {
		t.Fatal(err)
	}
	if ca.AccessToken == cb.AccessToken {
		t.Fatal("subjects must not share token material")
	}
	if ca.AccessToken != canaryVaultToken+"-alice" || cb.AccessToken != canaryVaultToken+"-bob" {
		t.Fatal("token mismatch")
	}
	// Same subject different profile isolates.
	otherProf := alice
	otherProf.ProfileID = "other"
	_, err = p.Obtain(context.Background(), otherProf)
	if err == nil || apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("cross-profile must miss: %v", err)
	}
}

func TestAPITokenVaultProvider_SecretCanaryOnErrors(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	caller := vaultCaller("canary")
	_ = v.Put(context.Background(), gateway.SubjectKey(caller), "u", canaryVaultToken)
	p, _ := gateway.RequireAPITokenVaultSetup(v)

	// Cancel path.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.Obtain(ctx, caller)
	if err == nil || strings.Contains(err.Error(), canaryVaultToken) {
		t.Fatalf("cancel err=%v", err)
	}

	// Invalid caller.
	_, err = p.Obtain(context.Background(), gateway.Caller{})
	if err == nil || strings.Contains(err.Error(), canaryVaultToken) {
		t.Fatalf("invalid caller err=%v", err)
	}

	// Success then ensure String surfaces clean.
	cred, err := p.Obtain(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}
	surfaces := []string{
		cred.String(),
		fmt.Sprintf("%+v", p.Status(context.Background())),
		gateway.SubjectKey(caller),
	}
	for i, s := range surfaces {
		if strings.Contains(s, canaryVaultToken) {
			t.Fatalf("surface %d leaked: %s", i, s)
		}
	}
}

func TestHTTPAuthFromCredential_BearerForAgentCoreMode(t *testing.T) {
	t.Parallel()
	auth, err := gateway.HTTPAuthFromCredential(gateway.Credential{
		AccessToken: canaryVaultToken,
		Mode:        gateway.ModeTokenExchange,
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth.Scheme != gateway.HTTPAuthSchemeBearer || auth.Username != "" {
		t.Fatalf("%+v", auth)
	}
	if strings.Contains(auth.String(), canaryVaultToken) {
		t.Fatal("canary")
	}
	_, err = gateway.HTTPAuthFromCredential(gateway.Credential{Mode: gateway.ModeAPITokenVault})
	if err == nil {
		t.Fatal("empty token")
	}
	_, err = gateway.HTTPAuthFromCredential(gateway.Credential{
		AccessToken: canaryVaultToken,
		Mode:        gateway.ModeAPITokenVault,
		// missing principal
	})
	if err == nil || strings.Contains(err.Error(), canaryVaultToken) {
		t.Fatalf("mode A without user: %v", err)
	}
}

func TestCredentialModeNormalize(t *testing.T) {
	t.Parallel()
	if gateway.NormalizeCredentialMode("api_token_vault") != gateway.CredentialModeAPITokenVault {
		t.Fatal("mode a")
	}
	if gateway.NormalizeCredentialMode("agentcore_3lo_obo") != gateway.CredentialModeAgentCore {
		t.Fatal("mode c")
	}
	if !gateway.CredentialModeAPITokenVault.Valid() {
		t.Fatal("valid")
	}
	if gateway.CredentialMode("nope").Valid() {
		t.Fatal("invalid")
	}
}

// AgentCore config must not accept mode A as AS mode (ValidateProviderConfig).
func TestAgentCoreRejectsAPITokenVaultMode(t *testing.T) {
	t.Parallel()
	err := gateway.ValidateProviderConfig(gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://login.microsoftonline.com/t/v2.0",
		Audience:                   "api://jenkins-api",
		Mode:                       gateway.ModeAPITokenVault,
		JenkinsBaseURL:             "https://jenkins.example.com",
	})
	if err == nil {
		t.Fatal("expected reject")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
}
