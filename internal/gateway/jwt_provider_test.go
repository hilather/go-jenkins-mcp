package gateway_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

const canaryJWTToken = "CANARY_HOST010_JWT_must_never_appear_abc999"

func jwtCaller(subject string) gateway.Caller {
	return gateway.Caller{
		Subject:    subject,
		Tenant:     "tenant-b",
		WorkloadID: "wl-jwt",
		ProfileID:  contracts.ProfileID("corp"),
	}
}

func TestMemoryJWTVault_PutGetDeleteIsolation(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryJWTVault()
	ctx := context.Background()
	a := gateway.SubjectKey(jwtCaller("alice"))
	b := gateway.SubjectKey(jwtCaller("bob"))

	if err := v.Put(ctx, a, canaryJWTToken+"-alice"); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(ctx, b, canaryJWTToken+"-bob"); err != nil {
		t.Fatal(err)
	}
	tok, ok, err := v.Get(ctx, a)
	if err != nil || !ok || tok != canaryJWTToken+"-alice" {
		t.Fatalf("alice get: tok=%q ok=%v err=%v", tok, ok, err)
	}
	tok, ok, err = v.Get(ctx, b)
	if err != nil || !ok || tok != canaryJWTToken+"-bob" {
		t.Fatalf("bob get: tok=%q ok=%v err=%v", tok, ok, err)
	}
	if err := v.Delete(ctx, a); err != nil {
		t.Fatal(err)
	}
	_, ok, err = v.Get(ctx, a)
	if err != nil || ok {
		t.Fatalf("alice after delete: ok=%v err=%v", ok, err)
	}
	// Bob still present.
	tok, ok, err = v.Get(ctx, b)
	if err != nil || !ok || tok != canaryJWTToken+"-bob" {
		t.Fatalf("bob after alice delete: %q ok=%v err=%v", tok, ok, err)
	}
	// Missing subject.
	_, ok, err = v.Get(ctx, gateway.SubjectKey(jwtCaller("carol")))
	if err != nil || ok {
		t.Fatalf("carol: ok=%v err=%v", ok, err)
	}
}

func TestMemoryJWTVault_RejectEmptyAndIDToken(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryJWTVault()
	ctx := context.Background()
	key := gateway.SubjectKey(jwtCaller("u1"))
	if err := v.Put(ctx, key, ""); err == nil {
		t.Fatal("empty token must fail")
	}
	if err := v.Put(ctx, "", canaryJWTToken); err == nil {
		t.Fatal("empty subject key must fail")
	}
	// JWT-shaped id_token payload must be rejected (HOST-010).
	idTok := compactJWTWithClaims(t, map[string]string{
		"sub":       "user-1",
		"token_use": "id_token",
	})
	err := v.Put(ctx, key, idTok)
	if err == nil {
		t.Fatal("id_token must be rejected as API credential")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	if strings.Contains(err.Error(), idTok) {
		t.Fatal("id_token material in error")
	}
	// Access-token shaped JWT is accepted.
	at := compactJWTWithClaims(t, map[string]string{
		"sub":       "user-1",
		"token_use": "access_token",
		"aud":       "api://jenkins",
	})
	if err := v.Put(ctx, key, at); err != nil {
		t.Fatal(err)
	}
}

func TestFileJWTVault_PutGetMode0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwt_vault.json")
	v, err := gateway.NewFileJWTVault(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := gateway.SubjectKey(jwtCaller("file-user"))
	if err := v.Put(ctx, key, canaryJWTToken); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("want 0600 got %o", st.Mode().Perm())
	}
	tok, ok, err := v.Get(ctx, key)
	if err != nil || !ok || tok != canaryJWTToken {
		t.Fatalf("get: %q ok=%v err=%v", tok, ok, err)
	}
	// Reload.
	v2, err := gateway.NewFileJWTVault(path)
	if err != nil {
		t.Fatal(err)
	}
	tok, ok, err = v2.Get(ctx, key)
	if err != nil || !ok || tok != canaryJWTToken {
		t.Fatalf("reload: %q ok=%v err=%v", tok, ok, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), canaryJWTToken) {
		// File holds secret — expected on disk; just ensure we can round-trip.
		t.Fatal("expected token on disk for lab vault")
	}
}

func TestFileJWTVault_CorruptFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := gateway.NewFileJWTVault(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = v.Get(context.Background(), gateway.SubjectKey(jwtCaller("x")))
	if err == nil || apperr.CodeOf(err) != apperr.CodeCorruptCache {
		t.Fatalf("want corrupt_cache got %v", err)
	}
}

func TestJWTRSBearerProvider_LiveFalseNotConfigured(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryJWTVault()
	_ = v.Put(context.Background(), gateway.SubjectKey(jwtCaller("u1")), canaryJWTToken)
	p := gateway.NewJWTRSBearerProvider(v)
	_, err := p.Obtain(context.Background(), jwtCaller("u1"))
	if err == nil || apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), canaryJWTToken) {
		t.Fatal("canary in error")
	}
	st := p.Status(context.Background())
	if st.Ready || st.Mode != gateway.ModeJWTRSBearer {
		t.Fatalf("status %+v", st)
	}
	if strings.Contains(fmt.Sprintf("%+v", st), canaryJWTToken) {
		t.Fatal("Status leaked canary")
	}
}

func TestJWTRSBearerProvider_ObtainSuccessAndHTTPAuthBearer(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryJWTVault()
	caller := jwtCaller("alice")
	key := gateway.SubjectKey(caller)
	if err := v.Put(context.Background(), key, canaryJWTToken); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireJWTRSBearerSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := p.Obtain(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != canaryJWTToken {
		t.Fatal("token mismatch")
	}
	if cred.Mode != gateway.ModeJWTRSBearer {
		t.Fatalf("mode %s", cred.Mode)
	}
	auth, err := gateway.HTTPAuthFromCredential(cred)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Scheme != gateway.HTTPAuthSchemeBearer || auth.Username != "" || auth.Token != canaryJWTToken {
		t.Fatalf("auth %+v", auth)
	}
	if strings.Contains(auth.String(), canaryJWTToken) {
		t.Fatal("HTTPAuth.String leaked canary")
	}
	if strings.Contains(cred.String(), canaryJWTToken) {
		t.Fatal("Credential.String leaked canary")
	}
	// ObtainHTTPAuth path.
	auth2, err := gateway.ObtainHTTPAuth(context.Background(), p, caller)
	if err != nil {
		t.Fatal(err)
	}
	if auth2.Scheme != gateway.HTTPAuthSchemeBearer || auth2.Token != canaryJWTToken {
		t.Fatalf("ObtainHTTPAuth %+v", auth2)
	}
	st := p.Status(context.Background())
	if !st.Ready || !st.Configured {
		t.Fatalf("status %+v", st)
	}
}

func TestJWTRSBearerProvider_WrongSubjectIsolation(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryJWTVault()
	alice := jwtCaller("alice")
	bob := jwtCaller("bob")
	_ = v.Put(context.Background(), gateway.SubjectKey(alice), canaryJWTToken+"-alice")
	_ = v.Put(context.Background(), gateway.SubjectKey(bob), canaryJWTToken+"-bob")
	p, _ := gateway.RequireJWTRSBearerSetup(v)

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
	if ca.AccessToken != canaryJWTToken+"-alice" || cb.AccessToken != canaryJWTToken+"-bob" {
		t.Fatal("token mismatch")
	}
	// Alice must never receive bob's token when looking up missing profile.
	other := alice
	other.ProfileID = "other"
	cred, err := p.Obtain(context.Background(), other)
	if err == nil || apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("cross-profile must miss: %v", err)
	}
	if cred.AccessToken != "" {
		t.Fatal("must not return token")
	}
	if strings.Contains(err.Error(), canaryJWTToken) {
		t.Fatal("canary in isolation error")
	}
}

func TestJWTRSBearerProvider_MissingSubjectNotFound(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryJWTVault()
	_ = v.Put(context.Background(), gateway.SubjectKey(jwtCaller("bob")), canaryJWTToken)
	p, err := gateway.RequireJWTRSBearerSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := p.Obtain(context.Background(), jwtCaller("alice"))
	if err == nil || apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("want not_found got %v", err)
	}
	if cred.AccessToken != "" {
		t.Fatal("must not return token")
	}
	if strings.Contains(err.Error(), canaryJWTToken) {
		t.Fatal("canary in missing-subject error")
	}
}

func TestJWTRSBearerProvider_EmptyVaultNoSharedSA(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryJWTVault()
	p, err := gateway.RequireJWTRSBearerSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := p.Obtain(context.Background(), jwtCaller("anyone"))
	if err == nil {
		t.Fatal("empty vault must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeNotFound && apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
	if cred.AccessToken != "" {
		t.Fatal("no ambient token")
	}
	_, err = gateway.RequireJWTRSBearerSetup(nil)
	if err == nil || apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("nil vault setup: %v", err)
	}
	p2 := gateway.NewJWTRSBearerProvider(nil)
	p2.Live = true
	_, err = p2.Obtain(context.Background(), jwtCaller("anyone"))
	if err == nil || apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("nil vault obtain: %v", err)
	}
}

func TestJWTRSBearerProvider_SecretCanaryOnErrors(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryJWTVault()
	caller := jwtCaller("canary")
	_ = v.Put(context.Background(), gateway.SubjectKey(caller), canaryJWTToken)
	p, _ := gateway.RequireJWTRSBearerSetup(v)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.Obtain(ctx, caller)
	if err == nil || strings.Contains(err.Error(), canaryJWTToken) {
		t.Fatalf("cancel err=%v", err)
	}
	_, err = p.Obtain(context.Background(), gateway.Caller{})
	if err == nil || strings.Contains(err.Error(), canaryJWTToken) {
		t.Fatalf("invalid caller err=%v", err)
	}
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
		if strings.Contains(s, canaryJWTToken) {
			t.Fatalf("surface %d leaked: %s", i, s)
		}
	}
}

// compactJWTWithClaims builds an unsigned compact JWT for vault id_token tests.
// Not cryptographically valid — only for payload claim inspection.
func compactJWTWithClaims(t *testing.T, claims map[string]string) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	// Build minimal JSON object.
	parts := make([]string, 0, len(claims))
	for k, v := range claims {
		parts = append(parts, fmt.Sprintf("%q:%q", k, v))
	}
	payload := "{" + strings.Join(parts, ",") + "}"
	pl := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return hdr + "." + pl + ".sig"
}
