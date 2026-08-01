package gateway_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// canary for secret-free String/Status assertions — must never appear in cache output.
const principalCacheCanaryToken = "pcache-canary-secret-token-NEVER-LOG"

func TestPrincipalCache_SetGetDeleteIsolation(t *testing.T) {
	t.Parallel()
	c := gateway.NewPrincipalCache()
	alice := gateway.Caller{
		Subject: "alice-sub", Tenant: "tid-1", ProfileID: contracts.ProfileID("corp"),
	}
	bob := gateway.Caller{
		Subject: "bob-sub", Tenant: "tid-1", ProfileID: contracts.ProfileID("corp"),
	}
	aliceKey := gateway.SubjectKey(alice)
	bobKey := gateway.SubjectKey(bob)

	c.Set(aliceKey, "alice-j")
	c.Set(bobKey, "bob-j")

	got, ok := c.Get(aliceKey)
	if !ok || got != "alice-j" {
		t.Fatalf("alice: ok=%v principal=%q", ok, got)
	}
	got, ok = c.Get(bobKey)
	if !ok || got != "bob-j" {
		t.Fatalf("bob: ok=%v principal=%q", ok, got)
	}
	// Cross-subject isolation: wrong key misses.
	if _, ok := c.Get(gateway.SubjectKeyParts("tid-1", "carol-sub", "corp")); ok {
		t.Fatal("carol must miss")
	}
	if aliceKey == bobKey {
		t.Fatal("fixture SubjectKeys must differ")
	}

	c.Delete(aliceKey)
	if _, ok := c.Get(aliceKey); ok {
		t.Fatal("alice deleted")
	}
	if p, ok := c.Get(bobKey); !ok || p != "bob-j" {
		t.Fatalf("bob must remain after alice Delete: ok=%v p=%q", ok, p)
	}

	c.Clear()
	if _, ok := c.Get(bobKey); ok {
		t.Fatal("clear must drop bob")
	}
	if c.Len() != 0 {
		t.Fatalf("len after clear: %d", c.Len())
	}
}

func TestPrincipalCache_RejectEmptyAndInvalid(t *testing.T) {
	t.Parallel()
	c := gateway.NewPrincipalCache()
	c.Set("", "alice-j")
	c.Set("  ", "alice-j")
	c.Set(gateway.SubjectKeyParts("t", "u", "p"), "")
	c.Set(gateway.SubjectKeyParts("t", "u", "p"), "  ")
	if c.Len() != 0 {
		t.Fatalf("empty key/principal must not store: len=%d", c.Len())
	}
	if _, ok := c.Get(""); ok {
		t.Fatal("empty get")
	}
	// Nil-safe.
	var nilC *gateway.PrincipalCache
	nilC.Set("t|u|p", "x")
	if _, ok := nilC.Get("t|u|p"); ok {
		t.Fatal("nil Get")
	}
	nilC.Delete("t|u|p")
	nilC.Clear()
	if nilC.Len() != 0 {
		t.Fatal("nil Len")
	}
	if !strings.Contains(nilC.String(), "entries=0") {
		t.Fatalf("nil String: %q", nilC.String())
	}
}

func TestPrincipalCache_StringStatusSecretFree(t *testing.T) {
	t.Parallel()
	c := gateway.NewPrincipalCache()
	c.Set(gateway.SubjectKeyParts("tid", "sub", "corp"), "alice-j")
	s := c.String()
	st := c.StatusMap()
	if strings.Contains(s, "alice-j") {
		// Count-only String by design (no principal inventory dump).
		t.Fatalf("String must not dump principals: %q", s)
	}
	if !strings.Contains(s, "entries=1") {
		t.Fatalf("String want entries=1: %q", s)
	}
	if st["entries"] != 1 {
		t.Fatalf("StatusMap entries: %v", st["entries"])
	}
	// Token-shaped principal must never appear in String (count only).
	c.Set(gateway.SubjectKeyParts("tid", "sub2", "corp"), principalCacheCanaryToken)
	if strings.Contains(c.String(), principalCacheCanaryToken) {
		t.Fatal("String leaked canary")
	}
	if strings.Contains(fmt.Sprint(st), principalCacheCanaryToken) {
		t.Fatal("StatusMap leaked canary")
	}
}

func TestRememberObtainPrincipal_ModeAAndCredential(t *testing.T) {
	t.Parallel()
	c := gateway.NewPrincipalCache()
	alice := gateway.Caller{
		Subject: "alice-sub", Tenant: "tid-1", ProfileID: "corp",
	}
	// Credential.JenkinsPrincipal preferred.
	gateway.RememberObtainPrincipal(c, alice, gateway.Credential{
		AccessToken:      principalCacheCanaryToken,
		JenkinsPrincipal: "alice-j",
		Mode:             gateway.ModeAPITokenVault,
	}, gateway.HTTPAuth{Scheme: gateway.HTTPAuthSchemeBasic, Username: "ignored", Token: principalCacheCanaryToken})
	got, ok := c.Get(gateway.SubjectKey(alice))
	if !ok || got != "alice-j" {
		t.Fatalf("prefer cred principal: ok=%v got=%q", ok, got)
	}
	// Fallback to Basic Username when cred principal empty.
	bob := gateway.Caller{Subject: "bob-sub", Tenant: "tid-1", ProfileID: "corp"}
	gateway.RememberObtainPrincipal(c, bob, gateway.Credential{
		AccessToken: principalCacheCanaryToken,
		Mode:        gateway.ModeAPITokenVault,
	}, gateway.HTTPAuth{Scheme: gateway.HTTPAuthSchemeBasic, Username: "bob-j", Token: principalCacheCanaryToken})
	got, ok = c.Get(gateway.SubjectKey(bob))
	if !ok || got != "bob-j" {
		t.Fatalf("fallback username: ok=%v got=%q", ok, got)
	}
	// Bearer with no principal → no store.
	carol := gateway.Caller{Subject: "carol-sub", Tenant: "tid-1", ProfileID: "corp"}
	gateway.RememberObtainPrincipal(c, carol, gateway.Credential{
		AccessToken: principalCacheCanaryToken,
		Mode:        gateway.ModeAuthorizationCode,
	}, gateway.HTTPAuth{Scheme: gateway.HTTPAuthSchemeBearer, Token: principalCacheCanaryToken})
	if _, ok := c.Get(gateway.SubjectKey(carol)); ok {
		t.Fatal("bearer without principal must not cache")
	}
	// Canary: never store token as key or appear via wrong Get.
	if p, ok := c.Get(principalCacheCanaryToken); ok {
		t.Fatalf("token as key: %q", p)
	}
	// Isolation alice vs bob.
	if a, _ := c.Get(gateway.SubjectKey(alice)); a == "bob-j" {
		t.Fatal("cross leak")
	}
}

func TestProcessPrincipalCache_NonNil(t *testing.T) {
	t.Parallel()
	if gateway.ProcessPrincipalCache() == nil {
		t.Fatal("process cache must be non-nil")
	}
	// Do not mutate process cache in parallel tests (inject private caches elsewhere).
	_ = gateway.ProcessPrincipalCache().String()
}
