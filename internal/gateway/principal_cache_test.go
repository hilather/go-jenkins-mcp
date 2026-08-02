package gateway_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
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
	// Unlimited defaults: no max_entries / ttl_seconds keys.
	if _, ok := st["max_entries"]; ok {
		t.Fatalf("unlimited must omit max_entries: %+v", st)
	}
	if _, ok := st["ttl_seconds"]; ok {
		t.Fatalf("no TTL must omit ttl_seconds: %+v", st)
	}
	// Token-shaped principal must never appear in String (count only).
	c.Set(gateway.SubjectKeyParts("tid", "sub2", "corp"), principalCacheCanaryToken)
	if strings.Contains(c.String(), principalCacheCanaryToken) {
		t.Fatal("String leaked canary")
	}
	// Refresh StatusMap after second Set.
	st = c.StatusMap()
	if strings.Contains(fmt.Sprint(st), principalCacheCanaryToken) {
		t.Fatal("StatusMap leaked canary")
	}
	// Subject keys must never appear in StatusMap either (no inventory dump).
	if strings.Contains(fmt.Sprint(st), "tid") || strings.Contains(fmt.Sprint(st), "sub2") {
		t.Fatalf("StatusMap must not dump subjects: %+v", st)
	}
}

func TestPrincipalCache_StatusMap_MaxAndTTL(t *testing.T) {
	t.Parallel()
	c := gateway.NewPrincipalCacheWithLimits(64, 2*time.Hour)
	c.Set(gateway.SubjectKeyParts("t", "u", "p"), "alice-j")
	st := c.StatusMap()
	if st["entries"] != 1 {
		t.Fatalf("entries: %v", st["entries"])
	}
	if st["max_entries"] != 64 {
		t.Fatalf("max_entries: %v", st["max_entries"])
	}
	if st["ttl_seconds"] != int((2*time.Hour)/time.Second) {
		t.Fatalf("ttl_seconds: %v", st["ttl_seconds"])
	}
	// Canary: principal never in status.
	if strings.Contains(fmt.Sprint(st), "alice-j") {
		t.Fatal("StatusMap leaked principal")
	}
}

func TestPrincipalCache_ZeroDefaultsUnlimited(t *testing.T) {
	t.Parallel()
	c := gateway.NewPrincipalCache()
	// Many entries with MaxEntries=0 / TTL=0 must not evict.
	for i := 0; i < 50; i++ {
		c.Set(gateway.SubjectKeyParts("tid", fmt.Sprintf("sub-%d", i), "corp"), fmt.Sprintf("u-%d", i))
	}
	if c.Len() != 50 {
		t.Fatalf("unlimited default len=%d want 50", c.Len())
	}
	// All still present.
	for i := 0; i < 50; i++ {
		p, ok := c.Get(gateway.SubjectKeyParts("tid", fmt.Sprintf("sub-%d", i), "corp"))
		if !ok || p != fmt.Sprintf("u-%d", i) {
			t.Fatalf("entry %d missing: ok=%v p=%q", i, ok, p)
		}
	}
	// WithLimits(0,0) same semantics.
	c2 := gateway.NewPrincipalCacheWithLimits(0, 0)
	c2.Set(gateway.SubjectKeyParts("t", "u", "p"), "x")
	if c2.Len() != 1 {
		t.Fatalf("WithLimits(0,0) len=%d", c2.Len())
	}
}

func TestPrincipalCache_MaxEntries_EvictOldestInsertOrder(t *testing.T) {
	t.Parallel()
	// Without intervening Gets, lastAccess ≈ insert order → oldest insert evicted.
	c := gateway.NewPrincipalCacheWithLimits(2, 0)
	// Deterministic lastAccess via sequential Sets (real clock advances).
	k1 := gateway.SubjectKeyParts("t", "u1", "p")
	k2 := gateway.SubjectKeyParts("t", "u2", "p")
	k3 := gateway.SubjectKeyParts("t", "u3", "p")
	c.Set(k1, "p1")
	// Sleep a tiny bit so lastAccess of k1 is strictly older if clock resolution needs it.
	time.Sleep(2 * time.Millisecond)
	c.Set(k2, "p2")
	time.Sleep(2 * time.Millisecond)
	c.Set(k3, "p3") // should evict k1 (oldest lastAccess)

	if c.Len() != 2 {
		t.Fatalf("len after cap: %d", c.Len())
	}
	if _, ok := c.Get(k1); ok {
		t.Fatal("k1 (oldest) must be evicted")
	}
	if p, ok := c.Get(k2); !ok || p != "p2" {
		t.Fatalf("k2: ok=%v p=%q", ok, p)
	}
	if p, ok := c.Get(k3); !ok || p != "p3" {
		t.Fatalf("k3: ok=%v p=%q", ok, p)
	}
}

func TestPrincipalCache_MaxEntries_LRUOnGet(t *testing.T) {
	t.Parallel()
	c := gateway.NewPrincipalCacheWithLimits(2, 0)
	k1 := gateway.SubjectKeyParts("t", "u1", "p")
	k2 := gateway.SubjectKeyParts("t", "u2", "p")
	k3 := gateway.SubjectKeyParts("t", "u3", "p")
	c.Set(k1, "p1")
	time.Sleep(2 * time.Millisecond)
	c.Set(k2, "p2")
	time.Sleep(2 * time.Millisecond)
	// Touch k1 so it becomes more recently used than k2.
	if _, ok := c.Get(k1); !ok {
		t.Fatal("k1 get")
	}
	time.Sleep(2 * time.Millisecond)
	c.Set(k3, "p3") // should evict k2 (LRU), keep k1

	if _, ok := c.Get(k2); ok {
		t.Fatal("k2 (LRU) must be evicted")
	}
	if p, ok := c.Get(k1); !ok || p != "p1" {
		t.Fatalf("k1 kept: ok=%v p=%q", ok, p)
	}
	if p, ok := c.Get(k3); !ok || p != "p3" {
		t.Fatalf("k3: ok=%v p=%q", ok, p)
	}
}

func TestPrincipalCache_MaxEntries_ReplaceDoesNotGrow(t *testing.T) {
	t.Parallel()
	c := gateway.NewPrincipalCacheWithLimits(2, 0)
	k1 := gateway.SubjectKeyParts("t", "u1", "p")
	k2 := gateway.SubjectKeyParts("t", "u2", "p")
	c.Set(k1, "p1")
	c.Set(k2, "p2")
	c.Set(k1, "p1-updated") // replace, not grow
	if c.Len() != 2 {
		t.Fatalf("len=%d", c.Len())
	}
	if p, ok := c.Get(k1); !ok || p != "p1-updated" {
		t.Fatalf("replace: ok=%v p=%q", ok, p)
	}
	if p, ok := c.Get(k2); !ok || p != "p2" {
		t.Fatalf("k2: ok=%v p=%q", ok, p)
	}
}

func TestPrincipalCache_TTL_Expiry(t *testing.T) {
	t.Parallel()
	// Short TTL with margin for -race / loaded CI (sleep can lag past wall clock).
	c := gateway.NewPrincipalCacheWithLimits(0, 40*time.Millisecond)
	k := gateway.SubjectKeyParts("t", "u", "p")
	c.Set(k, "alice-j")
	if p, ok := c.Get(k); !ok || p != "alice-j" {
		t.Fatalf("before expiry: ok=%v p=%q", ok, p)
	}
	time.Sleep(100 * time.Millisecond)
	if _, ok := c.Get(k); ok {
		t.Fatal("after TTL Get must miss and delete")
	}
	if c.Len() != 0 {
		t.Fatalf("len after TTL miss: %d", c.Len())
	}
	// Re-set works after expiry.
	c.Set(k, "alice-j2")
	if p, ok := c.Get(k); !ok || p != "alice-j2" {
		t.Fatalf("re-set: ok=%v p=%q", ok, p)
	}
}

func TestPrincipalCache_TTL_LenPurgesExpired(t *testing.T) {
	t.Parallel()
	c := gateway.NewPrincipalCacheWithLimits(0, 40*time.Millisecond)
	c.Set(gateway.SubjectKeyParts("t", "u1", "p"), "a")
	c.Set(gateway.SubjectKeyParts("t", "u2", "p"), "b")
	if c.Len() != 2 {
		t.Fatalf("before: %d", c.Len())
	}
	time.Sleep(100 * time.Millisecond)
	if c.Len() != 0 {
		t.Fatalf("Len must purge expired: %d", c.Len())
	}
}

func TestPrincipalCache_ConfigFromEnviron(t *testing.T) {
	t.Parallel()
	max, ttl, err := gateway.PrincipalCacheConfigFromEnviron(func(string) string { return "" })
	if err != nil || max != 0 || ttl != 0 {
		t.Fatalf("empty env: max=%d ttl=%v err=%v", max, ttl, err)
	}
	max, ttl, err = gateway.PrincipalCacheConfigFromEnviron(func(k string) string {
		switch k {
		case gateway.EnvGatewayPrincipalCacheMax:
			return "128"
		case gateway.EnvGatewayPrincipalCacheTTL:
			return "1h30m"
		default:
			return ""
		}
	})
	if err != nil || max != 128 || ttl != 90*time.Minute {
		t.Fatalf("valid: max=%d ttl=%v err=%v", max, ttl, err)
	}
	// Invalid max.
	_, _, err = gateway.PrincipalCacheConfigFromEnviron(func(k string) string {
		if k == gateway.EnvGatewayPrincipalCacheMax {
			return "-1"
		}
		return ""
	})
	if err == nil {
		t.Fatal("want error for negative max")
	}
	_, _, err = gateway.PrincipalCacheConfigFromEnviron(func(k string) string {
		if k == gateway.EnvGatewayPrincipalCacheMax {
			return "nope"
		}
		return ""
	})
	if err == nil {
		t.Fatal("want error for non-int max")
	}
	// Invalid TTL.
	_, _, err = gateway.PrincipalCacheConfigFromEnviron(func(k string) string {
		if k == gateway.EnvGatewayPrincipalCacheTTL {
			return "not-a-duration"
		}
		return ""
	})
	if err == nil {
		t.Fatal("want error for bad TTL")
	}
	// Explicit 0 max is unlimited (allowed).
	max, _, err = gateway.PrincipalCacheConfigFromEnviron(func(k string) string {
		if k == gateway.EnvGatewayPrincipalCacheMax {
			return "0"
		}
		return ""
	})
	if err != nil || max != 0 {
		t.Fatalf("explicit 0 max: max=%d err=%v", max, err)
	}
}

func TestPrincipalCache_ConcurrentSetGet(t *testing.T) {
	t.Parallel()
	c := gateway.NewPrincipalCacheWithLimits(64, time.Hour)
	const n = 100
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(2)
		i := i
		go func() {
			defer wg.Done()
			k := gateway.SubjectKeyParts("t", fmt.Sprintf("u-%d", i%20), "p")
			c.Set(k, fmt.Sprintf("p-%d", i))
		}()
		go func() {
			defer wg.Done()
			k := gateway.SubjectKeyParts("t", fmt.Sprintf("u-%d", i%20), "p")
			_, _ = c.Get(k)
			_ = c.Len()
			_ = c.StatusMap()
			_ = c.String()
		}()
	}
	wg.Wait()
	// Bounded by MaxEntries.
	if c.Len() > 64 {
		t.Fatalf("len over max: %d", c.Len())
	}
	// No panic / race (run with -race). Secret-free status still holds.
	st := fmt.Sprint(c.StatusMap())
	if strings.Contains(st, principalCacheCanaryToken) {
		t.Fatal("status canary")
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
