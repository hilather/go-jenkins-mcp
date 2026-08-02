package gateway_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

func TestMemoryTokenCache_RoundTripAndTTL(t *testing.T) {
	t.Parallel()
	c := gateway.NewMemoryTokenCache(50 * time.Millisecond)
	key := gateway.CacheKey{User: "u1", Workload: "wl", Profile: "corp"}
	c.Set(key, gateway.CachedToken{
		AccessToken:      canaryAccessToken,
		JenkinsPrincipal: "alice",
		Mode:             gateway.ModeAuthorizationCode,
		ExpiresAt:        time.Now().Add(time.Hour),
	})
	got, ok := c.Get(key)
	if !ok || got.AccessToken != canaryAccessToken {
		t.Fatalf("get: ok=%v tok=%v", ok, got.AccessToken != "")
	}
	// Isolation: different workload does not share.
	if _, ok := c.Get(gateway.CacheKey{User: "u1", Workload: "other", Profile: "corp"}); ok {
		t.Fatal("cross-workload leak")
	}
	if _, ok := c.Get(gateway.CacheKey{User: "u2", Workload: "wl", Profile: "corp"}); ok {
		t.Fatal("cross-user leak")
	}
	c.Delete(key)
	if _, ok := c.Get(key); ok {
		t.Fatal("deleted")
	}
}

func TestMemoryTokenCache_Expired(t *testing.T) {
	t.Parallel()
	c := gateway.NewMemoryTokenCache(time.Hour)
	key := gateway.CacheKey{User: "u1", Workload: "wl", Profile: "corp"}
	c.Set(key, gateway.CachedToken{
		AccessToken: canaryAccessToken,
		ExpiresAt:   time.Now().Add(-time.Second),
	})
	if _, ok := c.Get(key); ok {
		t.Fatal("expired entry must miss")
	}
}

func TestMemoryTokenCache_DefaultTTLOnZeroExpiry(t *testing.T) {
	t.Parallel()
	c := gateway.NewMemoryTokenCache(time.Hour)
	key := gateway.CacheKey{User: "u1", Workload: "", Profile: "corp"}
	c.Set(key, gateway.CachedToken{AccessToken: canaryAccessToken})
	got, ok := c.Get(key)
	if !ok {
		t.Fatal("miss")
	}
	if got.ExpiresAt.Before(time.Now()) {
		t.Fatal("should have future expiry")
	}
	if strings.Contains(got.String(), canaryAccessToken) {
		t.Fatal("String leaked token")
	}
}

func TestMemoryTokenCache_Clear(t *testing.T) {
	t.Parallel()
	c := gateway.NewMemoryTokenCache(0)
	c.Set(gateway.CacheKey{User: "a", Profile: "p"}, gateway.CachedToken{AccessToken: "t1", ExpiresAt: time.Now().Add(time.Hour)})
	c.Set(gateway.CacheKey{User: "b", Profile: "p"}, gateway.CachedToken{AccessToken: "t2", ExpiresAt: time.Now().Add(time.Hour)})
	c.Clear()
	if _, ok := c.Get(gateway.CacheKey{User: "a", Profile: "p"}); ok {
		t.Fatal("cleared")
	}
}

func TestCacheKeyStringNoSecrets(t *testing.T) {
	t.Parallel()
	k := gateway.CacheKey{User: "u", Workload: "w", Profile: "p"}
	s := k.String()
	if strings.Contains(s, canaryAccessToken) {
		t.Fatal(s)
	}
	if !k.Valid() {
		t.Fatal("valid")
	}
	if (gateway.CacheKey{}).Valid() {
		t.Fatal("empty invalid")
	}
}

// HOST-004: two-user offline isolation — no shared cache hit leakage.
func TestMemoryTokenCache_HOST004_TwoUserNoCrossHit(t *testing.T) {
	t.Parallel()
	c := gateway.NewMemoryTokenCache(time.Hour)

	aliceCaller := gateway.Caller{
		Subject:    "alice-sub",
		Tenant:     "tenant-a",
		WorkloadID: "wl-1",
		ProfileID:  "corp",
	}
	bobCaller := gateway.Caller{
		Subject:    "bob-sub",
		Tenant:     "tenant-a",
		WorkloadID: "wl-1",
		ProfileID:  "corp",
	}
	aliceKey := aliceCaller.CacheKey()
	bobKey := bobCaller.CacheKey()

	// Namespace keys are distinct SubjectKey shapes.
	if aliceCaller.SubjectKey() == bobCaller.SubjectKey() {
		t.Fatal("alice and bob subject keys must differ")
	}
	if aliceKey.NamespaceSubjectKey() != aliceCaller.SubjectKey() {
		t.Fatalf("namespace: got %q want %q", aliceKey.NamespaceSubjectKey(), aliceCaller.SubjectKey())
	}

	aliceTok := canaryAccessToken + "-alice-host004"
	bobTok := canaryAccessToken + "-bob-host004"
	c.Set(aliceKey, gateway.CachedToken{
		AccessToken:      aliceTok,
		JenkinsPrincipal: "alice-j",
		Mode:             gateway.ModeAuthorizationCode,
		ExpiresAt:        time.Now().Add(time.Hour),
	})
	c.Set(bobKey, gateway.CachedToken{
		AccessToken:      bobTok,
		JenkinsPrincipal: "bob-j",
		Mode:             gateway.ModeAuthorizationCode,
		ExpiresAt:        time.Now().Add(time.Hour),
	})

	gotA, okA := c.Get(aliceKey)
	gotB, okB := c.Get(bobKey)
	if !okA || !okB {
		t.Fatalf("miss: alice=%v bob=%v", okA, okB)
	}
	if gotA.AccessToken != aliceTok || gotB.AccessToken != bobTok {
		t.Fatal("token mix-up across subjects")
	}
	if gotA.AccessToken == gotB.AccessToken {
		t.Fatal("cross-user token collision")
	}
	// Bob's key must not return Alice's entry when Alice-only key used wrongly:
	// already covered; also ensure SubjectKeyHash path never confuses entries.
	if gateway.SubjectKeyHash(aliceCaller.SubjectKey()) == gateway.SubjectKeyHash(bobCaller.SubjectKey()) {
		t.Fatal("subject key hashes collided")
	}

	// Cross-tenant same subject label: no shared hit (HOST-004 multi-tenant).
	otherTenant := gateway.Caller{
		Subject:    "alice-sub",
		Tenant:     "tenant-b",
		WorkloadID: "wl-1",
		ProfileID:  "corp",
	}
	if _, ok := c.Get(otherTenant.CacheKey()); ok {
		t.Fatal("cross-tenant cache hit leakage")
	}

	// Secret-free String()
	if strings.Contains(aliceKey.String(), aliceTok) || strings.Contains(gotA.String(), aliceTok) {
		t.Fatal("String leaked token")
	}
}

// HOST-004: CacheKey from Caller includes tenant so multi-tenant keys diverge.
func TestCallerCacheKey_IncludesTenant(t *testing.T) {
	t.Parallel()
	a := gateway.Caller{Subject: "u1", Tenant: "t1", WorkloadID: "w", ProfileID: "p"}
	b := gateway.Caller{Subject: "u1", Tenant: "t2", WorkloadID: "w", ProfileID: "p"}
	if a.CacheKey() == b.CacheKey() {
		t.Fatal("different tenants must produce different cache keys")
	}
	if a.SubjectKey() == b.SubjectKey() {
		t.Fatal("different tenants must produce different subject keys")
	}
}
