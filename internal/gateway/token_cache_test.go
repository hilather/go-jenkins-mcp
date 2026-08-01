package gateway_test

import (
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
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
