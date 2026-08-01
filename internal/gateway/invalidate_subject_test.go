package gateway_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

const invalidateCanaryToken = "INV-CANARY-token-never-in-status-zz9"

func TestInvalidateSubjectLocal_PrincipalAndToken(t *testing.T) {
	t.Parallel()
	pc := gateway.NewPrincipalCache()
	tc := gateway.NewMemoryTokenCache(time.Hour)
	alice := gateway.Caller{
		Subject: "alice-sub", Tenant: "tid-1", WorkloadID: "wl-a", ProfileID: contracts.ProfileID("corp"),
	}
	bob := gateway.Caller{
		Subject: "bob-sub", Tenant: "tid-1", WorkloadID: "wl-b", ProfileID: contracts.ProfileID("corp"),
	}
	pc.Set(gateway.SubjectKey(alice), "alice-j")
	pc.Set(gateway.SubjectKey(bob), "bob-j")
	tc.Set(alice.CacheKey(), gateway.CachedToken{
		AccessToken: invalidateCanaryToken + "-a", ExpiresAt: time.Now().Add(time.Hour),
		JenkinsPrincipal: "alice-j",
	})
	// Second workload for alice — subject-namespace purge must drop both.
	aliceWL2 := alice
	aliceWL2.WorkloadID = "wl-a2"
	tc.Set(aliceWL2.CacheKey(), gateway.CachedToken{
		AccessToken: invalidateCanaryToken + "-a2", ExpiresAt: time.Now().Add(time.Hour),
	})
	tc.Set(bob.CacheKey(), gateway.CachedToken{
		AccessToken: invalidateCanaryToken + "-b", ExpiresAt: time.Now().Add(time.Hour),
		JenkinsPrincipal: "bob-j",
	})

	res := gateway.InvalidateSubjectLocal(alice, pc, tc)
	if !res.PrincipalCleared || !res.TokenCacheCleared {
		t.Fatalf("cleared flags: %+v", res)
	}
	if res.TokenCacheEntriesDeleted != 2 {
		t.Fatalf("entries deleted: %d want 2", res.TokenCacheEntriesDeleted)
	}
	if res.SubjectKey != gateway.SubjectKey(alice) {
		t.Fatalf("subject_key: %q", res.SubjectKey)
	}
	if res.SubjectKeyHash != audit.HashOpaque(gateway.SubjectKey(alice)) {
		t.Fatalf("hash: %q want %q", res.SubjectKeyHash, audit.HashOpaque(gateway.SubjectKey(alice)))
	}
	if _, ok := pc.Get(gateway.SubjectKey(alice)); ok {
		t.Fatal("alice principal must be gone")
	}
	if p, ok := pc.Get(gateway.SubjectKey(bob)); !ok || p != "bob-j" {
		t.Fatalf("bob principal must remain: ok=%v p=%q", ok, p)
	}
	if _, ok := tc.Get(alice.CacheKey()); ok {
		t.Fatal("alice token must miss")
	}
	if _, ok := tc.Get(aliceWL2.CacheKey()); ok {
		t.Fatal("alice wl2 token must miss")
	}
	if _, ok := tc.Get(bob.CacheKey()); !ok {
		t.Fatal("bob token must remain")
	}
	// Secret-free StatusMap / residual.
	st := res.StatusMap()
	blob := strings.ToLower(fmt.Sprint(st) + res.TokenCacheNote + res.ResidualNote)
	if strings.Contains(blob, strings.ToLower(invalidateCanaryToken)) {
		t.Fatal("canary leaked in result")
	}
	if !strings.Contains(res.ResidualNote, "multi-pod") {
		t.Fatalf("residual: %q", res.ResidualNote)
	}
}

func TestInvalidateSubjectLocal_NilCaches(t *testing.T) {
	t.Parallel()
	caller := gateway.Caller{Subject: "s", Tenant: "t", ProfileID: "p"}
	res := gateway.InvalidateSubjectLocal(caller, nil, nil)
	if res.PrincipalCleared || res.TokenCacheCleared {
		t.Fatalf("nil caches must not claim clear: %+v", res)
	}
	if !strings.Contains(res.TokenCacheNote, "token_cache not provided") {
		t.Fatalf("note: %q", res.TokenCacheNote)
	}
}

func TestInvalidateSubjectKeyLocal_ComposeAndReject(t *testing.T) {
	t.Parallel()
	pc := gateway.NewPrincipalCache()
	sk := gateway.SubjectKeyParts("tid", "user-1", "corp")
	pc.Set(sk, "u-j")
	res, err := gateway.InvalidateSubjectKeyLocal(sk, "", pc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.PrincipalCleared {
		t.Fatal("want principal cleared")
	}
	if _, ok := pc.Get(sk); ok {
		t.Fatal("must delete")
	}
	// Fail closed malformed.
	if _, err := gateway.InvalidateSubjectKeyLocal("not-a-key", "", pc, nil); err == nil {
		t.Fatal("want error for malformed key")
	}
	if _, err := gateway.InvalidateSubjectKeyLocal("", "", pc, nil); err == nil {
		t.Fatal("want error for empty key")
	}
}

func TestSplitSubjectKey(t *testing.T) {
	t.Parallel()
	ten, sub, prof, err := gateway.SplitSubjectKey("t1|alice|corp")
	if err != nil || ten != "t1" || sub != "alice" || prof != "corp" {
		t.Fatalf("got %q %q %q err=%v", ten, sub, prof, err)
	}
	if _, _, _, err := gateway.SplitSubjectKey("a|b"); err == nil {
		t.Fatal("want 3 fields")
	}
	if _, _, _, err := gateway.SplitSubjectKey("| |p"); err == nil {
		t.Fatal("empty subject must fail")
	}
}

func TestAgentCoreProvider_InvalidateDropsPrincipal(t *testing.T) {
	t.Parallel()
	pc := gateway.NewPrincipalCache()
	cache := gateway.NewMemoryTokenCache(time.Hour)
	// Seed cache + principal without full Obtain (avoids AgentCoreConfig matrix).
	caller := gateway.Caller{
		Subject: "alice-inv", Tenant: "tid", WorkloadID: "wl", ProfileID: "corp",
	}
	cache.Set(caller.CacheKey(), gateway.CachedToken{
		AccessToken: invalidateCanaryToken, ExpiresAt: time.Now().Add(time.Hour),
		JenkinsPrincipal: "alice-j",
	})
	pc.Set(gateway.SubjectKey(caller), "alice-j")
	p := &gateway.AgentCoreProvider{
		Cache:      cache,
		Principals: pc,
	}
	if err := p.Invalidate(context.Background(), caller); err != nil {
		t.Fatal(err)
	}
	if _, ok := pc.Get(gateway.SubjectKey(caller)); ok {
		t.Fatal("principal must drop on Invalidate")
	}
	if _, ok := cache.Get(caller.CacheKey()); ok {
		t.Fatal("token must drop on Invalidate")
	}
	// Peer isolation: bob untouched.
	bob := gateway.Caller{Subject: "bob-inv", Tenant: "tid", ProfileID: "corp"}
	pc.Set(gateway.SubjectKey(bob), "bob-j")
	cache.Set(bob.CacheKey(), gateway.CachedToken{
		AccessToken: invalidateCanaryToken + "-bob", ExpiresAt: time.Now().Add(time.Hour),
	})
	if err := p.Invalidate(context.Background(), caller); err != nil {
		t.Fatal(err)
	}
	if p, ok := pc.Get(gateway.SubjectKey(bob)); !ok || p != "bob-j" {
		t.Fatalf("bob principal: ok=%v p=%q", ok, p)
	}
	if _, ok := cache.Get(bob.CacheKey()); !ok {
		t.Fatal("bob token must remain")
	}
}

func TestAPITokenAndJWT_InvalidateDropsPrincipalOnly(t *testing.T) {
	t.Parallel()
	pc := gateway.NewPrincipalCache()
	caller := gateway.Caller{Subject: "u1", Tenant: "t", ProfileID: "corp"}
	pc.Set(gateway.SubjectKey(caller), "u-j")

	a := gateway.NewAPITokenVaultProvider(nil)
	a.Principals = pc
	if err := a.Invalidate(context.Background(), caller); err != nil {
		t.Fatal(err)
	}
	if _, ok := pc.Get(gateway.SubjectKey(caller)); ok {
		t.Fatal("mode A Invalidate must clear principal")
	}

	pc.Set(gateway.SubjectKey(caller), "u-j")
	b := gateway.NewJWTRSBearerProvider(nil)
	b.Principals = pc
	if err := b.Invalidate(context.Background(), caller); err != nil {
		t.Fatal(err)
	}
	if _, ok := pc.Get(gateway.SubjectKey(caller)); ok {
		t.Fatal("mode B Invalidate must clear principal")
	}
}

func TestMemoryTokenCache_DeleteBySubjectKey(t *testing.T) {
	t.Parallel()
	c := gateway.NewMemoryTokenCache(time.Hour)
	alice1 := gateway.CacheKey{Tenant: "t", User: "alice", Workload: "w1", Profile: "corp"}
	alice2 := gateway.CacheKey{Tenant: "t", User: "alice", Workload: "w2", Profile: "corp"}
	bob := gateway.CacheKey{Tenant: "t", User: "bob", Workload: "w1", Profile: "corp"}
	exp := time.Now().Add(time.Hour)
	c.Set(alice1, gateway.CachedToken{AccessToken: invalidateCanaryToken + "1", ExpiresAt: exp})
	c.Set(alice2, gateway.CachedToken{AccessToken: invalidateCanaryToken + "2", ExpiresAt: exp})
	c.Set(bob, gateway.CachedToken{AccessToken: invalidateCanaryToken + "b", ExpiresAt: exp})
	sk := alice1.NamespaceSubjectKey()
	n := c.DeleteBySubjectKey(sk)
	if n != 2 {
		t.Fatalf("deleted=%d want 2", n)
	}
	if _, ok := c.Get(alice1); ok {
		t.Fatal("alice1")
	}
	if _, ok := c.Get(bob); !ok {
		t.Fatal("bob remains")
	}
}

func TestFileTokenCache_DeleteBySubjectKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "tok.json")
	c, err := gateway.NewFileTokenCache(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	alice := gateway.CacheKey{Tenant: "t", User: "alice", Workload: "w1", Profile: "corp"}
	bob := gateway.CacheKey{Tenant: "t", User: "bob", Workload: "w1", Profile: "corp"}
	exp := time.Now().Add(time.Hour)
	c.Set(alice, gateway.CachedToken{AccessToken: invalidateCanaryToken + "a", ExpiresAt: exp})
	c.Set(bob, gateway.CachedToken{AccessToken: invalidateCanaryToken + "b", ExpiresAt: exp})
	n := c.DeleteBySubjectKey(alice.NamespaceSubjectKey())
	if n != 1 {
		t.Fatalf("deleted=%d", n)
	}
	if _, ok := c.Get(alice); ok {
		t.Fatal("alice must miss")
	}
	if _, ok := c.Get(bob); !ok {
		t.Fatal("bob remains")
	}
}
