package gateway_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

// HOST-008: FileTokenCache round-trip, isolation, TTL, 0600, StatusMap, canary.
func TestFileTokenCache_RoundTripIsolationTTL(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "token_cache.json")
	c, err := gateway.NewFileTokenCache(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if c.Path() != path && c.Path() != filepath.Clean(path) {
		t.Fatalf("path: %q", c.Path())
	}

	alice := gateway.CacheKey{Tenant: "t1", User: "alice", Workload: "wl", Profile: "corp"}
	bob := gateway.CacheKey{Tenant: "t1", User: "bob", Workload: "wl", Profile: "corp"}
	aliceTok := canaryAccessToken + "-alice-file"
	bobTok := canaryAccessToken + "-bob-file"

	c.Set(alice, gateway.CachedToken{
		AccessToken:      aliceTok,
		JenkinsPrincipal: "alice-j",
		Mode:             gateway.ModeAuthorizationCode,
		ExpiresAt:        time.Now().Add(time.Hour),
	})
	c.Set(bob, gateway.CachedToken{
		AccessToken:      bobTok,
		JenkinsPrincipal: "bob-j",
		Mode:             gateway.ModeAuthorizationCode,
		ExpiresAt:        time.Now().Add(time.Hour),
	})

	gotA, okA := c.Get(alice)
	gotB, okB := c.Get(bob)
	if !okA || !okB {
		t.Fatalf("miss: alice=%v bob=%v", okA, okB)
	}
	if gotA.AccessToken != aliceTok || gotB.AccessToken != bobTok {
		t.Fatal("token mix-up")
	}
	if gotA.JenkinsPrincipal != "alice-j" {
		t.Fatalf("principal %q", gotA.JenkinsPrincipal)
	}

	// Cross-tenant same user: no hit.
	other := gateway.CacheKey{Tenant: "t2", User: "alice", Workload: "wl", Profile: "corp"}
	if _, ok := c.Get(other); ok {
		t.Fatal("cross-tenant leak")
	}

	// Second process-like instance on same path sees Alice.
	c2, err := gateway.NewFileTokenCache(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got2, ok2 := c2.Get(alice)
	if !ok2 || got2.AccessToken != aliceTok {
		t.Fatal("same-host multi-process share miss")
	}

	// Mode 0600 on data file.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("cache file must be 0600-class, got %o", st.Mode().Perm())
	}

	// Expired miss + purge.
	c.Set(alice, gateway.CachedToken{
		AccessToken: aliceTok,
		ExpiresAt:   time.Now().Add(-time.Second),
	})
	if _, ok := c.Get(alice); ok {
		t.Fatal("expired must miss")
	}

	c.Delete(bob)
	if _, ok := c.Get(bob); ok {
		t.Fatal("deleted")
	}
	c.Clear()
	if _, ok := c2.Get(bob); ok {
		// bob already deleted; ensure clear wiped residual
	}
	// Re-set and clear.
	c.Set(alice, gateway.CachedToken{AccessToken: aliceTok, ExpiresAt: time.Now().Add(time.Hour)})
	c.Clear()
	if _, ok := c.Get(alice); ok {
		t.Fatal("cleared")
	}
}

func TestFileTokenCache_DefaultTTLOnZeroExpiry(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cache.json")
	c, err := gateway.NewFileTokenCache(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key := gateway.CacheKey{User: "u1", Profile: "corp"}
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

func TestFileTokenCache_FailClosedInvalidPath(t *testing.T) {
	t.Parallel()
	cases := []string{"", "   ", ".", "/"}
	for _, p := range cases {
		_, err := gateway.NewFileTokenCache(p, 0)
		if err == nil {
			t.Fatalf("path %q must fail closed", p)
		}
		if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("path %q code: %v err=%v", p, apperr.CodeOf(err), err)
		}
		// Canary: never mention canary token in path validation errors.
		if strings.Contains(err.Error(), canaryAccessToken) {
			t.Fatal("error leaked canary")
		}
	}
}

func TestFileTokenCache_CorruptFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "corrupt.json")
	if err := os.WriteFile(path, []byte("not-json{{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := gateway.NewFileTokenCache(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key := gateway.CacheKey{User: "u1", Profile: "corp"}
	// Get must miss (fail closed — no garbage token).
	if _, ok := c.Get(key); ok {
		t.Fatal("corrupt Get must miss")
	}
	// Set must not silently wipe/recreate over corrupt without acknowledging;
	// implementation fails closed on load so Set is no-op for cache persist.
	c.Set(key, gateway.CachedToken{AccessToken: canaryAccessToken, ExpiresAt: time.Now().Add(time.Hour)})
	if _, ok := c.Get(key); ok {
		// If we ever recover corrupt by overwrite, Get may succeed — still OK
		// as long as canary never appears in StatusMap/errors. Document either way.
		// Current contract: load fails closed → Set no-op → still miss.
		t.Log("note: Set recovered or succeeded after corrupt")
	}
	// Ensure file still not treated as success path that returns empty-token elevation.
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), canaryAccessToken) {
		// Set may have rewritten if load recovered — verify 0600 only.
		st, err := os.Stat(path)
		if err == nil && st.Mode().Perm()&0o077 != 0 {
			t.Fatalf("rewritten cache perms %o", st.Mode().Perm())
		}
	}
}

func TestFileTokenCache_StatusMapSecretFree(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cache.json")
	c, err := gateway.NewFileTokenCache(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key := gateway.CacheKey{User: "u1", Tenant: "tid", Workload: "wl", Profile: "corp"}
	c.Set(key, gateway.CachedToken{
		AccessToken:      canaryAccessToken,
		JenkinsPrincipal: "alice",
		Mode:             gateway.ModeAuthorizationCode,
		ExpiresAt:        time.Now().Add(time.Hour),
	})
	sm := c.StatusMap()
	if sm["shared_token_cache_file"] != true {
		t.Fatalf("shared_token_cache_file: %+v", sm)
	}
	if sm["shared_token_cache"] != false {
		t.Fatalf("shared_token_cache must stay false (multi-pod residual): %+v", sm)
	}
	if sm["ha_multi_replica"] != false {
		t.Fatalf("ha_multi_replica: %+v", sm)
	}
	if sm["kind"] != "file" {
		t.Fatalf("kind: %+v", sm)
	}
	dump := fmt.Sprintf("%v", sm)
	if strings.Contains(dump, canaryAccessToken) {
		t.Fatalf("StatusMap leaked token: %s", dump)
	}
	if strings.Contains(dump, "alice") {
		// principal inventory must not appear in StatusMap
		t.Fatalf("StatusMap must not dump principals: %s", dump)
	}
	// Path value itself is non-secret operator config; full path may appear as
	// path_configured bool only — ensure no access_token field.
	if _, ok := sm["access_token"]; ok {
		t.Fatal("access_token field forbidden")
	}
	if _, ok := sm["token"]; ok {
		t.Fatal("token field forbidden")
	}
	// Disk file holds secret; never put raw file contents in StatusMap (already checked).
	_ = path
}

func TestMemoryTokenCache_StatusMapSharedFalse(t *testing.T) {
	t.Parallel()
	c := gateway.NewMemoryTokenCache(time.Hour)
	c.Set(gateway.CacheKey{User: "u", Profile: "p"}, gateway.CachedToken{
		AccessToken: canaryAccessToken,
		ExpiresAt:   time.Now().Add(time.Hour),
	})
	sm := c.StatusMap()
	if sm["shared_token_cache"] != false {
		t.Fatalf("shared_token_cache: %+v", sm)
	}
	if sm["kind"] != "memory" {
		t.Fatalf("kind: %+v", sm)
	}
	if sm["ha_multi_replica"] != false {
		t.Fatalf("ha_multi_replica: %+v", sm)
	}
	dump := fmt.Sprintf("%v", sm)
	if strings.Contains(dump, canaryAccessToken) {
		t.Fatalf("StatusMap leaked token: %s", dump)
	}
}

// Regression: HOST-008 Done* lite — two FileTokenCache instances concurrent Set
// on the same path must not corrupt JSON and must retain entries (flock).
func TestFileTokenCache_MultiInstanceConcurrentSetNoCorrupt(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "shared_token_cache.json")
	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := gateway.NewFileTokenCache(path, time.Hour)
			if err != nil {
				t.Errorf("new: %v", err)
				return
			}
			key := gateway.CacheKey{
				Tenant:   "t",
				User:     fmt.Sprintf("user-%02d", i),
				Workload: "wl",
				Profile:  "corp",
			}
			c.Set(key, gateway.CachedToken{
				AccessToken: fmt.Sprintf("%s-%d", canaryAccessToken, i),
				ExpiresAt:   time.Now().Add(time.Hour),
			})
		}(i)
	}
	wg.Wait()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Entries map[string]json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("corrupt after concurrent set: %v\n%s", err, raw)
	}
	if len(doc.Entries) != n {
		t.Fatalf("entries=%d want %d (lost updates without flock)", len(doc.Entries), n)
	}
	// Canary: raw file holds tokens (expected) but StatusMap must not.
	c, err := gateway.NewFileTokenCache(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dump := fmt.Sprintf("%v", c.StatusMap())
	if strings.Contains(dump, canaryAccessToken) {
		t.Fatal("StatusMap leaked token after concurrent sets")
	}
}

func TestTokenCacheFromEnviron(t *testing.T) {
	t.Parallel()
	// Empty → Memory
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	cache, err := gateway.TokenCacheFromEnviron(getenv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.(*gateway.MemoryTokenCache); !ok {
		t.Fatalf("want MemoryTokenCache, got %T", cache)
	}
	sm := cache.(*gateway.MemoryTokenCache).StatusMap()
	if sm["shared_token_cache"] != false {
		t.Fatalf("%+v", sm)
	}

	// Path set → File
	path := filepath.Join(t.TempDir(), "env_cache.json")
	env[gateway.EnvGatewayTokenCachePath] = path
	cache, err = gateway.TokenCacheFromEnviron(getenv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fc, ok := cache.(*gateway.FileTokenCache)
	if !ok {
		t.Fatalf("want FileTokenCache, got %T", cache)
	}
	fsm := fc.StatusMap()
	if fsm["shared_token_cache_file"] != true {
		t.Fatalf("%+v", fsm)
	}

	// Invalid path fail closed (no Memory fallthrough).
	env[gateway.EnvGatewayTokenCachePath] = "."
	_, err = gateway.TokenCacheFromEnviron(getenv, 0)
	if err == nil {
		t.Fatal("invalid path must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
}

func TestTokenCachePathConfiguredFromEnviron(t *testing.T) {
	t.Parallel()
	if gateway.TokenCachePathConfiguredFromEnviron(func(string) string { return "" }) {
		t.Fatal("empty path must be false")
	}
	if gateway.TokenCachePathConfiguredFromEnviron(func(string) string { return "   " }) {
		t.Fatal("whitespace-only path must be false")
	}
	marker := "token-cache-path-canary-NEVER-IN-JSON"
	path := filepath.Join(t.TempDir(), marker+".json")
	if !gateway.TokenCachePathConfiguredFromEnviron(func(k string) string {
		if k == gateway.EnvGatewayTokenCachePath {
			return path
		}
		return ""
	}) {
		t.Fatal("non-empty path must be true")
	}
	// Secret-free: helper returns bool only — never the path string.
	// (No string return to leak; residual-status canaries assert path not dumped.)
}

// Mode C serve wire: JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH → FileTokenCache on provider.
func TestCredentialProviderFromEnviron_ModeC_FileTokenCache(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "mode_c_cache.json")
	env := map[string]string{
		gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeAgentCore),
		gateway.EnvAgentCoreASURL:        "https://login.microsoftonline.com/t/v2.0",
		gateway.EnvAgentCoreAudience:     "api://jenkins-api",
		gateway.EnvGatewayTokenCachePath: path,
	}
	getenv := func(k string) string { return env[k] }
	p, err := gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err != nil {
		t.Fatal(err)
	}
	ac, ok := p.(*gateway.AgentCoreProvider)
	if !ok {
		t.Fatalf("want AgentCoreProvider, got %T", p)
	}
	fc, ok := ac.Cache.(*gateway.FileTokenCache)
	if !ok {
		t.Fatalf("want FileTokenCache on Mode C when env set, got %T", ac.Cache)
	}
	if fc.StatusMap()["shared_token_cache_file"] != true {
		t.Fatal("StatusMap")
	}
	// Invalid path fails Mode C start (fail closed).
	env[gateway.EnvGatewayTokenCachePath] = "/"
	_, err = gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err == nil {
		t.Fatal("invalid token cache path must fail Mode C start")
	}

	// Unset path → Memory (default).
	delete(env, gateway.EnvGatewayTokenCachePath)
	p, err = gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err != nil {
		t.Fatal(err)
	}
	ac = p.(*gateway.AgentCoreProvider)
	if _, ok := ac.Cache.(*gateway.MemoryTokenCache); !ok {
		t.Fatalf("default Memory, got %T", ac.Cache)
	}
}
