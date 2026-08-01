package gateway_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

const filePrincipalCanaryToken = "fpc-canary-access-token-NEVER-LOG"

// HOST-008: FilePrincipalCache Alice/Bob isolation, cross-instance share, Delete.
func TestFilePrincipalCache_AliceBobIsolationAndCrossInstance(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "principal_cache.json")
	c, err := gateway.NewFilePrincipalCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Path() != path && c.Path() != filepath.Clean(path) {
		t.Fatalf("path: %q", c.Path())
	}

	alice := gateway.SubjectKeyParts("t1", "alice-sub", "corp")
	bob := gateway.SubjectKeyParts("t1", "bob-sub", "corp")
	c.Set(alice, "alice-j")
	c.Set(bob, "bob-j")

	gotA, okA := c.Get(alice)
	gotB, okB := c.Get(bob)
	if !okA || gotA != "alice-j" {
		t.Fatalf("alice: ok=%v p=%q", okA, gotA)
	}
	if !okB || gotB != "bob-j" {
		t.Fatalf("bob: ok=%v p=%q", okB, gotB)
	}
	if _, ok := c.Get(gateway.SubjectKeyParts("t1", "carol-sub", "corp")); ok {
		t.Fatal("carol must miss")
	}
	// Cross-tenant same subject label: no hit.
	if _, ok := c.Get(gateway.SubjectKeyParts("t2", "alice-sub", "corp")); ok {
		t.Fatal("cross-tenant leak")
	}

	// Second process-like instance on same path sees Alice after Set.
	c2, err := gateway.NewFilePrincipalCache(path)
	if err != nil {
		t.Fatal(err)
	}
	got2, ok2 := c2.Get(alice)
	if !ok2 || got2 != "alice-j" {
		t.Fatal("same-host multi-process share miss after Set")
	}

	// Delete from second handle visible to first.
	c2.Delete(alice)
	if _, ok := c.Get(alice); ok {
		t.Fatal("Delete from second handle must be visible")
	}
	if p, ok := c.Get(bob); !ok || p != "bob-j" {
		t.Fatalf("bob must remain: ok=%v p=%q", ok, p)
	}

	// Mode 0600 on data file.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("cache file must be 0600-class, got %o", st.Mode().Perm())
	}
}

func TestFilePrincipalCache_RejectEmptyAndInvalid(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "pc.json")
	c, err := gateway.NewFilePrincipalCache(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Set("", "alice-j")
	c.Set("  ", "alice-j")
	c.Set(gateway.SubjectKeyParts("t", "u", "p"), "")
	c.Set(gateway.SubjectKeyParts("t", "u", "p"), "  ")
	if c.Len() != 0 {
		t.Fatalf("empty key/principal must not store: len=%d", c.Len())
	}
	var nilC *gateway.FilePrincipalCache
	nilC.Set("t|u|p", "x")
	if _, ok := nilC.Get("t|u|p"); ok {
		t.Fatal("nil Get")
	}
	nilC.Delete("t|u|p")
	nilC.Clear()
	if nilC.Len() != 0 {
		t.Fatal("nil Len")
	}
}

func TestFilePrincipalCache_FailClosedInvalidPath(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"", "   ", ".", "/"} {
		_, err := gateway.NewFilePrincipalCache(p)
		if err == nil {
			t.Fatalf("path %q must fail closed", p)
		}
		if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("path %q code: %v err=%v", p, apperr.CodeOf(err), err)
		}
		if strings.Contains(err.Error(), filePrincipalCanaryToken) {
			t.Fatal("error leaked canary")
		}
	}
}

func TestFilePrincipalCache_SecretFreeCanary(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "pc.json")
	c, err := gateway.NewFilePrincipalCache(path)
	if err != nil {
		t.Fatal(err)
	}
	// Never store canary token as principal value in Status/String — we store
	// a legitimate principal id; canary must not appear in status surfaces.
	sk := gateway.SubjectKeyParts("tid", "sub", "corp")
	c.Set(sk, "alice-j")
	// Attempt to plant token as forbidden key is rejected on Set.
	c.Set("access_token", filePrincipalCanaryToken)
	c.Set("token", filePrincipalCanaryToken)

	s := c.String()
	st := c.StatusMap()
	blob, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, surface := range []string{s, string(blob)} {
		if strings.Contains(surface, filePrincipalCanaryToken) {
			t.Fatalf("canary in surface: %s", surface)
		}
		if strings.Contains(surface, "alice-j") {
			t.Fatalf("principal dump in surface: %s", surface)
		}
		if strings.Contains(surface, sk) {
			t.Fatalf("subject inventory in surface: %s", surface)
		}
	}
	if st["shared_principal_cache_file"] != true {
		t.Fatalf("shared_principal_cache_file: %+v", st)
	}
	if st["shared_principal_cache"] != false {
		t.Fatalf("shared_principal_cache multi-pod residual: %+v", st)
	}
	// Path value must not appear in StatusMap.
	if _, ok := st["path"]; ok {
		t.Fatal("StatusMap must not include path value")
	}
	// On-disk file must not contain canary token.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), filePrincipalCanaryToken) {
		t.Fatal("canary token written to principal cache file")
	}
	if !strings.Contains(string(raw), "alice-j") {
		t.Fatal("expected principal id on disk")
	}
}

func TestFilePrincipalCache_RejectForbiddenKeysOnLoad(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "bad.json")
	// Polluted document with access_token field.
	bad := []byte(`{"version":1,"access_token":"evil","entries":{"t|u|p":{"principal":"u"}}}`)
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := gateway.NewFilePrincipalCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get(gateway.SubjectKeyParts("t", "u", "p")); ok {
		t.Fatal("forbidden key document must fail closed (miss)")
	}
	// Entry key pollution.
	bad2 := filepath.Join(t.TempDir(), "bad2.json")
	if err := os.WriteFile(bad2, []byte(`{"version":1,"entries":{"access_token":{"principal":"x"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c2, err := gateway.NewFilePrincipalCache(bad2)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Len() != 0 {
		t.Fatal("forbidden entry key must not load")
	}
	// Nested token field on entry.
	bad3 := filepath.Join(t.TempDir(), "bad3.json")
	if err := os.WriteFile(bad3, []byte(`{"version":1,"entries":{"t|u|p":{"principal":"u","access_token":"evil"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c3, err := gateway.NewFilePrincipalCache(bad3)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c3.Get("t|u|p"); ok {
		t.Fatal("entry with access_token field must fail closed")
	}
}

func TestFilePrincipalCache_CorruptFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "corrupt.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := gateway.NewFilePrincipalCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get(gateway.SubjectKeyParts("t", "u", "p")); ok {
		t.Fatal("corrupt must miss")
	}
	// Set must not wipe corrupt file with empty success (fail closed on load).
	c.Set(gateway.SubjectKeyParts("t", "u", "p"), "u-j")
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "u-j") {
		// If write succeeded after treating corrupt as empty, that would be a wipe bug.
		// loadLocked fails → Set no-ops → file stays corrupt.
		t.Fatal("Set must not rewrite corrupt file with new principal")
	}
}

func TestFilePrincipalCache_TTLAndMaxEntries(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "hygiene.json")
	now := time.Now()
	c, err := gateway.NewFilePrincipalCacheWithLimits(path, 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Inject clock via package — FilePrincipalCache.now is unexported.
	// Exercise TTL via short-lived expires by writing entry then advancing with re-open + manual file edit.
	// MaxEntries: fill 2, Set third evicts LRU.
	c.Set(gateway.SubjectKeyParts("t", "a", "p"), "a-j")
	// Distinct last_access under -race / loaded CI: short sleeps can coalesce.
	time.Sleep(25 * time.Millisecond)
	c.Set(gateway.SubjectKeyParts("t", "b", "p"), "b-j")
	time.Sleep(25 * time.Millisecond)
	// Touch a so b is older — Get updates lastAccess — then insert c.
	if _, ok := c.Get(gateway.SubjectKeyParts("t", "a", "p")); !ok {
		t.Fatal("a miss")
	}
	time.Sleep(25 * time.Millisecond)
	c.Set(gateway.SubjectKeyParts("t", "c", "p"), "c-j")
	if c.Len() > 2 {
		t.Fatalf("max entries: %d", c.Len())
	}
	// b should be LRU victim (a was touched).
	if _, ok := c.Get(gateway.SubjectKeyParts("t", "b", "p")); ok {
		t.Fatal("b should be evicted as LRU")
	}
	if _, ok := c.Get(gateway.SubjectKeyParts("t", "a", "p")); !ok {
		t.Fatal("a should remain")
	}
	if _, ok := c.Get(gateway.SubjectKeyParts("t", "c", "p")); !ok {
		t.Fatal("c should remain")
	}

	// TTL: short limit then wait past expiry (margin for slow CI).
	path2 := filepath.Join(t.TempDir(), "ttl.json")
	cTTL, err := gateway.NewFilePrincipalCacheWithLimits(path2, 0, 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	sk := gateway.SubjectKeyParts("t", "ttl", "p")
	cTTL.Set(sk, "ttl-j")
	if _, ok := cTTL.Get(sk); !ok {
		t.Fatal("ttl immediate hit")
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok := cTTL.Get(sk); ok {
		t.Fatal("ttl expired must miss")
	}
	_ = now
}

func TestFilePrincipalCache_ClearAndConcurrent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "conc.json")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := gateway.NewFilePrincipalCache(path)
			if err != nil {
				t.Errorf("new: %v", err)
				return
			}
			sk := gateway.SubjectKeyParts("t", "u"+string(rune('a'+i%4)), "p")
			c.Set(sk, "p-j")
			_, _ = c.Get(sk)
			if i%3 == 0 {
				c.Delete(sk)
			}
		}(i)
	}
	wg.Wait()
	c, err := gateway.NewFilePrincipalCache(path)
	if err != nil {
		t.Fatal(err)
	}
	// Must remain readable JSON.
	c.Set(gateway.SubjectKeyParts("t", "final", "p"), "final-j")
	if p, ok := c.Get(gateway.SubjectKeyParts("t", "final", "p")); !ok || p != "final-j" {
		t.Fatalf("final: ok=%v p=%q", ok, p)
	}
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("clear: %d", c.Len())
	}
}

func TestPrincipalCachePathConfiguredFromEnviron(t *testing.T) {
	t.Parallel()
	if gateway.EnvGatewayPrincipalCachePath != "JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH" {
		t.Fatalf("env name: %q", gateway.EnvGatewayPrincipalCachePath)
	}
	getenv := func(k string) string {
		if k == gateway.EnvGatewayPrincipalCachePath {
			return "/tmp/pc.json"
		}
		return ""
	}
	if !gateway.PrincipalCachePathConfiguredFromEnviron(getenv) {
		t.Fatal("want configured true")
	}
	if gateway.PrincipalCachePathConfiguredFromEnviron(func(string) string { return "" }) {
		t.Fatal("empty path → false")
	}
	// Never return path value from StatusMap of memory cache.
	mem := gateway.NewPrincipalCache()
	st := mem.StatusMap()
	if st["shared_principal_cache_file"] != false {
		t.Fatalf("memory shared flag: %+v", st)
	}
}

func TestPrincipalStoreFromEnviron_MemoryAndFile(t *testing.T) {
	t.Parallel()
	mem, err := gateway.PrincipalStoreFromEnviron(func(string) string { return "" }, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mem.(*gateway.PrincipalCache); !ok {
		t.Fatalf("want *PrincipalCache, got %T", mem)
	}
	path := filepath.Join(t.TempDir(), "from_env.json")
	store, err := gateway.PrincipalStoreFromEnviron(func(k string) string {
		if k == gateway.EnvGatewayPrincipalCachePath {
			return path
		}
		return ""
	}, 10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fpc, ok := store.(*gateway.FilePrincipalCache)
	if !ok {
		t.Fatalf("want *FilePrincipalCache, got %T", store)
	}
	if fpc.Path() != path && fpc.Path() != filepath.Clean(path) {
		t.Fatalf("path: %q", fpc.Path())
	}
	// Invalid path fails closed.
	_, err = gateway.PrincipalStoreFromEnviron(func(k string) string {
		if k == gateway.EnvGatewayPrincipalCachePath {
			return "."
		}
		return ""
	}, 0, 0)
	if err == nil {
		t.Fatal("invalid path must fail")
	}
}

func TestConfigureProcessPrincipalCacheFromEnviron_FileInstall(t *testing.T) {
	// Not parallel: mutates process principal store.
	path := filepath.Join(t.TempDir(), "proc_pc.json")
	t.Cleanup(func() {
		// Reset to memory for other tests.
		_ = gateway.ConfigureProcessPrincipalCacheFromEnviron(func(string) string { return "" })
	})
	err := gateway.ConfigureProcessPrincipalCacheFromEnviron(func(k string) string {
		switch k {
		case gateway.EnvGatewayPrincipalCachePath:
			return path
		case gateway.EnvGatewayPrincipalCacheMax:
			return "64"
		case gateway.EnvGatewayPrincipalCacheTTL:
			return "1h"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	pc := gateway.ProcessPrincipalCache()
	fpc, ok := pc.(*gateway.FilePrincipalCache)
	if !ok {
		t.Fatalf("process store want file, got %T", pc)
	}
	sk := gateway.SubjectKeyParts("proc", "alice", "corp")
	fpc.Set(sk, "alice-j")
	// Cross-instance Get after process Set.
	c2, err := gateway.NewFilePrincipalCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := c2.Get(sk); !ok || p != "alice-j" {
		t.Fatalf("cross-instance: ok=%v p=%q", ok, p)
	}
	// Unset path restores memory.
	if err := gateway.ConfigureProcessPrincipalCacheFromEnviron(func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	if _, ok := gateway.ProcessPrincipalCache().(*gateway.PrincipalCache); !ok {
		t.Fatalf("want memory after unset: %T", gateway.ProcessPrincipalCache())
	}
}
