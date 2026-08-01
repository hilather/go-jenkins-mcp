package gateway_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// HOST-008 / HOST-006: FileSubjectRateLimiter burst isolation Alice/Bob.
func TestFileSubjectRateLimiter_AliceCapDoesNotBlockBob(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "subject_rate.json")
	l, err := gateway.NewFileSubjectRateLimiter(path, 30, 2, 300, 60)
	if err != nil {
		t.Fatal(err)
	}
	alice := gateway.SubjectKeyParts("t1", "alice", "corp")
	bob := gateway.SubjectKeyParts("t1", "bob", "corp")

	if err := l.Allow(alice); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(alice); err != nil {
		t.Fatal(err)
	}
	err = l.Allow(alice)
	if err == nil {
		t.Fatal("alice third allow must fail closed at burst")
	}
	if apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("code=%s want quota", apperr.CodeOf(err))
	}

	if err := l.Allow(bob); err != nil {
		t.Fatalf("bob must not share alice tokens: %v", err)
	}
	if err := l.Allow(bob); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(bob); err == nil {
		t.Fatal("bob third must fail at burst")
	}
}

// Cross-process lite: two sequential FileSubjectRateLimiter instances share budget.
func TestFileSubjectRateLimiter_CrossInstanceSharedBudget(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "shared_rate.json")
	alice := gateway.SubjectKeyParts("t", "alice", "corp")

	l1, err := gateway.NewFileSubjectRateLimiter(path, 30, 2, 300, 60)
	if err != nil {
		t.Fatal(err)
	}
	if err := l1.Allow(alice); err != nil {
		t.Fatal(err)
	}
	if err := l1.Allow(alice); err != nil {
		t.Fatal(err)
	}

	// Second instance opens the same path (simulates another process).
	l2, err := gateway.NewFileSubjectRateLimiter(path, 30, 2, 300, 60)
	if err != nil {
		t.Fatal(err)
	}
	err = l2.Allow(alice)
	if err == nil {
		t.Fatal("second instance must see exhausted subject budget")
	}
	if apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("code=%s want quota", apperr.CodeOf(err))
	}

	// Bob still has full budget on second instance.
	bob := gateway.SubjectKeyParts("t", "bob", "corp")
	if err := l2.Allow(bob); err != nil {
		t.Fatalf("bob isolated: %v", err)
	}
}

func TestFileSubjectRateLimiter_RefillOverTime(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "refill_rate.json")
	l, err := gateway.NewFileSubjectRateLimiter(path, 60, 1, 600, 60)
	if err != nil {
		t.Fatal(err)
	}
	key := gateway.SubjectKeyParts("t", "u", "p")
	base := time.Unix(1_700_000_000, 0).UTC()
	var clock atomic.Value
	clock.Store(base)
	l.SetNow(func() time.Time { return clock.Load().(time.Time) })

	if err := l.Allow(key); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(key); err == nil {
		t.Fatal("burst exhausted")
	}
	clock.Store(base.Add(time.Second + 10*time.Millisecond))
	if err := l.Allow(key); err != nil {
		t.Fatalf("after refill: %v", err)
	}
}

func TestFileSubjectRateLimiter_EmptySubjectFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty_key.json")
	l, err := gateway.NewFileSubjectRateLimiter(path, 30, 10, 300, 60)
	if err != nil {
		t.Fatal(err)
	}
	err = l.Allow("")
	if err == nil {
		t.Fatal("empty subject must fail")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
	var nilL *gateway.FileSubjectRateLimiter
	if err := nilL.Allow("t|u|p"); err != nil {
		t.Fatal(err)
	}
}

func TestFileSubjectRateLimiter_FailClosedInvalidPath(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"", " ", ".", "/"} {
		_, err := gateway.NewFileSubjectRateLimiter(p, 30, 10, 300, 60)
		if err == nil {
			t.Fatalf("path %q must fail closed", p)
		}
		if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("path %q code=%s", p, apperr.CodeOf(err))
		}
	}
}

func TestFileSubjectRateLimiter_CorruptFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "corrupt_rate.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := gateway.NewFileSubjectRateLimiter(path, 30, 2, 300, 60)
	if err != nil {
		t.Fatal(err)
	}
	// Construct succeeds; Allow fail-closed (CodeQuota) on corrupt — never over-allow.
	err = l.Allow(gateway.SubjectKeyParts("t", "u", "p"))
	if err == nil {
		t.Fatal("corrupt file must fail closed on Allow")
	}
	if apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("code=%s want quota", apperr.CodeOf(err))
	}
}

// Secret-free file contents: no Bearer, no access_token, no credential canaries.
func TestFileSubjectRateLimiter_FileContentsSecretFree(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "secret_free_rate.json")
	l, err := gateway.NewFileSubjectRateLimiter(path, 30, 3, 300, 60)
	if err != nil {
		t.Fatal(err)
	}
	key := gateway.SubjectKeyParts("t", "u", "p")
	if err := l.Allow(key); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, bad := range []string{
		"Bearer ",
		"access_token",
		"refresh_token",
		"client_secret",
		"Authorization",
		"sk-super-secret-token-value",
		"password",
	} {
		if strings.Contains(body, bad) {
			t.Fatalf("rate file must not contain %q: %s", bad, body)
		}
	}
	// Shape: version + subjects with tokens/last only.
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("json: %v body=%s", err, body)
	}
	subjects, ok := doc["subjects"].(map[string]any)
	if !ok || len(subjects) == 0 {
		t.Fatalf("want subjects map: %s", body)
	}
	for sk, v := range subjects {
		entry, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("entry type for %s: %T", sk, v)
		}
		for k := range entry {
			if k != "tokens" && k != "last" {
				t.Fatalf("unexpected field %q in rate entry (must be secret-free tokens/last only)", k)
			}
		}
		if _, has := entry["tokens"]; !has {
			t.Fatal("tokens field required")
		}
	}
	// Mode 0600.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("rate file mode=%o want 0600 (no group/other)", st.Mode().Perm())
	}
	// Lock sibling created on Allow.
	lockPath := path + ".lock"
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("expected flock path.lock: %v", err)
	}
}

func TestFileSubjectRateLimiter_StatusMapSecretFree(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "status_rate.json")
	l, err := gateway.NewFileSubjectRateLimiter(path, 30, 10, 300, 60)
	if err != nil {
		t.Fatal(err)
	}
	key := gateway.SubjectKeyParts("secret-tenant", "secret-sub", "corp")
	_ = l.Allow(key)
	st := l.StatusMap()
	blob := fmt.Sprintf("%v", st)
	if strings.Contains(blob, "secret-tenant") || strings.Contains(blob, "secret-sub") {
		t.Fatalf("status leaked subject material: %v", st)
	}
	if st["shared_subject_rate_file"] != true {
		t.Fatalf("shared_subject_rate_file: %+v", st)
	}
	if st["ha_multi_replica"] != false {
		t.Fatal("HOST-008 residual must report ha_multi_replica=false")
	}
	if st["kind"] != "file" {
		t.Fatalf("kind: %+v", st)
	}
	if st["path_configured"] != true {
		t.Fatalf("path_configured: %+v", st)
	}
	if _, ok := st["access_token"]; ok {
		t.Fatal("access_token field forbidden")
	}
	if strings.Contains(blob, "Bearer ") {
		t.Fatal("Bearer in StatusMap")
	}
	canary := "sk-super-secret-token-value"
	if strings.Contains(blob, canary) {
		t.Fatal("status leaked canary")
	}
}

func TestFileSubjectRateLimiter_LowerRateOnlyLowers(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "lower_rate.json")
	l, err := gateway.NewFileSubjectRateLimiter(path, 30, 10, 300, 60)
	if err != nil {
		t.Fatal(err)
	}
	if !l.LowerRate(15, 4) {
		t.Fatal("LowerRate to 15/4 should change")
	}
	if l.RatePerMinute() != 15 || l.Burst() != 4 {
		t.Fatalf("after lower: rpm=%d burst=%d", l.RatePerMinute(), l.Burst())
	}
	if l.LowerRate(30, 10) {
		t.Fatal("LowerRate must not raise")
	}
	if l.RatePerMinute() != 15 || l.Burst() != 4 {
		t.Fatal("still lowered")
	}
}

// Multi-instance concurrent Allow on same path must not corrupt JSON.
func TestFileSubjectRateLimiter_MultiInstanceConcurrentAllowNoCorrupt(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "concurrent_rate.json")
	const n = 16
	var wg sync.WaitGroup
	var okCount atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l, err := gateway.NewFileSubjectRateLimiter(path, 600, 50, 6000, 500)
			if err != nil {
				t.Errorf("new: %v", err)
				return
			}
			key := gateway.SubjectKeyParts("t", fmt.Sprintf("u%02d", i), "corp")
			if err := l.Allow(key); err == nil {
				okCount.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if okCount.Load() == 0 {
		t.Fatal("expected some successful allows")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version  int                       `json:"version"`
		Subjects map[string]map[string]any `json:"subjects"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("corrupt after concurrent allow: %v body=%s", err, raw)
	}
	if len(doc.Subjects) == 0 {
		t.Fatal("want subject entries after concurrent allows")
	}
}

func TestSubjectRatePathConfiguredFromEnviron(t *testing.T) {
	t.Parallel()
	if gateway.SubjectRatePathConfiguredFromEnviron(func(string) string { return "" }) {
		t.Fatal("empty → false")
	}
	if !gateway.SubjectRatePathConfiguredFromEnviron(func(k string) string {
		if k == gateway.EnvGatewaySubjectRatePath {
			return "/tmp/rate.json"
		}
		return ""
	}) {
		t.Fatal("path set → true")
	}
	if gateway.EnvGatewaySubjectRatePath != "JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH" {
		t.Fatalf("env name: %q", gateway.EnvGatewaySubjectRatePath)
	}
}

func TestSubjectRateLimiter_StatusMapSharedFileFalse(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectRateLimiter(30, 10, 300, 60)
	st := l.StatusMap()
	if st["shared_subject_rate_file"] != false {
		t.Fatalf("memory limiter shared_subject_rate_file: %+v", st)
	}
	if st["kind"] != "memory" {
		t.Fatalf("kind: %+v", st)
	}
}
