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

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
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
			// tokens/last required; last_access optional LRU hygiene (HOST-008 residual lite).
			if k != "tokens" && k != "last" && k != "last_access" {
				t.Fatalf("unexpected field %q in rate entry (must be secret-free tokens/last[/last_access] only)", k)
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

// HOST-008 residual lite: FileSubjectRateLimiter MaxSubjects LRU eviction.
// Tiny clock steps keep buckets partial so idle-full purge does not free the map
// before LRU (same pattern as memory MaxSubjectsEvictOldest).
func TestFileSubjectRateLimiter_MaxSubjectsEvictOldest(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "max_subj_rate.json")
	l, err := gateway.NewFileSubjectRateLimiter(path, 30, 10, 6000, 500)
	if err != nil {
		t.Fatal(err)
	}
	l.SetMaxSubjects(2)
	base := time.Unix(1_700_200_000, 0).UTC()
	var clock atomic.Value
	clock.Store(base)
	l.SetNow(func() time.Time { return clock.Load().(time.Time) })

	k1 := gateway.SubjectKeyParts("t", "u1", "p")
	k2 := gateway.SubjectKeyParts("t", "u2", "p")
	k3 := gateway.SubjectKeyParts("t", "u3", "p")
	if err := l.Allow(k1); err != nil {
		t.Fatal(err)
	}
	clock.Store(base.Add(time.Nanosecond))
	if err := l.Allow(k2); err != nil {
		t.Fatal(err)
	}
	if l.SubjectsTracked() != 2 {
		t.Fatalf("tracked=%d want 2", l.SubjectsTracked())
	}
	clock.Store(base.Add(2 * time.Nanosecond))
	if err := l.Allow(k3); err != nil {
		t.Fatal(err)
	}
	if l.SubjectsTracked() != 2 {
		t.Fatalf("after eviction tracked=%d want 2", l.SubjectsTracked())
	}

	// Durable file must only keep 2 subjects; k1 (oldest last_access) gone.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Subjects map[string]map[string]any `json:"subjects"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Subjects) != 2 {
		t.Fatalf("file subjects=%d want 2 body=%s", len(doc.Subjects), raw)
	}
	if _, ok := doc.Subjects[k1]; ok {
		t.Fatalf("k1 must be evicted from file: %s", raw)
	}
	if _, ok := doc.Subjects[k2]; !ok {
		t.Fatalf("k2 must remain: %s", raw)
	}
	if _, ok := doc.Subjects[k3]; !ok {
		t.Fatalf("k3 must remain: %s", raw)
	}

	// Cross-instance sees the same capped map.
	l2, err := gateway.NewFileSubjectRateLimiter(path, 30, 10, 6000, 500)
	if err != nil {
		t.Fatal(err)
	}
	l2.SetMaxSubjects(2)
	if l2.SubjectsTracked() != 2 {
		t.Fatalf("l2 tracked=%d", l2.SubjectsTracked())
	}

	st := l.StatusMap()
	if st["subject_rate_max_subjects"] != 2 {
		t.Fatalf("status: %+v", st)
	}
	if st["shared_subject_rate_file"] != true {
		t.Fatal("file status must keep shared_subject_rate_file")
	}
	blob := fmt.Sprintf("%v", st)
	if strings.Contains(blob, "u1") || strings.Contains(blob, "Bearer ") {
		t.Fatalf("status secret/subject leak: %s", blob)
	}
}

func TestFileSubjectRateLimiter_MaxSubjectsUnlimitedDefault(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "unlim_rate.json")
	l, err := gateway.NewFileSubjectRateLimiter(path, 600, 50, 6000, 500)
	if err != nil {
		t.Fatal(err)
	}
	if l.MaxSubjects() != 0 {
		t.Fatalf("default MaxSubjects=%d", l.MaxSubjects())
	}
	for i := 0; i < 12; i++ {
		if err := l.Allow(gateway.SubjectKeyParts("t", fmt.Sprintf("u%02d", i), "p")); err != nil {
			t.Fatalf("allow %d: %v", i, err)
		}
	}
	if l.SubjectsTracked() != 12 {
		t.Fatalf("tracked=%d want 12", l.SubjectsTracked())
	}
	st := l.StatusMap()
	if _, ok := st["subject_rate_max_subjects"]; ok {
		t.Fatalf("unlimited omit max: %+v", st)
	}
}

// Alice/Bob burst isolation under MaxSubjects + secret-free file with last_access.
func TestFileSubjectRateLimiter_MaxSubjectsAliceBobAndSecretFree(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "alice_bob_max.json")
	l, err := gateway.NewFileSubjectRateLimiter(path, 30, 2, 300, 60)
	if err != nil {
		t.Fatal(err)
	}
	l.SetMaxSubjects(16)
	alice := gateway.SubjectKeyParts("t1", "alice", "corp")
	bob := gateway.SubjectKeyParts("t1", "bob", "corp")
	if err := l.Allow(alice); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(alice); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(alice); err == nil {
		t.Fatal("alice third must fail")
	}
	if err := l.Allow(bob); err != nil {
		t.Fatalf("bob: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, bad := range []string{"Bearer ", "access_token", "refresh_token", "client_secret", "Authorization", "password"} {
		if strings.Contains(body, bad) {
			t.Fatalf("rate file must not contain %q: %s", bad, body)
		}
	}
	// last_access present after successful allow (hygiene field, not a secret).
	if !strings.Contains(body, "last_access") {
		t.Fatalf("want last_access in file after allow: %s", body)
	}
}

// Concurrent multi-instance Allow under MaxSubjects must not corrupt JSON or exceed cap.
func TestFileSubjectRateLimiter_MaxSubjectsConcurrent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "max_concurrent_rate.json")
	const n = 12
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
			l.SetMaxSubjects(4)
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
		Subjects map[string]map[string]any `json:"subjects"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("corrupt after concurrent: %v body=%s", err, raw)
	}
	if len(doc.Subjects) > 4 {
		t.Fatalf("subjects=%d exceeds MaxSubjects=4 body=%s", len(doc.Subjects), raw)
	}
}
