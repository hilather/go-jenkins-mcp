package gateway_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// Regression: HOST-008 Done* lite — two FileAPITokenVault instances (separate
// process-local mutexes) concurrent Put on the same path must not corrupt JSON
// and must retain all subjects (flock serializes load-modify-save).
func TestFileAPITokenVault_MultiInstanceConcurrentPutNoCorrupt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "shared_vault.json")
	ctx := context.Background()

	const n = 20
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := gateway.NewFileAPITokenVault(path)
			if err != nil {
				errCh <- err
				return
			}
			key := gateway.SubjectKeyParts("t", fmt.Sprintf("user-%02d", i), "corp")
			if err := v.Put(ctx, key, fmt.Sprintf("u%d", i), fmt.Sprintf("tok-%d-canary", i)); err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("put: %v", err)
		}
	}

	// Final vault must be valid JSON with n distinct subjects.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Entries map[string]struct {
			Username string `json:"username"`
			Token    string `json:"token"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("corrupt vault after concurrent put: %v\n%s", err, raw)
	}
	if len(doc.Entries) != n {
		t.Fatalf("entries=%d want %d (lost updates without flock)", len(doc.Entries), n)
	}
	// Reload via vault API.
	v, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := v.ListSubjectKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != n {
		t.Fatalf("list=%d want %d", len(keys), n)
	}
	for i := 0; i < n; i++ {
		key := gateway.SubjectKeyParts("t", fmt.Sprintf("user-%02d", i), "corp")
		u, tok, ok, err := v.Get(ctx, key)
		if err != nil || !ok {
			t.Fatalf("get %s: ok=%v err=%v", key, ok, err)
		}
		if u != fmt.Sprintf("u%d", i) || tok != fmt.Sprintf("tok-%d-canary", i) {
			t.Fatalf("mismatch subject %s u=%q", key, u)
		}
	}
	// Lock file exists after first write (unix); ignore if other OS no-op.
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		st, err := os.Stat(path + ".lock")
		if err != nil || st.IsDir() {
			t.Fatalf("expected lock file %s.lock: %v", path, err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("lock perm %#o want 0600", st.Mode().Perm())
		}
	}
}

// Regression: HOST-008 multi-process flock — child holds exclusive lock;
// parent Put blocks until child unlocks (linux/unix only).
func TestFileAPITokenVault_MultiProcessFlockBlocks(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("flock multi-process test is unix-only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "mp_vault.json")
	v0, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := v0.Put(context.Background(), gateway.SubjectKeyParts("t", "seed", "corp"), "seed", "seed-tok"); err != nil {
		t.Fatal(err)
	}

	holdMS := 400
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// When running under `go test`, Executable is the test binary.
	child := exec.Command(self, "-test.run=^TestVaultFlockHoldHelper$", "-test.v=false", "-test.count=1")
	child.Env = append(os.Environ(),
		"JENKINS_MCP_TEST_VAULT_FLOCK_HOLD=1",
		"JENKINS_MCP_TEST_VAULT_PATH="+path,
		"JENKINS_MCP_TEST_VAULT_HOLD_MS="+strconv.Itoa(holdMS),
	)
	if err := child.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	// Wait until child holds the exclusive lock.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			_ = child.Process.Kill()
			t.Fatal("child did not hold lock in time")
		}
		if tryFlockHeld(t, path+".lock") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	parent, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		_ = child.Process.Kill()
		t.Fatal(err)
	}
	start := time.Now()
	err = parent.Put(context.Background(), gateway.SubjectKeyParts("t", "parent", "corp"), "p", "parent-tok")
	elapsed := time.Since(start)
	if err != nil {
		_ = child.Process.Kill()
		t.Fatalf("parent put: %v", err)
	}
	// Parent should have blocked ~holdMS (allow slack for CI).
	if elapsed < 200*time.Millisecond {
		t.Fatalf("parent Put returned too fast (%v); expected block behind child flock", elapsed)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("child: %v", err)
	}
	// Both entries present.
	keys, err := parent.ListSubjectKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) < 2 {
		t.Fatalf("keys=%v want seed+parent", keys)
	}
	_, tok, ok, err := parent.Get(context.Background(), gateway.SubjectKeyParts("t", "parent", "corp"))
	if err != nil || !ok || tok != "parent-tok" {
		t.Fatalf("parent entry: ok=%v tok_ok=%v err=%v", ok, tok == "parent-tok", err)
	}
}

// TestVaultFlockHoldHelper is invoked only as a subprocess (env gated).
func TestVaultFlockHoldHelper(t *testing.T) {
	if os.Getenv("JENKINS_MCP_TEST_VAULT_FLOCK_HOLD") != "1" {
		t.Skip("subprocess helper only")
	}
	path := os.Getenv("JENKINS_MCP_TEST_VAULT_PATH")
	ms, _ := strconv.Atoi(os.Getenv("JENKINS_MCP_TEST_VAULT_HOLD_MS"))
	if ms <= 0 {
		ms = 400
	}
	if path == "" {
		t.Fatal("path required")
	}
	holdVaultLockFor(t, path, time.Duration(ms)*time.Millisecond)
}

func TestFileJWTVault_MultiInstanceConcurrentPutNoCorrupt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "shared_jwt.json")
	ctx := context.Background()
	const n = 16
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := gateway.NewFileJWTVault(path)
			if err != nil {
				errCh <- err
				return
			}
			// Valid-looking opaque access token (not JWT with token_use=id_token).
			tok := fmt.Sprintf("access-token-opaque-%02d-canary", i)
			key := gateway.SubjectKeyParts("t", fmt.Sprintf("jwt-user-%02d", i), "corp")
			if err := v.Put(ctx, key, tok); err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("jwt put: %v", err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatalf("corrupt jwt vault: %s", raw)
	}
	v, err := gateway.NewFileJWTVault(path)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := v.ListSubjectKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != n {
		t.Fatalf("jwt entries=%d want %d", len(keys), n)
	}
	for _, k := range keys {
		if strings.Contains(k, "canary") {
			t.Fatal("subject key must not embed canary token")
		}
	}
}
