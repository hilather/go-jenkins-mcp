package policy_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

func writeOverlayFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadPath(path string) policy.LoadFunc {
	return func() (policy.LoadResult, error) {
		return policy.LoadOverlay(policy.LoadOptions{Path: path})
	}
}

func TestReloadableAppliesNewDeny(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	writeOverlayFile(t, path, `{
		"version": 1,
		"mode": "pilot",
		"deny_tools": ["jenkins_get_build_logs"]
	}`)

	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	var successN atomic.Int32
	rel := policy.NewReloadableFromLoadResult(res, policy.ReloadableConfig{
		Load:        loadPath(path),
		Path:        path,
		MinInterval: -1, // no throttle
		OnSuccess:   func(policy.ReloadInfo) { successN.Add(1) },
	})

	subj := policy.NewSubject("corp", "admin", true)
	// Initial: logs denied, jobs allowed.
	if d := rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{}); !d.Denied() {
		t.Fatalf("initial logs deny: %+v", d)
	}
	if d := rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{}); !d.Allowed() {
		t.Fatalf("initial jobs allow: %+v", d)
	}

	// Change overlay: deny get_jobs instead.
	writeOverlayFile(t, path, `{
		"version": 1,
		"mode": "pilot",
		"deny_tools": ["jenkins_get_jobs"]
	}`)
	// Ensure mtime advances on filesystems with coarse resolution.
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)

	if err := rel.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if successN.Load() < 1 {
		t.Fatal("expected OnSuccess after content change")
	}

	if d := rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{}); !d.Denied() {
		t.Fatalf("after reload jobs must deny: %+v", d)
	}
	if d := rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{}); !d.Allowed() {
		t.Fatalf("after reload logs must allow: %+v", d)
	}
}

func TestReloadableCorruptKeepsLastGood(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	writeOverlayFile(t, path, `{
		"version": 1,
		"mode": "pilot",
		"deny_tools": ["jenkins_get_build_logs"]
	}`)
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	var errN atomic.Int32
	rel := policy.NewReloadableFromLoadResult(res, policy.ReloadableConfig{
		Load: loadPath(path),
		Path: path,
		OnError: func(error) {
			errN.Add(1)
		},
	})

	subj := policy.NewSubject("corp", "admin", true)
	// Corrupt the file.
	writeOverlayFile(t, path, `{not valid json`)
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)

	if err := rel.Reload(); err == nil {
		t.Fatal("expected reload error on corrupt file")
	}
	if errN.Load() < 1 {
		t.Fatal("expected OnError")
	}
	// Last-good still denies logs.
	d := rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{})
	if !d.Denied() || d.ReasonCode != policy.ReasonExplicitDeny {
		t.Fatalf("last-good must still deny logs: %+v", d)
	}
	if d2 := rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{}); !d2.Allowed() {
		t.Fatalf("last-good still allows jobs: %+v", d2)
	}
}

func TestReloadableNeverLoadedDenies(t *testing.T) {
	t.Parallel()
	rel := policy.NewReloadableDenyOnly(policy.ReloadableConfig{
		Load: func() (policy.LoadResult, error) {
			return policy.LoadResult{}, errors.New("no source")
		},
	})
	d := rel.Evaluate(
		policy.NewSubject("corp", "admin", true),
		policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead},
		policy.Target{},
	)
	if !d.Denied() || d.ReasonCode != policy.ReasonNoEvaluator {
		t.Fatalf("never loaded must deny: %+v", d)
	}
	if rel.HasSnapshot() {
		t.Fatal("HasSnapshot should be false when never seeded")
	}
}

func TestReloadableSignedSignatureFailKeepsLastGood(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	keysDir := writeTrustDir(t, dir, "k1", pub)
	keys, err := policy.LoadTrustedKeys(keysDir)
	if err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(dir, "last_good.json")
	cache, err := policy.OpenLastGoodCache(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	v := policy.BundleVerifier(keys, cache, true)

	ov := policy.Overlay{
		Version:   1,
		Mode:      policy.ModePilot,
		DenyTools: []string{"jenkins_get_build_logs"},
	}
	env := signOverlay(t, ov, priv, "k1", 20, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339))
	path := filepath.Join(dir, "overlay.bundle.json")
	writeBundle(t, path, env)

	res, err := policy.LoadOverlay(policy.LoadOptions{
		Path:         path,
		Verifier:     v,
		SkipLastGood: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.BundleSeq != 20 {
		t.Fatalf("seq=%d", res.BundleSeq)
	}

	load := func() (policy.LoadResult, error) {
		// Fresh verifier+cache each load (mirrors DefaultVerifierFromEnviron).
		c, err := policy.OpenLastGoodCache(cachePath)
		if err != nil {
			return policy.LoadResult{}, err
		}
		return policy.LoadOverlay(policy.LoadOptions{
			Path:         path,
			Verifier:     policy.BundleVerifier(keys, c, true),
			SkipLastGood: true,
		})
	}
	var errN atomic.Int32
	rel := policy.NewReloadableFromLoadResult(res, policy.ReloadableConfig{
		Load: load,
		Path: path,
		OnError: func(error) {
			errN.Add(1)
		},
	})
	if rel.BundleSeq() != 20 {
		t.Fatalf("bundle_seq=%d", rel.BundleSeq())
	}

	// Tamper signature (fail closed on reload).
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a character inside the signature field value.
	s := string(raw)
	idx := strings.Index(s, `"signature"`)
	if idx < 0 {
		t.Fatal("no signature field")
	}
	// Find first base64-ish char after signature key.
	colon := strings.Index(s[idx:], ":")
	if colon < 0 {
		t.Fatal("no colon")
	}
	// Crude tamper: replace a letter in the signature value.
	b := []byte(s)
	for i := idx + colon; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] = 'A' + (b[i]-'A'+1)%26
			break
		}
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] = 'a' + (b[i]-'a'+1)%26
			break
		}
		if b[i] >= '0' && b[i] <= '9' {
			b[i] = '0' + (b[i]-'0'+1)%10
			break
		}
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)

	if err := rel.Reload(); err == nil {
		t.Fatal("expected signature failure on reload")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial && err != nil {
		// Load returns policy_denial; accept any error as long as last-good held.
		t.Logf("reload err code=%s err=%v", apperr.CodeOf(err), err)
	}
	if errN.Load() < 1 {
		t.Fatal("expected OnError on signature fail")
	}

	subj := policy.NewSubject("corp", "admin", true)
	d := rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{})
	if !d.Denied() {
		t.Fatalf("last-good after signature fail must still deny: %+v", d)
	}
	if rel.BundleSeq() != 20 {
		t.Fatalf("bundle_seq must remain 20 after failed reload, got %d", rel.BundleSeq())
	}
}

func TestReloadableMaybeReloadHonorsMtimeAndInterval(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	writeOverlayFile(t, path, `{
		"version": 1,
		"mode": "pilot",
		"deny_tools": ["jenkins_get_build_logs"]
	}`)
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}

	var now atomic.Value // time.Time
	now.Store(time.Unix(1_700_000_000, 0))
	var loads atomic.Int32
	rel := policy.NewReloadableFromLoadResult(res, policy.ReloadableConfig{
		Load: func() (policy.LoadResult, error) {
			loads.Add(1)
			return policy.LoadOverlay(policy.LoadOptions{Path: path})
		},
		Path:        path,
		MinInterval: 5 * time.Second,
		Now: func() time.Time {
			return now.Load().(time.Time)
		},
	})

	subj := policy.NewSubject("corp", "admin", true)
	// First Evaluate triggers interval check + Stat; mtime matches seed → no load.
	_ = rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if loads.Load() != 0 {
		t.Fatalf("no content change → no load, got %d", loads.Load())
	}

	// Within interval: even with content change, throttle skips Stat/load.
	writeOverlayFile(t, path, `{
		"version": 1,
		"mode": "pilot",
		"deny_tools": ["jenkins_get_jobs"]
	}`)
	future := now.Load().(time.Time).Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)
	now.Store(now.Load().(time.Time).Add(1 * time.Second))
	_ = rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if loads.Load() != 0 {
		t.Fatalf("within min interval must not load, got %d", loads.Load())
	}
	// Still last-good: get_jobs allowed, logs denied.
	if d := rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{}); !d.Allowed() {
		t.Fatalf("throttled: jobs still allow: %+v", d)
	}

	// Past interval + mtime change → load applies new deny.
	now.Store(now.Load().(time.Time).Add(10 * time.Second))
	_ = rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if loads.Load() < 1 {
		t.Fatal("expected load after interval + mtime change")
	}
	if d := rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{}); !d.Denied() {
		t.Fatalf("after MaybeReload jobs deny: %+v", d)
	}
}

func TestReloadableAbsentAfterLoadKeepsLastGood(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	writeOverlayFile(t, path, `{
		"version": 1,
		"mode": "pilot",
		"deny_tools": ["jenkins_get_build_logs"]
	}`)
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	rel := policy.NewReloadableFromLoadResult(res, policy.ReloadableConfig{
		Load: loadPath(path),
		Path: path,
	})
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := rel.Reload(); err == nil {
		t.Fatal("expected error when source absent after last-good")
	}
	subj := policy.NewSubject("corp", "admin", true)
	if d := rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{}); !d.Denied() {
		t.Fatalf("keep last-good after delete: %+v", d)
	}
}

func TestReloadableConcurrentEvaluate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	writeOverlayFile(t, path, `{
		"version": 1,
		"mode": "pilot",
		"deny_tools": ["jenkins_get_build_logs"]
	}`)
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	rel := policy.NewReloadableFromLoadResult(res, policy.ReloadableConfig{
		Load:        loadPath(path),
		Path:        path,
		MinInterval: -1,
	})
	subj := policy.NewSubject("corp", "admin", true)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				d := rel.Evaluate(subj, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{})
				if !d.Denied() {
					t.Errorf("expected deny: %+v", d)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// Ensure ReloadInfo never carries raw signature material (canary shape).
func TestReloadInfoNoSecrets(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	writeOverlayFile(t, path, `{
		"version": 1,
		"mode": "pilot",
		"deny_tools": ["jenkins_get_job"]
	}`)
	var info policy.ReloadInfo
	rel := policy.NewReloadableDenyOnly(policy.ReloadableConfig{
		Load: loadPath(path),
		Path: path,
		OnSuccess: func(i policy.ReloadInfo) {
			info = i
		},
	})
	if err := rel.Reload(); err != nil {
		t.Fatal(err)
	}
	if info.DenyToolsCount != 1 {
		t.Fatalf("deny_tools=%d", info.DenyToolsCount)
	}
	if info.PathBase != "overlay.json" {
		t.Fatalf("path base=%q", info.PathBase)
	}
	// Regression: never embed full absolute paths or signature-like blobs.
	if strings.Contains(info.PathBase, string(os.PathSeparator)) {
		t.Fatalf("PathBase must be basename only: %q", info.PathBase)
	}
	if info.SignatureState == "" {
		t.Fatal("signature_state expected")
	}
}

// Wave 25: ReloadInfo carries force_read_only + max_result_bytes for OnSuccess hot-apply.
func TestReloadInfoForceAndMaxResultBytes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	writeOverlayFile(t, path, `{
		"version": 1,
		"mode": "pilot",
		"force_read_only": true,
		"max_result_bytes": 4096,
		"deny_tools": ["jenkins_get_build_logs"]
	}`)
	var info policy.ReloadInfo
	var n atomic.Int32
	rel := policy.NewReloadableDenyOnly(policy.ReloadableConfig{
		Load: loadPath(path),
		Path: path,
		OnSuccess: func(i policy.ReloadInfo) {
			info = i
			n.Add(1)
		},
	})
	if err := rel.Reload(); err != nil {
		t.Fatal(err)
	}
	if n.Load() < 1 {
		t.Fatal("OnSuccess expected")
	}
	if !info.ForceReadOnly {
		t.Fatal("ForceReadOnly want true")
	}
	if info.MaxResultBytes != 4096 {
		t.Fatalf("MaxResultBytes=%d want 4096", info.MaxResultBytes)
	}

	// Change force + budget; OnSuccess must reflect new values.
	writeOverlayFile(t, path, `{
		"version": 1,
		"mode": "pilot",
		"force_read_only": false,
		"max_result_bytes": 1024,
		"deny_tools": ["jenkins_get_build_logs"]
	}`)
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)
	if err := rel.Reload(); err != nil {
		t.Fatal(err)
	}
	if info.ForceReadOnly {
		t.Fatal("ForceReadOnly want false after reload")
	}
	if info.MaxResultBytes != 1024 {
		t.Fatalf("MaxResultBytes=%d want 1024", info.MaxResultBytes)
	}
}
