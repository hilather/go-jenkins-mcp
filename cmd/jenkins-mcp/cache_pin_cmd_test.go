package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// ensureTestProfileDataDir creates the profile data root + empty meta store for pin CLI tests.
func ensureTestProfileDataDir(t *testing.T, profileID string) string {
	t.Helper()
	p := mustLoadProfile(t, profileID)
	dir, err := resolveProfileDataDir(p)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := meta.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func mustLoadProfile(t *testing.T, id string) *profile.Profile {
	t.Helper()
	ps, err := profileStore()
	if err != nil {
		t.Fatal(err)
	}
	p, err := ps.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCachePinGenerationAndList_CLI(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	_ = ensureTestProfileDataDir(t, "corp")

	out, err := captureCacheKeyStdout(t, func() error {
		return runCachePin([]string{"generation", "--profile", "corp", "--generation", "42"})
	})
	if err != nil {
		t.Fatalf("pin generation: %v", err)
	}
	if !strings.Contains(out, "kind=generation") || !strings.Contains(out, "target=42") {
		t.Fatalf("pin out: %q", out)
	}

	// Idempotent re-pin.
	if _, err := captureCacheKeyStdout(t, func() error {
		return runCachePin([]string{"generation", "--profile", "corp", "--generation", "42"})
	}); err != nil {
		t.Fatalf("re-pin: %v", err)
	}

	out, err = captureCacheKeyStdout(t, func() error {
		return runCachePins([]string{"--profile", "corp"})
	})
	if err != nil {
		t.Fatalf("pins: %v", err)
	}
	if !strings.Contains(out, "pins=1") || !strings.Contains(out, "kind=generation") || !strings.Contains(out, "target=42") {
		t.Fatalf("list text: %q", out)
	}

	// Meta store agrees.
	dir, err := resolveProfileDataDirPath(mustLoadProfile(t, "corp"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = meta.Close() }()
	ok, err := meta.IsPinned(context.Background(), store.PinKindGeneration, "42")
	if err != nil || !ok {
		t.Fatalf("IsPinned: ok=%v err=%v", ok, err)
	}

	out, err = captureCacheKeyStdout(t, func() error {
		return runCacheUnpin([]string{"generation", "--profile", "corp", "--generation", "42"})
	})
	if err != nil {
		t.Fatalf("unpin: %v", err)
	}
	if !strings.Contains(out, "unpinned") || !strings.Contains(out, "target=42") {
		t.Fatalf("unpin out: %q", out)
	}

	out, err = captureCacheKeyStdout(t, func() error {
		return runCachePins([]string{"--profile", "corp"})
	})
	if err != nil {
		t.Fatalf("pins empty: %v", err)
	}
	if !strings.Contains(out, "pins=0") {
		t.Fatalf("expected empty list: %q", out)
	}
}

func TestCachePinPackAndJSONList_CLI(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	_ = ensureTestProfileDataDir(t, "corp")

	if _, err := captureCacheKeyStdout(t, func() error {
		return runCachePin([]string{"pack", "--profile", "corp", "--pack", "pack-abc"})
	}); err != nil {
		t.Fatalf("pin pack: %v", err)
	}
	if _, err := captureCacheKeyStdout(t, func() error {
		return runCachePin([]string{"generation", "--profile", "corp", "--generation", "7"})
	}); err != nil {
		t.Fatalf("pin gen: %v", err)
	}

	out, err := captureCacheKeyStdout(t, func() error {
		return runCachePins([]string{"--profile", "corp", "--json"})
	})
	if err != nil {
		t.Fatalf("pins json: %v", err)
	}
	var doc pinListJSON
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json: %v out=%q", err, out)
	}
	if doc.Profile != "corp" || len(doc.Pins) != 2 {
		t.Fatalf("doc: %+v", doc)
	}
	// Secret-free: only kind/target_id/pinned_at — no tokens.
	if strings.Contains(out, "token") || strings.Contains(out, "password") || strings.Contains(out, "Bearer") {
		t.Fatalf("Regression: pins JSON looked secret-bearing: %q", out)
	}
	kinds := map[string]string{}
	for _, p := range doc.Pins {
		kinds[p.Kind] = p.TargetID
	}
	if kinds["generation"] != "7" || kinds["pack"] != "pack-abc" {
		t.Fatalf("kinds: %v", kinds)
	}

	if _, err := captureCacheKeyStdout(t, func() error {
		return runCacheUnpin([]string{"pack", "--profile", "corp", "--pack", "pack-abc"})
	}); err != nil {
		t.Fatalf("unpin pack: %v", err)
	}
	out, err = captureCacheKeyStdout(t, func() error {
		return runCachePins([]string{"--profile", "corp", "--json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Pins) != 1 || doc.Pins[0].Kind != "generation" {
		t.Fatalf("after unpin pack: %+v", doc)
	}
}

func TestCachePin_FailClosedMissingProfile(t *testing.T) {
	withTestXDG(t)
	err := runCachePin([]string{"generation", "--profile", "missing", "--generation", "1"})
	if err == nil {
		t.Fatal("expected missing profile to fail")
	}
	if apperr.CodeOf(err) == "" {
		t.Fatalf("expected typed error: %v", err)
	}
}

func TestCachePin_FailClosedMissingDataDir(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	// Profile exists; data dir never created.
	err := runCachePin([]string{"generation", "--profile", "corp", "--generation", "1"})
	if err == nil {
		t.Fatal("expected missing data dir to fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeNotFound && !strings.Contains(err.Error(), "data directory") {
		t.Fatalf("expected not_found / data directory: code=%v err=%v", apperr.CodeOf(err), err)
	}
	// pins list also fail closed.
	err = runCachePins([]string{"--profile", "corp"})
	if err == nil {
		t.Fatal("expected pins list without data dir to fail")
	}
}

func TestCachePin_Validation(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	_ = ensureTestProfileDataDir(t, "corp")

	cases := []struct {
		name string
		fn   func() error
		want string
	}{
		{"pin no profile", func() error {
			return runCachePin([]string{"generation", "--generation", "1"})
		}, "profile"},
		{"pin no generation", func() error {
			return runCachePin([]string{"generation", "--profile", "corp"})
		}, "generation"},
		{"pin zero gen", func() error {
			return runCachePin([]string{"generation", "--profile", "corp", "--generation", "0"})
		}, "positive"},
		{"pin pack empty", func() error {
			return runCachePin([]string{"pack", "--profile", "corp", "--pack", ""})
		}, "pack"},
		{"pin pack path", func() error {
			return runCachePin([]string{"pack", "--profile", "corp", "--pack", "../evil"})
		}, "path"},
		{"unknown pin sub", func() error {
			return runCachePin([]string{"chunk"})
		}, "unknown"},
		{"unknown unpin sub", func() error {
			return runCacheUnpin([]string{"chunk"})
		}, "unknown"},
		{"cache unknown", func() error {
			return runCache([]string{"pinz"})
		}, "unknown"},
		{"pins no profile", func() error {
			return runCachePins(nil)
		}, "profile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("err %q want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestCachePin_CustomProfileDataDir(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	// Point profile at an absolute custom data root; ensure meta lives there.
	customRoot := filepath.Join(t.TempDir(), "custom-data")
	ps, err := profileStore()
	if err != nil {
		t.Fatal(err)
	}
	p, err := ps.Load("corp")
	if err != nil {
		t.Fatal(err)
	}
	p.DataDir = customRoot
	if err := ps.Save(p); err != nil {
		t.Fatal(err)
	}
	p = mustLoadProfile(t, "corp")
	dir, err := resolveProfileDataDir(p)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(dir) != "corp" {
		t.Fatalf("expected profile segment: %q", dir)
	}
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = meta.Close()

	if _, err := captureCacheKeyStdout(t, func() error {
		return runCachePin([]string{"generation", "--profile", "corp", "--generation", "99"})
	}); err != nil {
		t.Fatalf("pin custom dataDir: %v", err)
	}
	// Default XDG profile path must not have received the pin.
	defaultDir := filepath.Join(os.Getenv("XDG_DATA_HOME"), "jenkins-mcp", "profiles", "corp")
	if _, err := os.Stat(filepath.Join(defaultDir, store.MetaDBFile)); err == nil {
		if m2, err := store.Open(defaultDir); err == nil {
			pins, _ := m2.ListPins(context.Background())
			_ = m2.Close()
			if len(pins) > 0 {
				t.Fatalf("pin leaked into default data dir: %+v", pins)
			}
		}
	}
	// Custom path has the pin.
	m3, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m3.Close() }()
	ok, err := m3.IsPinned(context.Background(), store.PinKindGeneration, "99")
	if err != nil || !ok {
		t.Fatalf("custom pin missing: ok=%v err=%v", ok, err)
	}
}
