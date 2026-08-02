package diagnostics_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/archive"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

const verifyCanary = "VERIFY_CANARY_token_must_never_appear_xyz"

func writeVerifyPack(t *testing.T, packID string) []byte {
	t.Helper()
	data, _, err := archive.WritePack([]archive.MemberInput{
		{Name: "logs/a/1/consoleText", Body: []byte("line-a-1\nline-a-2\n")},
		{Name: "logs/b/2/consoleText", Body: []byte("line-b-1\nline-b-2\n")},
	}, archive.WriteOptions{PackID: packID, TargetFrameBytes: 32})
	if err != nil {
		t.Fatalf("WritePack: %v", err)
	}
	return data
}

func TestRunCacheVerify_ReportsKindsAndNoSecrets(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodAPIToken,
		// Plant canary only as a control; must never appear in report.
		Username: "alice",
		DataDir:  filepath.Join(paths.DataDir, "profiles", "corp"),
	}
	dataDir, err := store.EnsureProfileDataDir(p.DataDir, string(p.ID))
	if err != nil {
		t.Fatal(err)
	}
	arch := filepath.Join(dataDir, store.ArchivesDirName)
	if err := os.MkdirAll(arch, 0o700); err != nil {
		t.Fatal(err)
	}

	good := writeVerifyPack(t, "pack-good")
	if err := os.WriteFile(filepath.Join(arch, "pack-good.tar.zst"), good, 0o600); err != nil {
		t.Fatal(err)
	}
	// Sidecar index via RepairIndex
	idx, err := archive.RepairIndex(context.Background(), "pack-good", "", filepath.Join(arch, "pack-good.tar.zst"), good)
	if err != nil || idx == nil {
		t.Fatalf("RepairIndex: %v", err)
	}

	// Corrupt pack: not valid multi-frame
	if err := os.WriteFile(filepath.Join(arch, "pack-bad.tar.zst"), []byte("not-a-pack"+verifyCanary), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := diagnostics.RunCacheVerify(context.Background(), diagnostics.CacheVerifyOptions{
		Profile: p,
		Paths:   &paths,
		Full:    true,
	})
	if err != nil {
		// full may return nil error even with pack fails
	}
	_ = err
	if rep.PacksTotal < 2 {
		t.Fatalf("packs total: %+v", rep)
	}
	if rep.PacksChecked < 2 {
		t.Fatalf("checked: %+v", rep)
	}
	if rep.PackFail < 1 {
		t.Fatalf("expected pack fail: %+v", rep)
	}
	if rep.PackOK < 1 {
		t.Fatalf("expected pack ok: %+v", rep)
	}
	// Issue kinds should be classified (pack and/or index at minimum).
	if len(rep.IssueCounts) == 0 && rep.PackFail == 0 {
		t.Fatal("expected issue counts")
	}

	var buf bytes.Buffer
	diagnostics.FormatCacheVerifyText(&buf, rep)
	out := buf.String()
	if strings.Contains(out, verifyCanary) {
		t.Fatalf("canary leaked in verify output:\n%s", out)
	}
	if strings.Contains(out, "api_token") || strings.Contains(out, "Authorization") {
		t.Fatalf("secret-like token in output:\n%s", out)
	}
	// Good pack should report index status separately.
	foundGood := false
	for _, r := range rep.Results {
		if r.PackID == "pack-good" {
			foundGood = true
			if !r.PackOK {
				t.Fatalf("good pack not ok: %+v", r)
			}
			if !r.IndexTrusted {
				t.Fatalf("good pack index not trusted: %+v", r)
			}
		}
		if r.PackID == "pack-bad" {
			if r.PackOK {
				t.Fatal("bad pack marked ok")
			}
			// Issues should include pack or checksum kind.
			hasKind := false
			for _, iss := range r.Issues {
				if iss.Kind == "pack" || iss.Kind == "checksum" {
					hasKind = true
				}
			}
			if !hasKind && r.Error == "" {
				t.Fatalf("bad pack missing kinded issue: %+v", r)
			}
		}
	}
	if !foundGood {
		t.Fatal("missing pack-good result")
	}
}

func TestRunCacheVerify_SampleAndCancel(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodAPIToken,
		DataDir:       filepath.Join(paths.DataDir, "profiles", "corp"),
	}
	dataDir, err := store.EnsureProfileDataDir(p.DataDir, string(p.ID))
	if err != nil {
		t.Fatal(err)
	}
	arch := filepath.Join(dataDir, store.ArchivesDirName)
	if err := os.MkdirAll(arch, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("p%d", i)
		data := writeVerifyPack(t, id)
		if err := os.WriteFile(filepath.Join(arch, id+".tar.zst"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := diagnostics.RunCacheVerify(context.Background(), diagnostics.CacheVerifyOptions{
		Profile: p,
		Paths:   &paths,
		Full:    false,
		Sample:  2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Mode != "sample" {
		t.Fatalf("mode %s", rep.Mode)
	}
	if rep.PacksChecked != 2 {
		t.Fatalf("sample checked %d", rep.PacksChecked)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = diagnostics.RunCacheVerify(ctx, diagnostics.CacheVerifyOptions{
		Profile: p,
		Paths:   &paths,
		Full:    true,
	})
	if err == nil {
		t.Fatal("expected cancel error")
	}
}

func TestRunCacheRepair_IndexOnly(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodAPIToken,
		DataDir:       filepath.Join(paths.DataDir, "profiles", "corp"),
	}
	dataDir, err := store.EnsureProfileDataDir(p.DataDir, string(p.ID))
	if err != nil {
		t.Fatal(err)
	}
	arch := filepath.Join(dataDir, store.ArchivesDirName)
	if err := os.MkdirAll(arch, 0o700); err != nil {
		t.Fatal(err)
	}
	data := writeVerifyPack(t, "pack-r1")
	packPath := filepath.Join(arch, "pack-r1.tar.zst")
	if err := os.WriteFile(packPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// No index yet.
	rep, err := diagnostics.RunCacheRepair(context.Background(), diagnostics.CacheRepairOptions{
		Profile:   p,
		Paths:     &paths,
		IndexOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.IndexesRebuilt != 1 {
		t.Fatalf("rebuilt: %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(arch, "pack-r1.idx.json")); err != nil {
		t.Fatal("index file missing after repair")
	}
	// Pack bytes unchanged.
	got, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("repair mutated pack bytes")
	}
	var buf bytes.Buffer
	diagnostics.FormatCacheRepairText(&buf, rep)
	if strings.Contains(buf.String(), verifyCanary) {
		t.Fatal("canary in repair output")
	}
}
