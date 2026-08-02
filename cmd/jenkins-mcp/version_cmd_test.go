package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/update"
)

func TestBuildVersionInfoJSONShape(t *testing.T) {
	// Override package vars for deterministic fields (not parallel — shared package state).
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "1.2.3", "abc1234", "2026-08-01T00:00:00Z"
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()

	info := buildVersionInfo()
	if info.Version != "1.2.3" || info.Commit != "abc1234" || info.BuildTime != "2026-08-01T00:00:00Z" {
		t.Fatalf("unexpected info: %+v", info)
	}
	if info.GoVersion == "" || info.OS == "" || info.Arch == "" {
		t.Fatalf("runtime fields empty: %+v", info)
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "commit", "buildTime", "goVersion", "os", "arch"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing key %q in %s", k, string(b))
		}
	}
	// Regression: no secret-looking keys.
	raw := string(b)
	for _, bad := range []string{"token", "password", "authorization", "secret"} {
		if strings.Contains(strings.ToLower(raw), bad) {
			t.Fatalf("unexpected secret-ish field %q in version JSON: %s", bad, raw)
		}
	}
}

func TestRunVersionJSON(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "9.9.9", "deadbeef", "2026-01-01T00:00:00Z"
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()

	out := captureStdout(t, func() {
		if err := runVersion([]string{"--json"}); err != nil {
			t.Fatal(err)
		}
	})
	var info versionInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if info.Version != "9.9.9" || info.Commit != "deadbeef" {
		t.Fatalf("%+v", info)
	}
}

func TestUpdateCheckSkipsNetworkWhenEnvEmpty(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "1.0.0", "c0", "t0"
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()

	rep, err := performUpdateCheck(updateCheckParams{
		Channel:    "stable",
		AppVersion: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.NetworkSkipped || rep.ManifestURLSet {
		t.Fatalf("expected skip: %+v", rep)
	}
	if rep.AutoDownload {
		t.Fatal("auto_download must always be false")
	}
	if rep.NewerAvailable {
		t.Fatal("no network ⇒ not newer")
	}
	if !strings.Contains(rep.Residual, "JENKINS_MCP_UPDATE_MANIFEST_URL") {
		t.Fatalf("residual: %s", rep.Residual)
	}
}

func TestUpdateCheckHTTPManifestNewerUnsignedPilot(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "1.0.0", "old", "t0"
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()

	const canary = "CANARY_TOKEN_update_check_must_not_echo"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		if !strings.Contains(r.Header.Get("Accept"), "json") {
			t.Errorf("Accept: %s", r.Header.Get("Accept"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema_version": 1,
			"channel":        "stable",
			"latest": map[string]any{
				"version":       "1.2.0",
				"commit":        "newc",
				"changelog_url": "https://example.corp/changelog/1.2.0",
				"published_at":  "2026-08-01T00:00:00Z",
			},
			"notes": "no secrets " + canary,
		})
	}))
	defer srv.Close()

	rep, err := performUpdateCheck(updateCheckParams{
		Channel:       "stable",
		ManifestURL:   srv.URL,
		AllowUnsigned: true,
		AppVersion:    "1.0.0",
		HTTPClient:    srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.NewerAvailable || rep.LatestVersion != "1.2.0" {
		t.Fatalf("%+v", rep)
	}
	if rep.CompareResult != "newer" {
		t.Fatalf("compare: %s", rep.CompareResult)
	}
	if rep.ChangelogURL != "https://example.corp/changelog/1.2.0" {
		t.Fatalf("changelog: %s", rep.ChangelogURL)
	}
	if rep.AutoDownload {
		t.Fatal("must never auto-download")
	}
	if rep.SignatureState != update.SigStateUnverifiedPilot {
		t.Fatalf("signature_state %s", rep.SignatureState)
	}
}

func TestUpdateCheckSignedManifest(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "1.0.0", "old", "t0"
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &update.Manifest{
		SchemaVersion: update.SchemaV2,
		Channel:       "stable",
		Version:       "1.5.0",
		Commit:        "newc",
		ChangelogURL:  "https://example.corp/changelog/1.5.0",
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
		NotAfter:      time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		MinAppVersion: "1.0.0",
		Artifacts: map[string]update.Artifact{
			"linux/amd64": {
				URL:    "https://example.corp/art.tgz",
				SHA256: strings.Repeat("ab", 32),
			},
		},
	}
	if err := update.SignManifest(m, priv, "corp-u"); err != nil {
		t.Fatal(err)
	}
	raw, err := update.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	keys := update.TrustedKeySet{"corp-u": pub}
	rep, err := performUpdateCheck(updateCheckParams{
		Channel:     "stable",
		ManifestURL: srv.URL,
		Keys:        keys,
		AppVersion:  "1.0.0",
		HTTPClient:  srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.SignatureState != update.SigStateVerified || rep.SignatureKeyID != "corp-u" {
		t.Fatalf("%+v", rep)
	}
	if !rep.NewerAvailable || rep.LatestVersion != "1.5.0" {
		t.Fatalf("%+v", rep)
	}
}

func TestUpdateCheckRejectsUnsignedWhenKeysPresent(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema_version": 1,
			"channel":        "stable",
			"latest":         map[string]any{"version": "9.0.0"},
		})
	}))
	defer srv.Close()

	_, err = performUpdateCheck(updateCheckParams{
		Channel:       "stable",
		ManifestURL:   srv.URL,
		Keys:          update.TrustedKeySet{"k": pub},
		AllowUnsigned: true,
		AppVersion:    "1.0.0",
		HTTPClient:    srv.Client(),
	})
	if err == nil {
		t.Fatal("expected reject unsigned when keys present")
	}
}

func TestUpdateCheckHTTPManifestSame(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "2.0.0", "c", "t"
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema_version": 1,
			"channel":        "stable",
			"latest": map[string]any{
				"version": "2.0.0",
			},
		})
	}))
	defer srv.Close()

	rep, err := performUpdateCheck(updateCheckParams{
		Channel:       "stable",
		ManifestURL:   srv.URL,
		AllowUnsigned: true,
		AppVersion:    "2.0.0",
		HTTPClient:    srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.NewerAvailable || rep.CompareResult != "same" {
		t.Fatalf("%+v", rep)
	}
}

func TestUpdateCheckChannelMismatch(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema_version": 1,
			"channel":        "beta",
			"latest":         map[string]any{"version": "9.0.0"},
		})
	}))
	defer srv.Close()

	_, err := performUpdateCheck(updateCheckParams{
		Channel:       "stable",
		ManifestURL:   srv.URL,
		AllowUnsigned: true,
		HTTPClient:    srv.Client(),
	})
	if err == nil {
		t.Fatal("expected channel mismatch error")
	}
	if !strings.Contains(err.Error(), "channel") {
		t.Fatalf("%v", err)
	}
}

func TestUpdateCheckRejectsNonHTTPURL(t *testing.T) {
	t.Parallel()
	_, err := performUpdateCheck(updateCheckParams{
		Channel:     "stable",
		ManifestURL: "file:///etc/passwd",
	})
	if err == nil {
		t.Fatal("expected invalid scheme")
	}
}

func TestUpdateCheckBadJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()
	_, err := performUpdateCheck(updateCheckParams{
		Channel:       "stable",
		ManifestURL:   srv.URL,
		AllowUnsigned: true,
		HTTPClient:    srv.Client(),
	})
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestUpdateVerifyManifestCLI(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pem, err := update.EncodePublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "corp.pub"), pem, 0o600); err != nil {
		t.Fatal(err)
	}
	m := &update.Manifest{
		SchemaVersion: update.SchemaV2,
		Channel:       "stable",
		Version:       "3.0.0",
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
		NotAfter:      time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Artifacts: map[string]update.Artifact{
			"linux/amd64": {URL: "https://example.corp/a.tgz", SHA256: strings.Repeat("cd", 32)},
		},
	}
	if err := update.SignManifest(m, priv, "corp"); err != nil {
		t.Fatal(err)
	}
	raw, err := update.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	manPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runUpdate([]string{"verify-manifest", "--file", manPath, "--keys", keysDir, "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if report["ok"] != true {
		t.Fatalf("%v", report)
	}
	if report["signature_state"] != update.SigStateVerified {
		t.Fatalf("%v", report)
	}
}

func TestUpdateDownloadRequiresKeys(t *testing.T) {
	// Ensure empty trusted keys path.
	t.Setenv(update.EnvUpdateTrustedKeysVar, filepath.Join(t.TempDir(), "missing-keys-dir-xyz"))
	// LoadTrustedKeys errors on missing path when env is set — use empty env and empty XDG.
	t.Setenv(update.EnvUpdateTrustedKeysVar, "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv(EnvUpdateManifestURL, "https://example.corp/manifest.json")
	err := runUpdate([]string{"download", "--channel", "stable"})
	if err == nil || !strings.Contains(err.Error(), "trusted keys") {
		t.Fatalf("expected trusted keys requirement: %v", err)
	}
}

func TestUpdateCheckIncludesLKG(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "1.5.0", "c", "t"
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()

	lkgPath := filepath.Join(t.TempDir(), "lkg.json")
	sum := strings.Repeat("cd", 32)
	if _, err := update.StoreLKG(update.LKGWriteOptions{
		Path:            lkgPath,
		Version:         "1.2.0",
		Channel:         "stable",
		ArtifactSHA256:  sum,
		ArtifactPath:    "jenkins-mcp_1.2.0_linux_amd64.tar.gz",
		SignatureKeyIDs: []string{"corp-u"},
		Platform:        "linux/amd64",
	}); err != nil {
		t.Fatal(err)
	}

	rep, err := performUpdateCheck(updateCheckParams{
		Channel:    "stable",
		AppVersion: "1.5.0",
		LKGPath:    lkgPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.LKGPresent || rep.LKGVersion != "1.2.0" {
		t.Fatalf("%+v", rep)
	}
	if rep.LKGSHA256 != sum {
		t.Fatalf("sha %s", rep.LKGSHA256)
	}
	if rep.CompareLKG != "older" {
		// current 1.5.0 vs lkg 1.2.0 → remote(lkg) is older ⇒ CompareVersions(current, lkg) = "older"
		t.Fatalf("compare_lkg %s", rep.CompareLKG)
	}
	if !strings.Contains(rep.Message, "lkg") {
		t.Fatalf("message should mention lkg: %s", rep.Message)
	}
}

func TestUpdateShowLKGCLI(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv(update.EnvUpdateLKGPath, "")
	// Resolve uses XDG_DATA_HOME → …/jenkins-mcp/update/last_known_good.json
	// Store via package API to the resolved path.
	paths, err := config.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	lkgPath := paths.UpdateLKGFile()
	if _, err := update.StoreLKG(update.LKGWriteOptions{
		Path:            lkgPath,
		Version:         "3.1.4",
		Channel:         "stable",
		ArtifactSHA256:  strings.Repeat("ef", 32),
		ArtifactPath:    "art.bin",
		SignatureKeyIDs: []string{"k1"},
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runUpdate([]string{"show-lkg", "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if report["present"] != true {
		t.Fatalf("%v", report)
	}
	if report["version"] != "3.1.4" {
		t.Fatalf("%v", report)
	}
	// Regression: no full home path secrets; only basename of lkg_path.
	if lp, _ := report["lkg_path"].(string); strings.Contains(lp, dataHome) {
		t.Fatalf("must not leak full data home in lkg_path: %s", lp)
	}
	raw := strings.ToLower(out)
	for _, bad := range []string{"private_key", "password", "https://"} {
		if strings.Contains(raw, bad) {
			t.Fatalf("secret-ish %q in show-lkg: %s", bad, out)
		}
	}
}

func TestUpdateShowLKGAbsent(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv(update.EnvUpdateLKGPath, filepath.Join(t.TempDir(), "no-such-lkg.json"))
	out := captureStdout(t, func() {
		if err := runUpdate([]string{"show-lkg", "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report["present"] != false {
		t.Fatalf("%v", report)
	}
}

// Release-evidence tests live in release_evidence_cmd_test.go (schema v2 Wave 21).
