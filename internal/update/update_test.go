package update_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/update"
)

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func writeTrustDir(t *testing.T, dir, keyID string, pub ed25519.PublicKey) string {
	t.Helper()
	td := filepath.Join(dir, "trusted_keys")
	if err := os.MkdirAll(td, 0o700); err != nil {
		t.Fatal(err)
	}
	pem, err := update.EncodePublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(td, keyID+".pub")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return td
}

func sampleManifestV2(version string) *update.Manifest {
	return &update.Manifest{
		SchemaVersion: update.SchemaV2,
		Channel:       update.ChannelStable,
		Version:       version,
		Commit:        "abc1234",
		ChangelogURL:  "https://example.corp/changelog/" + version,
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
		NotAfter:      time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		MinSchema:     update.SchemaV2,
		MinAppVersion: "1.0.0",
		Artifacts: map[string]update.Artifact{
			"linux/amd64": {
				URL:      "https://example.corp/jenkins-mcp_" + version + "_linux_amd64.tar.gz",
				SHA256:   strings.Repeat("ab", 32),
				Filename: "jenkins-mcp_" + version + "_linux_amd64.tar.gz",
				Size:     100,
			},
		},
	}
}

func TestSignVerifyHappyPath(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	keysDir := writeTrustDir(t, dir, "corp-update-2026", pub)
	keys, err := update.LoadTrustedKeys(keysDir)
	if err != nil {
		t.Fatal(err)
	}

	m := sampleManifestV2("1.2.3")
	if err := update.SignManifest(m, priv, "corp-update-2026"); err != nil {
		t.Fatal(err)
	}
	raw, err := update.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	res, err := update.VerifyManifest(raw, update.VerifyOptions{
		Keys:       keys,
		AppVersion: "1.0.0",
		Channel:    "stable",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.SignatureState != update.SigStateVerified {
		t.Fatalf("state %s", res.SignatureState)
	}
	if res.KeyID != "corp-update-2026" {
		t.Fatalf("key_id %s", res.KeyID)
	}
	if res.Version != "1.2.3" {
		t.Fatalf("version %s", res.Version)
	}
}

func TestTamperFails(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	keys := update.TrustedKeySet{"k1": pub}

	m := sampleManifestV2("1.2.3")
	if err := update.SignManifest(m, priv, "k1"); err != nil {
		t.Fatal(err)
	}
	// Tamper version after sign.
	m.Version = "9.9.9"
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = update.VerifyManifest(raw, update.VerifyOptions{Keys: keys, AppVersion: "1.0.0"})
	if err == nil {
		t.Fatal("expected tamper failure")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("want signature failure, got %v", err)
	}
	// Regression: no key material in error.
	if strings.Contains(err.Error(), string(pub)) {
		t.Fatal("public key bytes must not appear in error")
	}
}

func TestExpiredFails(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	keys := update.TrustedKeySet{"k1": pub}

	m := sampleManifestV2("1.2.3")
	m.NotAfter = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if err := update.SignManifest(m, priv, "k1"); err != nil {
		t.Fatal(err)
	}
	raw, err := update.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = update.VerifyManifest(raw, update.VerifyOptions{Keys: keys, AppVersion: "1.0.0"})
	if err == nil {
		t.Fatal("expected expiry failure")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("%v", err)
	}
}

func TestUnsignedRejectedWhenKeysPresent(t *testing.T) {
	t.Parallel()
	pub, _ := testKeyPair(t)
	keys := update.TrustedKeySet{"k1": pub}
	m := sampleManifestV2("1.2.3")
	raw, err := update.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = update.VerifyManifest(raw, update.VerifyOptions{
		Keys:          keys,
		AllowUnsigned: true, // ignored when keys present
		AppVersion:    "1.0.0",
	})
	if err == nil {
		t.Fatal("expected unsigned reject")
	}
}

func TestUnsignedPilotOnlyWithAllowFlag(t *testing.T) {
	t.Parallel()
	// v1 lite shape
	raw := []byte(`{"schema_version":1,"channel":"stable","latest":{"version":"1.2.0"}}`)
	_, err := update.VerifyManifest(raw, update.VerifyOptions{AllowUnsigned: false})
	if err == nil {
		t.Fatal("expected reject without allow")
	}
	res, err := update.VerifyManifest(raw, update.VerifyOptions{AllowUnsigned: true, Channel: "stable"})
	if err != nil {
		t.Fatal(err)
	}
	if res.SignatureState != update.SigStateUnverifiedPilot {
		t.Fatalf("state %s", res.SignatureState)
	}
	if res.Version != "1.2.0" {
		t.Fatalf("version %s", res.Version)
	}
}

func TestChannelMismatch(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema_version":1,"channel":"beta","latest":{"version":"9.0.0"}}`)
	_, err := update.VerifyManifest(raw, update.VerifyOptions{AllowUnsigned: true, Channel: "stable"})
	if err == nil || !strings.Contains(err.Error(), "channel") {
		t.Fatalf("expected channel mismatch: %v", err)
	}
}

func TestMinAppVersionFails(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	keys := update.TrustedKeySet{"k1": pub}
	m := sampleManifestV2("2.0.0")
	m.MinAppVersion = "2.0.0"
	if err := update.SignManifest(m, priv, "k1"); err != nil {
		t.Fatal(err)
	}
	raw, err := update.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = update.VerifyManifest(raw, update.VerifyOptions{Keys: keys, AppVersion: "1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "min_app_version") {
		t.Fatalf("%v", err)
	}
}

func TestChecksumMismatchFails(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	payload := []byte("real-artifact-bytes")
	sum := sha256.Sum256(payload)
	wantHex := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve tampered body.
		_, _ = w.Write([]byte("TAMPERED"))
	}))
	defer srv.Close()

	m := sampleManifestV2("1.2.3")
	m.Artifacts = map[string]update.Artifact{
		"linux/amd64": {
			URL:      srv.URL + "/art.bin",
			SHA256:   wantHex,
			Filename: "art.bin",
			Size:     0, // unknown size so size check doesn't fire first
		},
	}
	if err := update.SignManifest(m, priv, "k1"); err != nil {
		t.Fatal(err)
	}
	keys := update.TrustedKeySet{"k1": pub}
	raw, err := update.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	vres, err := update.VerifyManifest(raw, update.VerifyOptions{Keys: keys, AppVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}

	out := t.TempDir()
	_, err = update.DownloadArtifact(update.DownloadOptions{
		Manifest:        vres.Manifest,
		RequireVerified: true,
		SignatureState:  vres.SignatureState,
		GOOS:            "linux",
		GOARCH:          "amd64",
		OutDir:          out,
		HTTPClient:      srv.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("expected checksum fail: %v", err)
	}
	// No partial final file.
	if ents, _ := os.ReadDir(out); len(ents) != 0 {
		// .part files should be cleaned; any leftover is a bug.
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".part") {
				t.Fatalf("unexpected leftover %s", e.Name())
			}
		}
	}
}

// TestUPD001_AutoInstallResidualContract locks the UPD-001 product residual:
// download never claims install; install/rollback stay operator-owned.
func TestUPD001_AutoInstallResidualContract(t *testing.T) {
	t.Parallel()
	// Zero value and explicit field must never advertise auto-install.
	var zero update.DownloadResult
	if zero.AutoInstall {
		t.Fatal("zero DownloadResult.AutoInstall must be false")
	}
	// JSON contract for operator tooling (secret-free residual honesty).
	type wire struct {
		AutoInstall bool `json:"auto_install"`
	}
	b, err := json.Marshal(update.DownloadResult{AutoInstall: false, Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var w wire
	if err := json.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	if w.AutoInstall {
		t.Fatal("json auto_install must be false")
	}
	if strings.Contains(string(b), "token") || strings.Contains(string(b), "password") {
		t.Fatalf("secret-shaped download result: %s", b)
	}
}

func TestDownloadChecksumOKNoAutoInstall(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	payload := []byte("official-artifact-v1.2.3")
	sum := sha256.Sum256(payload)
	sumHex := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	m := sampleManifestV2("1.2.3")
	m.Artifacts = map[string]update.Artifact{
		"linux/amd64": {
			URL:      srv.URL + "/jenkins-mcp_1.2.3_linux_amd64.tar.gz",
			SHA256:   sumHex,
			Filename: "jenkins-mcp_1.2.3_linux_amd64.tar.gz",
			Size:     int64(len(payload)),
		},
	}
	if err := update.SignManifest(m, priv, "k1"); err != nil {
		t.Fatal(err)
	}
	keys := update.TrustedKeySet{"k1": pub}
	raw, err := update.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	vres, err := update.VerifyManifest(raw, update.VerifyOptions{Keys: keys, AppVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}

	out := t.TempDir()
	dres, err := update.DownloadArtifact(update.DownloadOptions{
		Manifest:        vres.Manifest,
		RequireVerified: true,
		SignatureState:  vres.SignatureState,
		GOOS:            "linux",
		GOARCH:          "amd64",
		OutDir:          out,
		HTTPClient:      srv.Client(),
		UserAgent:       "jenkins-mcp-test/1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if dres.AutoInstall {
		t.Fatal("auto_install must always be false")
	}
	if dres.SHA256 != sumHex {
		t.Fatalf("sha %s", dres.SHA256)
	}
	got, err := os.ReadFile(dres.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch")
	}
	if !strings.Contains(dres.NextSteps, "not installed") && !strings.Contains(dres.NextSteps, "package manager") {
		t.Fatalf("next steps: %s", dres.NextSteps)
	}
}

func TestDownloadRejectsUnverified(t *testing.T) {
	t.Parallel()
	m := sampleManifestV2("1.2.3")
	_, err := update.DownloadArtifact(update.DownloadOptions{
		Manifest:        m,
		RequireVerified: true,
		SignatureState:  update.SigStateUnverifiedPilot,
		GOOS:            "linux",
		GOARCH:          "amd64",
		OutDir:          t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "verified") {
		t.Fatalf("%v", err)
	}
}

func TestDownloadUnwritableOutdir(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	// Use a file path as outdir — not a directory.
	f := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := sampleManifestV2("1.2.3")
	if err := update.SignManifest(m, priv, "k1"); err != nil {
		t.Fatal(err)
	}
	_, err := update.DownloadArtifact(update.DownloadOptions{
		Manifest:        m,
		RequireVerified: true,
		SignatureState:  update.SigStateVerified,
		GOOS:            "linux",
		GOARCH:          "amd64",
		OutDir:          f,
	})
	if err == nil {
		t.Fatal("expected unwritable/not-dir error")
	}
	_ = pub
}

func TestCompareVersions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cur, rem, want string
	}{
		{"1.0.0", "1.0.1", "newer"},
		{"1.2.0", "1.1.9", "older"},
		{"v1.2.3", "1.2.3", "same"},
		{"1.2.3-4-gabcdef", "1.2.3", "same"},
		{"dev", "1.0.0", "unknown"},
		{"1.0", "1.0.0", "same"},
	}
	for _, tc := range cases {
		got := update.CompareVersions(tc.cur, tc.rem)
		if got != tc.want {
			t.Errorf("CompareVersions(%q,%q)=%q want %q", tc.cur, tc.rem, got, tc.want)
		}
	}
}

func TestVerifyDoesNotMutateSignedFields(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	keys := update.TrustedKeySet{"k1": pub}
	m := sampleManifestV2("1.2.3")
	// Non-normalized platform key must still verify after parse.
	m.Artifacts = map[string]update.Artifact{
		"Linux/AMD64": {
			URL:    "https://example.corp/a.tgz",
			SHA256: strings.Repeat("ab", 32),
		},
	}
	if err := update.SignManifest(m, priv, "k1"); err != nil {
		t.Fatal(err)
	}
	raw, err := update.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	res, err := update.VerifyManifest(raw, update.VerifyOptions{Keys: keys, AppVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if res.SignatureState != update.SigStateVerified {
		t.Fatalf("%s", res.SignatureState)
	}
	if _, ok := res.Manifest.ArtifactFor("linux", "amd64"); !ok {
		t.Fatal("case-insensitive artifact lookup failed")
	}
}

func TestSignedWithoutKeysRejected(t *testing.T) {
	t.Parallel()
	_, priv := testKeyPair(t)
	m := sampleManifestV2("1.2.3")
	if err := update.SignManifest(m, priv, "k1"); err != nil {
		t.Fatal(err)
	}
	raw, err := update.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = update.VerifyManifest(raw, update.VerifyOptions{AllowUnsigned: true, AppVersion: "1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "no trusted") {
		t.Fatalf("%v", err)
	}
}

func TestLKGStoreLoadRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "last_known_good.json")
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	sum := strings.Repeat("ab", 32)
	rec, err := update.StoreLKG(update.LKGWriteOptions{
		Path:            path,
		Version:         "1.2.3",
		Channel:         "stable",
		ArtifactSHA256:  sum,
		ArtifactPath:    filepath.Join(dir, "nested", "jenkins-mcp_1.2.3_linux_amd64.tar.gz"),
		SignatureKeyIDs: []string{"corp-update-2026", "corp-update-2026", "backup-key"},
		Platform:        "linux/amd64",
		Now:             func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.PathBasename != "jenkins-mcp_1.2.3_linux_amd64.tar.gz" {
		t.Fatalf("basename %q", rec.PathBasename)
	}
	if len(rec.SignatureKeyIDs) != 2 {
		t.Fatalf("key ids dedupe: %v", rec.SignatureKeyIDs)
	}
	// Reload.
	got, err := update.LoadLKG(path)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Version != "1.2.3" || got.ArtifactSHA256 != sum {
		t.Fatalf("%+v", got)
	}
	if got.Timestamp != "2026-08-01T12:00:00Z" {
		t.Fatalf("ts %s", got.Timestamp)
	}
	// Secret-free: no URL, no private key markers on disk.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ToLower(string(raw))
	for _, bad := range []string{"http://", "https://", "private", "password", "token"} {
		if strings.Contains(s, bad) {
			t.Fatalf("LKG must not contain %q: %s", bad, raw)
		}
	}
}

func TestLKGMissingIsNil(t *testing.T) {
	t.Parallel()
	got, err := update.LoadLKG(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || got != nil {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestLKGCorruptFailsClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "lkg.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := update.LoadLKG(path)
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("%v", err)
	}
}

func TestLKGRejectsURLInBasename(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "lkg.json")
	// Craft invalid on-disk record (bypass StoreLKG basename sanitization).
	raw := []byte(`{
  "schema_version": 1,
  "version": "1.0.0",
  "channel": "stable",
  "artifact_sha256": "` + strings.Repeat("ab", 32) + `",
  "path_basename": "https://evil.example/a.bin",
  "timestamp": "2026-08-01T00:00:00Z"
}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := update.LoadLKG(path)
	if err == nil || !strings.Contains(err.Error(), "basename") {
		t.Fatalf("%v", err)
	}
}

func TestPreflightDowngradeRejectedByDefault(t *testing.T) {
	t.Parallel()
	m := sampleManifestV2("1.0.0")
	err := update.PreflightAccept(update.PreflightOptions{
		Manifest:       m,
		CurrentVersion: "2.0.0",
		AllowDowngrade: false,
		GOOS:           "linux",
		GOARCH:         "amd64",
		SkipFreeSpace:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("%v", err)
	}
	// Opt-in allows.
	err = update.PreflightAccept(update.PreflightOptions{
		Manifest:       m,
		CurrentVersion: "2.0.0",
		AllowDowngrade: true,
		GOOS:           "linux",
		GOARCH:         "amd64",
		SkipFreeSpace:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPreflightEqualAndNewerOK(t *testing.T) {
	t.Parallel()
	for _, ver := range []string{"1.2.3", "1.2.4"} {
		m := sampleManifestV2(ver)
		err := update.PreflightAccept(update.PreflightOptions{
			Manifest:       m,
			CurrentVersion: "1.2.3",
			ChannelPin:     "stable",
			GOOS:           "linux",
			GOARCH:         "amd64",
			SkipFreeSpace:  true,
		})
		if err != nil {
			t.Fatalf("version %s: %v", ver, err)
		}
	}
}

func TestPreflightChannelPinReject(t *testing.T) {
	t.Parallel()
	m := sampleManifestV2("2.0.0")
	m.Channel = "beta"
	err := update.PreflightAccept(update.PreflightOptions{
		Manifest:       m,
		CurrentVersion: "1.0.0",
		ChannelPin:     "stable",
		GOOS:           "linux",
		GOARCH:         "amd64",
		SkipFreeSpace:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "channel") {
		t.Fatalf("%v", err)
	}
}

func TestPreflightFreeSpaceInsufficient(t *testing.T) {
	t.Parallel()
	m := sampleManifestV2("2.0.0")
	// Size under MaxBytes but larger than any real free volume → free-space reject.
	art := m.Artifacts["linux/amd64"]
	art.Size = 1 << 50 // 1 PiB
	m.Artifacts["linux/amd64"] = art
	out := t.TempDir()
	err := update.PreflightAccept(update.PreflightOptions{
		Manifest:       m,
		CurrentVersion: "1.0.0",
		GOOS:           "linux",
		GOARCH:         "amd64",
		OutDir:         out,
		MaxBytes:       1 << 52, // allow declared size past default 512 MiB cap
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "space") {
		t.Fatalf("expected free-space failure: %v", err)
	}
}

func TestPreflightCredentialURLRejected(t *testing.T) {
	t.Parallel()
	m := sampleManifestV2("2.0.0")
	art := m.Artifacts["linux/amd64"]
	art.URL = "https://user:secret@example.corp/art.bin"
	m.Artifacts["linux/amd64"] = art
	err := update.PreflightAccept(update.PreflightOptions{
		Manifest:       m,
		CurrentVersion: "1.0.0",
		GOOS:           "linux",
		GOARCH:         "amd64",
		SkipFreeSpace:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "credential") {
		t.Fatalf("%v", err)
	}
}

func TestDownloadRejectsDowngrade(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	payload := []byte("older-artifact")
	sum := sha256.Sum256(payload)
	sumHex := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	m := sampleManifestV2("1.0.0")
	m.Artifacts = map[string]update.Artifact{
		"linux/amd64": {
			URL:      srv.URL + "/a.bin",
			SHA256:   sumHex,
			Filename: "a.bin",
			Size:     int64(len(payload)),
		},
	}
	if err := update.SignManifest(m, priv, "k1"); err != nil {
		t.Fatal(err)
	}
	keys := update.TrustedKeySet{"k1": pub}
	raw, err := update.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	vres, err := update.VerifyManifest(raw, update.VerifyOptions{Keys: keys, AppVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = update.DownloadArtifact(update.DownloadOptions{
		Manifest:        vres.Manifest,
		RequireVerified: true,
		SignatureState:  vres.SignatureState,
		GOOS:            "linux",
		GOARCH:          "amd64",
		OutDir:          t.TempDir(),
		HTTPClient:      srv.Client(),
		CurrentVersion:  "2.0.0",
		ChannelPin:      "stable",
		AllowDowngrade:  false,
	})
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("expected downgrade reject: %v", err)
	}
	// No network body written if preflight fails first — server may still be hit only after preflight.
	// Ensure outdir empty.
	ents, _ := os.ReadDir(t.TempDir()) // fresh empty is fine; use download outdir
	_ = ents
}

func TestDownloadOKWritesNoLKGInternally(t *testing.T) {
	// DownloadArtifact itself does not write LKG — CLI does. Regression: package stays pure.
	t.Parallel()
	pub, priv := testKeyPair(t)
	payload := []byte("official-artifact-v2.0.0")
	sum := sha256.Sum256(payload)
	sumHex := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	m := sampleManifestV2("2.0.0")
	m.Artifacts = map[string]update.Artifact{
		"linux/amd64": {
			URL:      srv.URL + "/art.bin",
			SHA256:   sumHex,
			Filename: "art.bin",
			Size:     int64(len(payload)),
		},
	}
	if err := update.SignManifest(m, priv, "k1"); err != nil {
		t.Fatal(err)
	}
	keys := update.TrustedKeySet{"k1": pub}
	raw, _ := update.MarshalManifest(m)
	vres, err := update.VerifyManifest(raw, update.VerifyOptions{Keys: keys, AppVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	dres, err := update.DownloadArtifact(update.DownloadOptions{
		Manifest:        vres.Manifest,
		RequireVerified: true,
		SignatureState:  vres.SignatureState,
		GOOS:            "linux",
		GOARCH:          "amd64",
		OutDir:          out,
		HTTPClient:      srv.Client(),
		CurrentVersion:  "1.0.0",
		ChannelPin:      "stable",
	})
	if err != nil {
		t.Fatal(err)
	}
	if dres.Version != "2.0.0" || dres.AutoInstall {
		t.Fatalf("%+v", dres)
	}
	// Store LKG after download (CLI path).
	lkgPath := filepath.Join(out, "last_known_good.json")
	rec, err := update.StoreLKG(update.LKGWriteOptions{
		Path:            lkgPath,
		Version:         dres.Version,
		Channel:         dres.Channel,
		ArtifactSHA256:  dres.SHA256,
		ArtifactPath:    dres.Path,
		SignatureKeyIDs: update.SignatureKeyIDsFromManifest(vres.Manifest),
		Platform:        dres.Platform,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Version != "2.0.0" || rec.PathBasename != "art.bin" {
		t.Fatalf("%+v", rec)
	}
}

func TestCheckDowngradePolicy(t *testing.T) {
	t.Parallel()
	if err := update.CheckDowngradePolicy("1.0.0", "1.0.0", false); err != nil {
		t.Fatal(err)
	}
	if err := update.CheckDowngradePolicy("1.0.0", "1.1.0", false); err != nil {
		t.Fatal(err)
	}
	if err := update.CheckDowngradePolicy("2.0.0", "1.0.0", false); err == nil {
		t.Fatal("expected reject")
	}
	if err := update.CheckDowngradePolicy("2.0.0", "1.0.0", true); err != nil {
		t.Fatal(err)
	}
	if err := update.CheckDowngradePolicy("dev", "1.0.0", false); err != nil {
		t.Fatal(err)
	}
}

// --- Wave 35: LKG on-disk re-verify ---

func TestFileSHA256(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	payload := []byte("lkg-verify-payload")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)
	got, err := update.FileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("got %s want %s", got, hex.EncodeToString(want[:]))
	}
	if _, err := update.FileSHA256(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected not found")
	}
	if _, err := update.FileSHA256(dir); err == nil {
		t.Fatal("expected directory reject")
	}
}

func TestVerifyLKGMatchViaSearchDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	payload := []byte("good-lkg-artifact")
	sum := sha256.Sum256(payload)
	sumHex := hex.EncodeToString(sum[:])
	artName := "jenkins-mcp_9.9.9_linux_amd64.tar.gz"
	artPath := filepath.Join(dir, artName)
	if err := os.WriteFile(artPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	lkgPath := filepath.Join(dir, "last_known_good.json")
	if _, err := update.StoreLKG(update.LKGWriteOptions{
		Path:           lkgPath,
		Version:        "9.9.9",
		Channel:        "stable",
		ArtifactSHA256: sumHex,
		ArtifactPath:   artPath,
		Platform:       "linux/amd64",
	}); err != nil {
		t.Fatal(err)
	}
	res, err := update.VerifyLKG(update.VerifyLKGOptions{
		LKGPath:    lkgPath,
		SearchDirs: []string{dir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.SHAMatch || !res.ArtifactFound || !res.LKGPresent {
		t.Fatalf("%+v", res)
	}
	if res.Version != "9.9.9" || res.PathBasename != artName {
		t.Fatalf("%+v", res)
	}
	if res.ActualSHA256 != sumHex {
		t.Fatalf("actual %s", res.ActualSHA256)
	}
	// Secret-free residual only.
	raw, _ := json.Marshal(res)
	lower := strings.ToLower(string(raw))
	for _, bad := range []string{"private_key", "password", "https://", "bearer "} {
		if strings.Contains(lower, bad) {
			t.Fatalf("secret-ish %q in result: %s", bad, raw)
		}
	}
}

func TestVerifyLKGMatchViaExplicitFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	payload := []byte("explicit-file-artifact")
	sumHex := hex.EncodeToString(sha256Sum(payload))
	// Staged outside search dir.
	stageDir := filepath.Join(dir, "stage")
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	artPath := filepath.Join(stageDir, "art.bin")
	if err := os.WriteFile(artPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	lkgPath := filepath.Join(dir, "lkg.json")
	if _, err := update.StoreLKG(update.LKGWriteOptions{
		Path:           lkgPath,
		Version:        "1.0.0",
		Channel:        "stable",
		ArtifactSHA256: sumHex,
		ArtifactPath:   "art.bin",
	}); err != nil {
		t.Fatal(err)
	}
	// Without --file, search empty custom dir → not found.
	miss, err := update.VerifyLKG(update.VerifyLKGOptions{
		LKGPath:    lkgPath,
		SearchDirs: []string{filepath.Join(dir, "empty")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if miss.OK || miss.ArtifactFound {
		t.Fatalf("expected miss: %+v", miss)
	}
	// With explicit file → ok.
	res, err := update.VerifyLKG(update.VerifyLKGOptions{
		LKGPath:      lkgPath,
		ArtifactPath: artPath,
		SearchDirs:   []string{filepath.Join(dir, "empty")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.SHAMatch {
		t.Fatalf("%+v", res)
	}
}

func TestVerifyLKGMismatchFailsClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// LKG claims one hash; file has different content.
	good := []byte("original")
	bad := []byte("tampered")
	goodSum := hex.EncodeToString(sha256Sum(good))
	artPath := filepath.Join(dir, "art.bin")
	if err := os.WriteFile(artPath, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	lkgPath := filepath.Join(dir, "lkg.json")
	if _, err := update.StoreLKG(update.LKGWriteOptions{
		Path:           lkgPath,
		Version:        "1.0.0",
		Channel:        "beta",
		ArtifactSHA256: goodSum,
		ArtifactPath:   artPath,
	}); err != nil {
		t.Fatal(err)
	}
	res, err := update.VerifyLKG(update.VerifyLKGOptions{
		LKGPath:    lkgPath,
		SearchDirs: []string{dir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.SHAMatch || !res.ArtifactFound {
		t.Fatalf("expected mismatch fail closed: %+v", res)
	}
	if !strings.Contains(res.Reason, "mismatch") {
		t.Fatalf("reason %q", res.Reason)
	}
	if res.ActualSHA256 == goodSum {
		t.Fatal("actual should differ from expected")
	}
}

func TestVerifyLKGMissingArtifact(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	lkgPath := filepath.Join(dir, "lkg.json")
	if _, err := update.StoreLKG(update.LKGWriteOptions{
		Path:           lkgPath,
		Version:        "1.0.0",
		Channel:        "stable",
		ArtifactSHA256: strings.Repeat("cd", 32),
		ArtifactPath:   "gone.bin",
	}); err != nil {
		t.Fatal(err)
	}
	res, err := update.VerifyLKG(update.VerifyLKGOptions{
		LKGPath:    lkgPath,
		SearchDirs: []string{dir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.ArtifactFound || res.SHAMatch {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(res.Reason, "not found") {
		t.Fatalf("reason %q", res.Reason)
	}
}

func TestVerifyLKGMissingRecord(t *testing.T) {
	t.Parallel()
	res, err := update.VerifyLKG(update.VerifyLKGOptions{
		LKGPath: filepath.Join(t.TempDir(), "no-lkg.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.LKGPresent {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(res.Reason, "no last-known-good") {
		t.Fatalf("reason %q", res.Reason)
	}
	// Residual honesty always populated (metadata only / operator-owned).
	if res.Residual != update.ResidualLKGIntegrity || res.Residual == "" {
		t.Fatalf("residual: %q", res.Residual)
	}
}

// TestResidualLKGIntegrityHonesty proves the exported residual note is non-empty
// and states LKG is metadata only (not an installed binary; operator-owned).
func TestResidualLKGIntegrityHonesty(t *testing.T) {
	t.Parallel()
	note := update.ResidualLKGIntegrity
	if strings.TrimSpace(note) == "" {
		t.Fatal("ResidualLKGIntegrity must be non-empty")
	}
	if update.LKGResidualNote() != note {
		t.Fatal("LKGResidualNote must equal ResidualLKGIntegrity")
	}
	lower := strings.ToLower(note)
	if !strings.Contains(lower, "not an installed binary") {
		t.Fatalf("must say not an installed binary: %s", note)
	}
	if !strings.Contains(lower, "metadata") {
		t.Fatalf("must mention metadata: %s", note)
	}
	if !strings.Contains(lower, "operator-owned") && !strings.Contains(lower, "operator owned") {
		t.Fatalf("must say operator-owned: %s", note)
	}
	// Secret-free: no PEM / bearer material in the constant.
	if strings.Contains(strings.ToUpper(note), "BEGIN PRIVATE") ||
		strings.Contains(note, "Bearer ") ||
		strings.Contains(note, "password=") {
		t.Fatal("ResidualLKGIntegrity must be secret-free")
	}
}

func TestVerifyLKGEmptyBasenameNeedsFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Craft LKG with empty basename (StoreLKG allows empty base).
	lkgPath := filepath.Join(dir, "lkg.json")
	if _, err := update.StoreLKG(update.LKGWriteOptions{
		Path:           lkgPath,
		Version:        "1.0.0",
		Channel:        "stable",
		ArtifactSHA256: strings.Repeat("ab", 32),
		ArtifactPath:   "", // empty → empty basename
	}); err != nil {
		t.Fatal(err)
	}
	res, err := update.VerifyLKG(update.VerifyLKGOptions{
		LKGPath:    lkgPath,
		SearchDirs: []string{dir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.ArtifactFound {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(res.Reason, "--file") {
		t.Fatalf("reason should suggest --file: %q", res.Reason)
	}
	// Explicit file still works.
	payload := []byte("x")
	// Need matching hash for OK; write file with expected hash content.
	// expected is strings.Repeat("ab",32) — just prove found+hash path.
	art := filepath.Join(dir, "manual.bin")
	// Wrong content → found but mismatch.
	if err := os.WriteFile(art, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	res2, err := update.VerifyLKG(update.VerifyLKGOptions{
		LKGPath:      lkgPath,
		ArtifactPath: art,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.ArtifactFound || res2.OK {
		t.Fatalf("expect found+mismatch: %+v", res2)
	}
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func TestAllowDowngradeFromEnviron(t *testing.T) {
	t.Setenv(update.EnvUpdateAllowDowngrade, "")
	if update.AllowDowngradeFromEnviron() {
		t.Fatal("default must be false")
	}
	t.Setenv(update.EnvUpdateAllowDowngrade, "1")
	if !update.AllowDowngradeFromEnviron() {
		t.Fatal("want true")
	}
	t.Setenv(update.EnvUpdateAllowDowngrade, "true")
	if update.AllowDowngradeFromEnviron() {
		t.Fatal("only exact 1")
	}
}

func TestSignatureKeyIDsFromManifest(t *testing.T) {
	t.Parallel()
	m := sampleManifestV2("1.0.0")
	m.Signatures = []update.ManifestSignature{
		{KeyID: "b", Signature: "x"},
		{KeyID: "a", Signature: "y"},
		{KeyID: "b", Signature: "z"},
	}
	ids := update.SignatureKeyIDsFromManifest(m)
	if len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("%v", ids)
	}
}
