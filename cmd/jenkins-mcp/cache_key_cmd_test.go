package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/keyring"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
	storecrypto "github.com/hilather/go-jenkins-mcp/internal/store/crypto"
)

// withTestXDG installs isolated XDG dirs and a Memory keyring for cache-key CLI tests.
func withTestXDG(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	// Clear process-wide encryption force so profile flags alone control EffectiveCacheEncryption.
	t.Setenv("JENKINS_MCP_CACHE_ENCRYPTION", "")

	mem := keyring.NewMemory()
	testKeyringMu.Lock()
	testKeyring = keyring.NewStore(mem)
	testKeyringMu.Unlock()
	t.Cleanup(func() {
		testKeyringMu.Lock()
		testKeyring = nil
		testKeyringMu.Unlock()
	})
}

func testKR(t *testing.T) *keyring.Store {
	t.Helper()
	testKeyringMu.RLock()
	kr := testKeyring
	testKeyringMu.RUnlock()
	if kr == nil {
		t.Fatal("test keyring not installed")
	}
	return kr
}

func saveSeedProfile(t *testing.T, id string) {
	t.Helper()
	ps, err := profileStore()
	if err != nil {
		t.Fatal(err)
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            contracts.ProfileID(id),
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	if err := ps.Save(p); err != nil {
		t.Fatal(err)
	}
}

func captureCacheKeyStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String(), runErr
}

func TestCacheKeyInitStatusRotate_CLI(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")

	// Init
	out, err := captureCacheKeyStdout(t, func() error {
		return runCacheKey([]string{"init", "--profile", "corp"})
	})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if !strings.Contains(out, "cache encryption enabled") || !strings.Contains(out, "key_version=1") {
		t.Fatalf("init out: %q", out)
	}

	// Status after init
	out, err = captureCacheKeyStdout(t, func() error {
		return runCacheKey([]string{"status", "--profile", "corp"})
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out, "cache_encryption=true") {
		t.Fatalf("status encryption: %q", out)
	}
	if !strings.Contains(out, "key_version=1") {
		t.Fatalf("status version: %q", out)
	}
	if !strings.Contains(out, "write_key_present=true") {
		t.Fatalf("status write: %q", out)
	}
	if !strings.Contains(out, "prev_key_present=false") {
		t.Fatalf("status prev: %q", out)
	}

	kr := testKR(t)

	// Capture v1 material for canary (must never appear in status after rotate).
	mat1, err := kr.GetCacheKey("corp", 1)
	if err != nil {
		t.Fatal(err)
	}
	canaryHex := hex.EncodeToString(mat1)
	canaryB64 := base64.StdEncoding.EncodeToString(mat1)

	// Seal a frame with v1, then rotate and ensure N+1 writes + Prev reads.
	aad := storecrypto.FrameAAD(7, 0, 1)
	oldPlain := []byte("frame-sealed-with-v1")
	oldSeal, err := storecrypto.Seal(storecrypto.Key{Version: 1, Material: mat1}, oldPlain, aad)
	if err != nil {
		t.Fatal(err)
	}

	out, err = captureCacheKeyStdout(t, func() error {
		return runCacheKey([]string{"rotate", "--profile", "corp"})
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !strings.Contains(out, "key_version=2") || !strings.Contains(out, "last 2 versions") {
		t.Fatalf("rotate out: %q", out)
	}

	// Profile bumped.
	ps, err := profileStore()
	if err != nil {
		t.Fatal(err)
	}
	p, err := ps.Load("corp")
	if err != nil {
		t.Fatal(err)
	}
	if p.CacheKeyVersion != 2 || !p.CacheEncryption {
		t.Fatalf("profile after rotate: ver=%d enc=%v", p.CacheKeyVersion, p.CacheEncryption)
	}

	// loadFrameCrypto: write=2, prev=1 available.
	fc, err := loadFrameCryptoFromKeyring(kr, "corp", 2)
	if err != nil {
		t.Fatalf("loadFrameCrypto: %v", err)
	}
	if fc == nil || !fc.Enabled() || fc.WriteKeyVersion() != 2 {
		t.Fatalf("fc: enabled=%v ver=%d", fc != nil && fc.Enabled(), fc.WriteKeyVersion())
	}

	// Encrypt with N+1 (v2).
	mat2, err := kr.GetCacheKey("corp", 2)
	if err != nil {
		t.Fatal(err)
	}
	newPlain := []byte("frame-sealed-with-v2")
	newSeal, err := storecrypto.Seal(storecrypto.Key{Version: 2, Material: mat2}, newPlain, aad)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt old (v1) and new (v2) via KeysForRead path (N and N-1).
	env := &storecrypto.Envelope{
		Enabled: true,
		Write:   storecrypto.Key{Version: 2, Material: mat2},
		Prev:    &storecrypto.Key{Version: 1, Material: mat1},
	}
	keys := env.KeysForRead()
	got, ver, err := storecrypto.Open(keys, oldSeal, aad)
	if err != nil || ver != 1 || !bytes.Equal(got, oldPlain) {
		t.Fatalf("decrypt old: ver=%d err=%v got=%q", ver, err, got)
	}
	got, ver, err = storecrypto.Open(keys, newSeal, aad)
	if err != nil || ver != 2 || !bytes.Equal(got, newPlain) {
		t.Fatalf("decrypt new: ver=%d err=%v got=%q", ver, err, got)
	}

	// Status canary: never key material.
	out, err = captureCacheKeyStdout(t, func() error {
		return runCacheKey([]string{"status", "--profile", "corp"})
	})
	if err != nil {
		t.Fatalf("status2: %v", err)
	}
	if !strings.Contains(out, "key_version=2") || !strings.Contains(out, "prev_key_present=true") {
		t.Fatalf("status after rotate: %q", out)
	}
	if strings.Contains(out, canaryHex) || strings.Contains(out, canaryB64) {
		t.Fatalf("Regression: status leaked key material: %q", out)
	}
	if strings.Contains(out, hex.EncodeToString(mat2)) || strings.Contains(out, base64.StdEncoding.EncodeToString(mat2)) {
		t.Fatalf("Regression: status leaked write key material: %q", out)
	}

	// Second rotate → v3; v1 dropped (retention last 2 only).
	_, err = captureCacheKeyStdout(t, func() error {
		return runCacheKey([]string{"rotate", "--profile", "corp"})
	})
	if err != nil {
		t.Fatalf("rotate2: %v", err)
	}
	ok1, err := kr.HasCacheKey("corp", 1)
	if err != nil || ok1 {
		t.Fatalf("v1 must be dropped after second rotate: present=%v err=%v", ok1, err)
	}
	ok2, err := kr.HasCacheKey("corp", 2)
	if err != nil || !ok2 {
		t.Fatalf("v2 must remain as prev: present=%v err=%v", ok2, err)
	}
	ok3, err := kr.HasCacheKey("corp", 3)
	if err != nil || !ok3 {
		t.Fatalf("v3 must be write key: present=%v err=%v", ok3, err)
	}

	// Old v1 frame no longer decryptable via active load path.
	fc3, err := loadFrameCryptoFromKeyring(kr, "corp", 3)
	if err != nil {
		t.Fatal(err)
	}
	if fc3.WriteKeyVersion() != 3 {
		t.Fatalf("write ver %d", fc3.WriteKeyVersion())
	}
	// Open with only N and N-1 from keyring (v3 + v2) must fail for v1 seal.
	mat3, _ := kr.GetCacheKey("corp", 3)
	mat2b, _ := kr.GetCacheKey("corp", 2)
	keysActive := []storecrypto.Key{
		{Version: 3, Material: mat3},
		{Version: 2, Material: mat2b},
	}
	_, _, err = storecrypto.Open(keysActive, oldSeal, aad)
	if err == nil {
		t.Fatal("expected v1 frame unreadable after N-2 drop")
	}
	// v2 still readable.
	got, ver, err = storecrypto.Open(keysActive, newSeal, aad)
	if err != nil || ver != 2 || !bytes.Equal(got, newPlain) {
		t.Fatalf("v2 via prev: ver=%d err=%v", ver, err)
	}
}

func TestCacheKeyRotate_RequiresInit(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	err := runCacheKey([]string{"rotate", "--profile", "corp"})
	if err == nil {
		t.Fatal("expected rotate without init to fail")
	}
	if !strings.Contains(err.Error(), "init") && !strings.Contains(err.Error(), "rotate") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestLoadProfileFrameCrypto_MissingKeyFailClosed(t *testing.T) {
	withTestXDG(t)
	// Encryption on, version set, but no key material in keyring.
	p := &profile.Profile{
		ConfigVersion:   profile.CurrentConfigVersion,
		ID:              contracts.ProfileID("corp"),
		JenkinsURL:      "https://jenkins.example.com/",
		AuthMethod:      profile.AuthMethodAPIToken,
		CacheEncryption: true,
		CacheKeyVersion: 1,
	}
	_, err := loadProfileFrameCrypto(p)
	if err == nil {
		t.Fatal("expected fail closed when key missing")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}
	// Canary: errors must not contain synthetic key bytes.
	const canary = "CACHE_KEY_FAILCLOSED_CANARY_bytes"
	if strings.Contains(err.Error(), canary) {
		t.Fatal("canary in error")
	}
}

func TestCacheKeyStatus_NeverContainsKeyBytes(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")

	// Plant a distinctive key then enable via profile/version without going through init
	// so we control the material for the canary.
	mat := make([]byte, 32)
	for i := range mat {
		mat[i] = 0xcd
	}
	if err := testKR(t).SetCacheKey("corp", 1, mat); err != nil {
		t.Fatal(err)
	}
	ps, err := profileStore()
	if err != nil {
		t.Fatal(err)
	}
	p, err := ps.Load("corp")
	if err != nil {
		t.Fatal(err)
	}
	p.CacheEncryption = true
	p.CacheKeyVersion = 1
	if err := ps.Save(p); err != nil {
		t.Fatal(err)
	}

	out, err := captureCacheKeyStdout(t, func() error {
		return runCacheKey([]string{"status", "--profile", "corp"})
	})
	if err != nil {
		t.Fatal(err)
	}
	// Regression: status output never contains key bytes (hex or base64).
	if strings.Contains(out, hex.EncodeToString(mat)) {
		t.Fatalf("Regression: status leaked hex key: %q", out)
	}
	if strings.Contains(out, base64.StdEncoding.EncodeToString(mat)) {
		t.Fatalf("Regression: status leaked b64 key: %q", out)
	}
	// Raw byte run of 0xcd should not appear as printable sequence either.
	if strings.Contains(out, string(mat)) {
		t.Fatalf("Regression: status leaked raw key bytes: %q", out)
	}
	if !strings.Contains(out, "write_key_present=true") {
		t.Fatalf("status: %q", out)
	}
}

func TestCacheKeyUnknownSubcommand(t *testing.T) {
	err := runCacheKey([]string{"export"})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("%v", err)
	}
	err = runCacheKey(nil)
	if err == nil || !strings.Contains(err.Error(), "subcommand") {
		t.Fatalf("%v", err)
	}
	err = runCacheKey([]string{"status"})
	if err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("%v", err)
	}
}
