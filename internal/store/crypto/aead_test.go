package crypto_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/store/crypto"
)

func testKey(t *testing.T, ver int) crypto.Key {
	t.Helper()
	// Deterministic non-production test vector (not a real secret).
	mat, err := hex.DecodeString(strings.Repeat("ab", crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	k := crypto.Key{Version: ver, Material: mat}
	if err := k.Validate(); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()
	k := testKey(t, 1)
	aad := crypto.FrameAAD(42, 3, 1)
	plain := []byte("independent-zstd-frame-bytes-not-real-zstd")
	onDisk, err := crypto.Seal(k, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.IsEncrypted(onDisk) {
		t.Fatal("expected encrypted magic")
	}
	ver, err := crypto.KeyVersionOf(onDisk)
	if err != nil || ver != 1 {
		t.Fatalf("version: %d %v", ver, err)
	}
	got, gotVer, err := crypto.Open([]crypto.Key{k}, onDisk, aad)
	if err != nil {
		t.Fatal(err)
	}
	if gotVer != 1 || !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch ver=%d", gotVer)
	}
}

func TestOpenTamperFails(t *testing.T) {
	t.Parallel()
	k := testKey(t, 1)
	aad := crypto.FrameAAD(1, 0, 1)
	onDisk, err := crypto.Seal(k, []byte("payload"), aad)
	if err != nil {
		t.Fatal(err)
	}
	// Bit-flip ciphertext (past header).
	flip := append([]byte(nil), onDisk...)
	flip[len(flip)-1] ^= 0x01
	_, _, err = crypto.Open([]crypto.Key{k}, flip, aad)
	if err == nil {
		t.Fatal("expected auth failure on tamper")
	}
	if apperr.CodeOf(err) != apperr.CodeCorruptCache {
		t.Fatalf("code: %v", apperr.CodeOf(err))
	}
	// Wrong AAD must fail.
	_, _, err = crypto.Open([]crypto.Key{k}, onDisk, crypto.FrameAAD(1, 1, 1))
	if err == nil {
		t.Fatal("expected AAD mismatch failure")
	}
	// Error must not contain key material hex.
	canary := hex.EncodeToString(k.Material)
	if strings.Contains(err.Error(), canary) {
		t.Fatal("key material leaked in error")
	}
}

func TestRotationNandNMinus1(t *testing.T) {
	t.Parallel()
	k1 := testKey(t, 1)
	// Distinct material for v2.
	mat2 := make([]byte, crypto.KeySize)
	for i := range mat2 {
		mat2[i] = byte(i + 1)
	}
	k2 := crypto.Key{Version: 2, Material: mat2}
	aad := crypto.FrameAAD(9, 1, 1)
	oldSeal, err := crypto.Seal(k1, []byte("old"), aad)
	if err != nil {
		t.Fatal(err)
	}
	newSeal, err := crypto.Seal(k2, []byte("new"), aad)
	if err != nil {
		t.Fatal(err)
	}
	env := &crypto.Envelope{Enabled: true, Write: k2, Prev: &k1}
	if err := env.Validate(); err != nil {
		t.Fatal(err)
	}
	keys := env.KeysForRead()
	got, ver, err := crypto.Open(keys, oldSeal, aad)
	if err != nil || ver != 1 || string(got) != "old" {
		t.Fatalf("old: got=%q ver=%d err=%v", got, ver, err)
	}
	got, ver, err = crypto.Open(keys, newSeal, aad)
	if err != nil || ver != 2 || string(got) != "new" {
		t.Fatalf("new: got=%q ver=%d err=%v", got, ver, err)
	}
}

func TestGenerateKey(t *testing.T) {
	t.Parallel()
	k, err := crypto.GenerateKey(3)
	if err != nil {
		t.Fatal(err)
	}
	if k.Version != 3 || len(k.Material) != crypto.KeySize {
		t.Fatalf("key: %+v len=%d", k.Version, len(k.Material))
	}
	// Two generates must differ.
	k2, err := crypto.GenerateKey(3)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k.Material, k2.Material) {
		t.Fatal("expected distinct random keys")
	}
}

func TestOpenMissingKeyFailClosed(t *testing.T) {
	t.Parallel()
	k := testKey(t, 1)
	aad := crypto.FrameAAD(1, 0, 1)
	onDisk, err := crypto.Seal(k, []byte("x"), aad)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = crypto.Open(nil, onDisk, aad)
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("expected authentication fail-closed: %v", err)
	}
}
