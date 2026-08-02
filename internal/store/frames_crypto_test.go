package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	storecrypto "github.com/hilather/go-jenkins-mcp/internal/store/crypto"
)

// testFrameKey is a deterministic non-production test vector (never a real secret).
func testFrameKey(t *testing.T, ver int) storecrypto.Key {
	t.Helper()
	out := make([]byte, storecrypto.KeySize)
	for i := range out {
		out[i] = byte(ver*17 + i)
	}
	return storecrypto.Key{Version: ver, Material: out}
}

func openEncryptedFrames(t *testing.T, target int, env *storecrypto.Envelope) (*store.Meta, *store.Frames, string, *store.FrameCrypto) {
	t.Helper()
	meta, fr, dir := openFrames(t, target)
	fc, err := store.NewFrameCrypto(env)
	if err != nil {
		t.Fatal(err)
	}
	fr.SetCrypto(fc)
	return meta, fr, dir, fc
}

func TestFrames_EncryptionRoundTrip(t *testing.T) {
	// ARC-009: encrypt on write, decrypt on read; disabled path is separate.
	k := testFrameKey(t, 1)
	env := &storecrypto.Envelope{Enabled: true, Write: k}
	meta, fr, dir, _ := openEncryptedFrames(t, 64, env)
	ctx := context.Background()
	genID := insertGen(t, meta)

	raw := []byte(strings.Repeat("hello-encrypted-line\n", 20))
	if _, err := fr.Append(ctx, genID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, genID); err != nil {
		t.Fatal(err)
	}

	chunks, err := meta.ListChunks(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) == 0 {
		t.Fatal("expected chunks")
	}
	for _, c := range chunks {
		if c.EncAlg != storecrypto.AlgAES256GCM || c.EncKeyVersion != 1 {
			t.Fatalf("enc meta: alg=%q ver=%d", c.EncAlg, c.EncKeyVersion)
		}
		abs, err := store.FrameAbsPath(dir, c.RelPath)
		if err != nil {
			t.Fatal(err)
		}
		onDisk, err := os.ReadFile(abs)
		if err != nil {
			t.Fatal(err)
		}
		if !storecrypto.IsEncrypted(onDisk) {
			t.Fatal("on-disk frame must be AEAD envelope")
		}
		// Plain zstd helper must refuse encrypted files without keys.
		if _, err := store.DecompressFrameFile(abs); err == nil {
			t.Fatal("expected DecompressFrameFile to fail on encrypted envelope")
		}
		// Ciphertext must not contain plaintext log.
		if bytes.Contains(onDisk, []byte("hello-encrypted-line")) {
			t.Fatal("plaintext leaked into on-disk envelope")
		}
	}

	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := reader.ReadRange(ctx, genID, 0, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Data, raw) {
		t.Fatalf("round-trip mismatch: got %q", rr.Data[:min(40, len(rr.Data))])
	}
}

func TestFrames_TamperFailsAuth(t *testing.T) {
	// Regression: bit-flip must fail AEAD before plaintext is returned.
	k := testFrameKey(t, 1)
	env := &storecrypto.Envelope{Enabled: true, Write: k}
	meta, fr, dir, _ := openEncryptedFrames(t, 0, env)
	ctx := context.Background()
	genID := insertGen(t, meta)
	payload := []byte("secret-log-line-must-not-leak\n")
	if _, err := fr.Append(ctx, genID, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, genID); err != nil {
		t.Fatal(err)
	}
	chunks, err := meta.ListChunks(ctx, genID)
	if err != nil || len(chunks) != 1 {
		t.Fatalf("chunks: %v %d", err, len(chunks))
	}
	c := chunks[0]
	abs, err := store.FrameAbsPath(dir, c.RelPath)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	// Flip last ciphertext byte and rewrite (also breaks FrameSHA256).
	onDisk[len(onDisk)-1] ^= 0xff
	if err := os.WriteFile(abs, onDisk, 0o600); err != nil {
		t.Fatal(err)
	}
	// Update meta checksum so we reach AEAD open (otherwise checksum fails first).
	// Directly rewrite frame_sha256 via SQL to exercise AEAD path.
	sum := sha256HexTest(onDisk)
	if _, err := meta.DB().Exec(`UPDATE chunks SET frame_sha256 = ? WHERE id = ?`, sum, c.ID); err != nil {
		t.Fatal(err)
	}
	// Reload chunk from DB.
	chunks, err = meta.ListChunks(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	c = chunks[0]

	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	_, err = reader.ReadRange(ctx, genID, 0, int64(len(payload)))
	if err == nil {
		t.Fatal("expected tamper to fail")
	}
	if apperr.CodeOf(err) != apperr.CodeCorruptCache && apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}
	// Canary: key material and plaintext must not appear in errors.
	keyHex := hex.EncodeToString(k.Material)
	if strings.Contains(err.Error(), keyHex) || strings.Contains(err.Error(), "secret-log-line") {
		t.Fatalf("leak in error: %v", err)
	}
}

func TestFrames_KeyRotationReadNAndNMinus1(t *testing.T) {
	// Rotation lite: write with N=2, read frames sealed with N=1 and N=2.
	k1 := testFrameKey(t, 1)
	k2 := testFrameKey(t, 2)
	meta, fr, _, _ := openEncryptedFrames(t, 0, &storecrypto.Envelope{Enabled: true, Write: k1})
	ctx := context.Background()
	genID := insertGen(t, meta)

	old := []byte("sealed-with-v1\n")
	if _, err := fr.Append(ctx, genID, old); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, genID); err != nil {
		t.Fatal(err)
	}
	// Rotate write key to v2; keep v1 for reads.
	fc2, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: k2, Prev: &k1})
	if err != nil {
		t.Fatal(err)
	}
	fr.SetCrypto(fc2)
	// New generation for fresh write under N.
	g2 := &store.LogGeneration{Profile: "corp", Job: "demo", Build: 2, Generation: 1, MoreData: true}
	if err := meta.InsertGeneration(ctx, g2); err != nil {
		t.Fatal(err)
	}
	newPayload := []byte("sealed-with-v2\n")
	if _, err := fr.Append(ctx, g2.ID, newPayload); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, g2.ID); err != nil {
		t.Fatal(err)
	}

	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := reader.ReadRange(ctx, genID, 0, int64(len(old)))
	if err != nil {
		t.Fatalf("read v1 frame: %v", err)
	}
	if !bytes.Equal(rr.Data, old) {
		t.Fatal("v1 content mismatch")
	}
	rr2, err := reader.ReadRange(ctx, g2.ID, 0, int64(len(newPayload)))
	if err != nil {
		t.Fatalf("read v2 frame: %v", err)
	}
	if !bytes.Equal(rr2.Data, newPayload) {
		t.Fatal("v2 content mismatch")
	}
	chunks, _ := meta.ListChunks(ctx, g2.ID)
	if len(chunks) != 1 || chunks[0].EncKeyVersion != 2 {
		t.Fatalf("expected write key version 2, got %+v", chunks)
	}
}

func TestFrames_EncryptionDisabledUnchanged(t *testing.T) {
	// Default path: no Crypto → plain independent zstd (STO-003 unchanged).
	meta, fr, dir := openFrames(t, 0)
	ctx := context.Background()
	genID := insertGen(t, meta)
	raw := []byte("plaintext-default\n")
	if _, err := fr.Append(ctx, genID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, genID); err != nil {
		t.Fatal(err)
	}
	chunks, err := meta.ListChunks(ctx, genID)
	if err != nil || len(chunks) != 1 {
		t.Fatalf("chunks: %v", err)
	}
	if chunks[0].EncAlg != "" || chunks[0].EncKeyVersion != 0 {
		t.Fatalf("plaintext must have empty enc fields: %+v", chunks[0])
	}
	abs, _ := store.FrameAbsPath(dir, chunks[0].RelPath)
	got, err := store.DecompressFrameFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("plaintext decompress mismatch")
	}
}

func TestFrames_MissingKeyFailClosed(t *testing.T) {
	k := testFrameKey(t, 1)
	meta, fr, _, _ := openEncryptedFrames(t, 0, &storecrypto.Envelope{Enabled: true, Write: k})
	ctx := context.Background()
	genID := insertGen(t, meta)
	raw := []byte("need-key\n")
	if _, err := fr.Append(ctx, genID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, genID); err != nil {
		t.Fatal(err)
	}
	// Reader without crypto must fail closed.
	plainReader, err := store.NewLogReader(meta, fr.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = plainReader.ReadRange(ctx, genID, 0, int64(len(raw)))
	if err == nil {
		t.Fatal("expected fail closed without key")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication && apperr.CodeOf(err) != apperr.CodeCorruptCache {
		t.Fatalf("code: %v", apperr.CodeOf(err))
	}
}

func TestOpenFrameCompressed_ForL2Copy(t *testing.T) {
	// Encrypted L1 → pure zstd for zero-recompression L2 copy (ARC-009 residual path).
	k := testFrameKey(t, 1)
	fc, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: k})
	if err != nil {
		t.Fatal(err)
	}
	meta, fr, dir, _ := openEncryptedFrames(t, 0, &storecrypto.Envelope{Enabled: true, Write: k})
	ctx := context.Background()
	genID := insertGen(t, meta)
	raw := []byte("l2-copy-payload\n")
	if _, err := fr.Append(ctx, genID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, genID); err != nil {
		t.Fatal(err)
	}
	chunks, _ := meta.ListChunks(ctx, genID)
	zstdBytes, err := store.OpenFrameCompressed(dir, chunks[0], fc)
	if err != nil {
		t.Fatal(err)
	}
	if storecrypto.IsEncrypted(zstdBytes) {
		t.Fatal("OpenFrameCompressed must return pure zstd")
	}
	got, err := store.DecompressZstdFrame(zstdBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("zstd content mismatch")
	}
}

func sha256HexTest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
