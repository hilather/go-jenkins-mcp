package store_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	storecrypto "github.com/hilather/go-jenkins-mcp/internal/store/crypto"
)

// FLC-053: cache encryption portability and key isolation proofs.
//
// Acceptance:
//  1. All nodes read identical decoded content with different local keys.
//  2. Compromise of one local cache key does not decrypt another node's frames.
//  3. Missing key fails local cache closed without leaking material.
//  4. Rotation does not alter wire manifest identity (pure zstd sha256 stable).

// openEncryptedMember opens a dual-dir style profile store with a single write key.
func openEncryptedMember(t *testing.T, name string, key storecrypto.Key) (*store.Meta, *store.Frames, *store.FrameCrypto, *store.PeerImportSink) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profiles", name)
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fr.Close() })
	fc, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: key})
	if err != nil {
		t.Fatal(err)
	}
	fr.SetCrypto(fc)
	return meta, fr, fc, store.NewPeerImportSink(meta, fr)
}

// openEncryptedMemberRotated opens a store with write key N and optional Prev (N-1).
func openEncryptedMemberRotated(t *testing.T, name string, write storecrypto.Key, prev *storecrypto.Key) (*store.Meta, *store.Frames, *store.FrameCrypto, *store.PeerImportSink) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profiles", name)
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fr.Close() })
	env := &storecrypto.Envelope{Enabled: true, Write: write}
	if prev != nil {
		env.Prev = prev
	}
	fc, err := store.NewFrameCrypto(env)
	if err != nil {
		t.Fatal(err)
	}
	fr.SetCrypto(fc)
	return meta, fr, fc, store.NewPeerImportSink(meta, fr)
}

func readOnDiskFrame(t *testing.T, dataDir string, c store.Chunk) []byte {
	t.Helper()
	abs, err := store.FrameAbsPath(dataDir, c.RelPath)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	return onDisk
}

func assertSecretFreeError(t *testing.T, err error, keys ...storecrypto.Key) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, k := range keys {
		if len(k.Material) == 0 {
			continue
		}
		// Raw bytes and common encodings must never appear.
		if strings.Contains(msg, string(k.Material)) {
			t.Fatalf("key material leaked as raw bytes in error: %v", err)
		}
		hexMat := hex.EncodeToString(k.Material)
		if strings.Contains(msg, hexMat) {
			t.Fatalf("key material leaked as hex in error: %v", err)
		}
	}
	// Stable residual: no JME1 envelope dump / ciphertext hex of on-disk frames.
	if strings.Contains(msg, "JME1") && strings.Contains(msg, hex.EncodeToString([]byte("JME1"))) {
		t.Fatalf("possible ciphertext dump in error: %v", err)
	}
}

// TestCryptoIsolation_DualKeyParity: AC1 — Member A key v1, Member B key v7;
// pure-zstd ReplicateSealed path; LogReader.ReadRange identical body; EncKeyVersion differs.
func TestCryptoIsolation_DualKeyParity(t *testing.T) {
	parts := [][]byte{
		[]byte("iso-dual-frame-0\n"),
		[]byte("iso-dual-frame-1\n"),
	}
	wm, frames, full := buildImportFixture(t, parts)

	keyA := testKey(t, 1)
	keyB := testKey(t, 7)
	metaA, frA, fcA, sinkA := openEncryptedMember(t, "member-a", keyA)
	metaB, frB, fcB, sinkB := openEncryptedMember(t, "member-b", keyB)

	resA, err := fleetcache.ReplicateSealed(context.Background(), sinkA, wm, frames)
	if err != nil || resA.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("A import %+v %v", resA, err)
	}
	// Wire path: A → pure zstd → B re-wrap under local key.
	wire := exportAllPure(t, metaA, frA, resA.GenerationID, fcA)
	resB, err := fleetcache.ReplicateSealed(context.Background(), sinkB, wm, wire)
	if err != nil || resB.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("B import %+v %v", resB, err)
	}

	chunksA, err := metaA.ListChunks(context.Background(), resA.GenerationID)
	if err != nil || len(chunksA) != 2 {
		t.Fatalf("A chunks %v n=%d", err, len(chunksA))
	}
	chunksB, err := metaB.ListChunks(context.Background(), resB.GenerationID)
	if err != nil || len(chunksB) != 2 {
		t.Fatalf("B chunks %v n=%d", err, len(chunksB))
	}
	for i := range chunksA {
		if chunksA[i].EncKeyVersion != 1 {
			t.Fatalf("A seq %d EncKeyVersion=%d want 1", i, chunksA[i].EncKeyVersion)
		}
		if chunksB[i].EncKeyVersion != 7 {
			t.Fatalf("B seq %d EncKeyVersion=%d want 7", i, chunksB[i].EncKeyVersion)
		}
		if chunksA[i].EncAlg != storecrypto.AlgAES256GCM || chunksB[i].EncAlg != storecrypto.AlgAES256GCM {
			t.Fatalf("enc alg A=%q B=%q", chunksA[i].EncAlg, chunksB[i].EncAlg)
		}
	}

	// LogReader parity on both members.
	readerA, err := frA.Reader()
	if err != nil {
		t.Fatal(err)
	}
	readerB, err := frB.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rrA, err := readerA.ReadRange(context.Background(), resA.GenerationID, 0, int64(len(full)))
	if err != nil {
		t.Fatal(err)
	}
	rrB, err := readerB.ReadRange(context.Background(), resB.GenerationID, 0, int64(len(full)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rrA.Data, full) || !bytes.Equal(rrB.Data, full) {
		t.Fatalf("decoded body mismatch A=%d B=%d want=%d", len(rrA.Data), len(rrB.Data), len(full))
	}
	if !bytes.Equal(rrA.Data, rrB.Data) {
		t.Fatal("members must decode identical content under different local keys")
	}

	// On-disk AEAD envelopes must differ (local re-wrap) while wire pure zstd matches fixture.
	for i := range chunksA {
		diskA := readOnDiskFrame(t, frA.DataDir(), chunksA[i])
		diskB := readOnDiskFrame(t, frB.DataDir(), chunksB[i])
		if !storecrypto.IsEncrypted(diskA) || !storecrypto.IsEncrypted(diskB) {
			t.Fatal("on-disk frames must be JME1 AEAD envelopes")
		}
		if bytes.Equal(diskA, diskB) {
			t.Fatalf("seq %d: different keys must produce different on-disk envelopes", i)
		}
		if !bytes.Equal(wire[i].PureZstd, frames[i].PureZstd) {
			t.Fatalf("wire pure zstd must match fixture seq %d", i)
		}
	}
	_ = fcB
}

// TestCryptoIsolation_CrossKeyFail: AC2 — reading A's ciphertext with B-only keyring fails closed.
func TestCryptoIsolation_CrossKeyFail(t *testing.T) {
	parts := [][]byte{[]byte("cross-key-isolation\n")}
	wm, frames, full := buildImportFixture(t, parts)

	keyA := testKey(t, 1)
	keyB := testKey(t, 7)
	metaA, frA, fcA, sinkA := openEncryptedMember(t, "member-a", keyA)
	resA, err := fleetcache.ReplicateSealed(context.Background(), sinkA, wm, frames)
	if err != nil || resA.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", resA, err)
	}
	chunksA, err := metaA.ListChunks(context.Background(), resA.GenerationID)
	if err != nil || len(chunksA) != 1 {
		t.Fatalf("%v n=%d", err, len(chunksA))
	}
	c := chunksA[0]
	onDisk := readOnDiskFrame(t, frA.DataDir(), c)
	if !storecrypto.IsEncrypted(onDisk) {
		t.Fatal("expected JME1 envelope")
	}

	// Path 1: OpenFrameCompressed with B-only crypto against A's sealed frame.
	fcB, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: keyB})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.OpenFrameCompressed(frA.DataDir(), c, fcB)
	if err == nil {
		t.Fatal("B key must not open A's on-disk frame")
	}
	code := apperr.CodeOf(err)
	if code != apperr.CodeCorruptCache && code != apperr.CodeAuthentication {
		t.Fatalf("fail-closed code want corrupt_cache|authentication got %v err=%v", code, err)
	}
	assertSecretFreeError(t, err, keyA, keyB)
	// Must not leak decoded log content.
	if strings.Contains(err.Error(), string(full)) || strings.Contains(err.Error(), "cross-key-isolation") {
		t.Fatalf("plaintext leaked in error: %v", err)
	}

	// Path 2: ExportPureZstd with wrong crypto fails closed (same residual).
	_, err = store.ExportPureZstd(frA.DataDir(), c, fcB)
	if err == nil {
		t.Fatal("ExportPureZstd with wrong key must fail")
	}
	assertSecretFreeError(t, err, keyA, keyB)

	// Path 3: LogReader on A after swapping crypto to B-only must fail.
	frA.SetCrypto(fcB)
	reader, err := frA.Reader()
	if err != nil {
		t.Fatal(err)
	}
	_, err = reader.ReadRange(context.Background(), resA.GenerationID, 0, int64(len(full)))
	if err == nil {
		t.Fatal("LogReader with B key on A ciphertext must fail closed")
	}
	assertSecretFreeError(t, err, keyA, keyB)

	// Sanity: correct key still works (re-attach A crypto).
	frA.SetCrypto(fcA)
	reader, err = frA.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := reader.ReadRange(context.Background(), resA.GenerationID, 0, int64(len(full)))
	if err != nil || !bytes.Equal(rr.Data, full) {
		t.Fatalf("A key should still open own frames: %v", err)
	}
}

// TestCryptoIsolation_MissingKey: AC3 — sealed with v9; empty/wrong keyring fails closed.
func TestCryptoIsolation_MissingKey(t *testing.T) {
	parts := [][]byte{[]byte("missing-key-v9-payload\n")}
	wm, frames, full := buildImportFixture(t, parts)

	keyV9 := testKey(t, 9)
	meta, fr, fc, sink := openEncryptedMember(t, "member-v9", keyV9)
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	chunks, err := meta.ListChunks(context.Background(), res.GenerationID)
	if err != nil || len(chunks) != 1 {
		t.Fatalf("%v n=%d", err, len(chunks))
	}
	c := chunks[0]
	if c.EncKeyVersion != 9 {
		t.Fatalf("EncKeyVersion=%d want 9", c.EncKeyVersion)
	}

	// Empty / nil crypto: fail closed.
	_, err = store.OpenFrameCompressed(fr.DataDir(), c, nil)
	if err == nil {
		t.Fatal("nil crypto must fail closed on encrypted frame")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication && apperr.CodeOf(err) != apperr.CodeCorruptCache {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}
	assertSecretFreeError(t, err, keyV9)

	// Wrong keyring (different version + material): fail closed.
	wrong := testKey(t, 3)
	fcWrong, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: wrong})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.OpenFrameCompressed(fr.DataDir(), c, fcWrong)
	if err == nil {
		t.Fatal("wrong keyring must fail closed")
	}
	assertSecretFreeError(t, err, keyV9, wrong)

	// LogReader without crypto (plain NewLogReader).
	plain, err := store.NewLogReader(meta, fr.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = plain.ReadRange(context.Background(), res.GenerationID, 0, int64(len(full)))
	if err == nil {
		t.Fatal("LogReader without key must fail closed")
	}
	assertSecretFreeError(t, err, keyV9)
	if strings.Contains(err.Error(), "missing-key-v9-payload") {
		t.Fatalf("plaintext in error: %v", err)
	}

	// Correct key still works.
	got, err := store.OpenFrameCompressed(fr.DataDir(), c, fc)
	if err != nil {
		t.Fatal(err)
	}
	if storecrypto.IsEncrypted(got) {
		t.Fatal("OpenFrameCompressed must return pure zstd")
	}
	dec, err := store.DecompressZstdFrame(got)
	if err != nil || !bytes.Equal(dec, full) {
		t.Fatalf("decoded %v len=%d", err, len(dec))
	}
}

// TestCryptoIsolation_WireIdentityStable: AC4 (wire) — ExportPureZstd equal across members;
// zstd_sha256 matches wire manifest; on-disk AEAD ≠ pure zstd.
func TestCryptoIsolation_WireIdentityStable(t *testing.T) {
	parts := [][]byte{
		[]byte("wire-id-frame-0\n"),
		[]byte("wire-id-frame-1\n"),
	}
	wm, frames, full := buildImportFixture(t, parts)

	metaA, frA, fcA, sinkA := openEncryptedMember(t, "wire-a", testKey(t, 1))
	metaB, frB, fcB, sinkB := openEncryptedMember(t, "wire-b", testKey(t, 7))

	resA, err := fleetcache.ReplicateSealed(context.Background(), sinkA, wm, frames)
	if err != nil {
		t.Fatal(err)
	}
	wireA := exportAllPure(t, metaA, frA, resA.GenerationID, fcA)
	resB, err := fleetcache.ReplicateSealed(context.Background(), sinkB, wm, wireA)
	if err != nil {
		t.Fatal(err)
	}
	wireB := exportAllPure(t, metaB, frB, resB.GenerationID, fcB)

	if len(wm.Frames) != len(wireA) || len(wireA) != len(wireB) {
		t.Fatalf("frame counts wm=%d A=%d B=%d", len(wm.Frames), len(wireA), len(wireB))
	}
	for i := range wm.Frames {
		// Members export identical pure zstd bytes (wire identity).
		if !bytes.Equal(wireA[i].PureZstd, wireB[i].PureZstd) {
			t.Fatalf("ExportPureZstd bytes differ across members seq %d", i)
		}
		if !bytes.Equal(wireA[i].PureZstd, frames[i].PureZstd) {
			t.Fatalf("export must match original pure zstd seq %d", i)
		}
		// Guard: pure zstd is not AEAD magic.
		if len(wireA[i].PureZstd) >= 4 && string(wireA[i].PureZstd[:4]) == storecrypto.Magic {
			t.Fatal("wire export must not be JME1 envelope")
		}
		sum := hexSHA(wireA[i].PureZstd)
		if sum != wm.Frames[i].ZstdSHA256 {
			t.Fatalf("zstd_sha256 mismatch seq %d: got %s want %s", i, sum, wm.Frames[i].ZstdSHA256)
		}
		// Chunk meta ZstdSHA256 (when present) must match wire.
		chunksA, _ := metaA.ListChunks(context.Background(), resA.GenerationID)
		chunksB, _ := metaB.ListChunks(context.Background(), resB.GenerationID)
		if chunksA[i].ZstdSHA256 != "" && !strings.EqualFold(chunksA[i].ZstdSHA256, sum) {
			t.Fatalf("A chunk zstd_sha256 %s want %s", chunksA[i].ZstdSHA256, sum)
		}
		if chunksB[i].ZstdSHA256 != "" && !strings.EqualFold(chunksB[i].ZstdSHA256, sum) {
			t.Fatalf("B chunk zstd_sha256 %s want %s", chunksB[i].ZstdSHA256, sum)
		}
		// On-disk AEAD envelopes differ from pure zstd and from each other.
		diskA := readOnDiskFrame(t, frA.DataDir(), chunksA[i])
		diskB := readOnDiskFrame(t, frB.DataDir(), chunksB[i])
		if !storecrypto.IsEncrypted(diskA) || !storecrypto.IsEncrypted(diskB) {
			t.Fatal("on-disk must be JME1")
		}
		if bytes.Equal(diskA, wireA[i].PureZstd) || bytes.Equal(diskB, wireB[i].PureZstd) {
			t.Fatal("on-disk AEAD must not equal pure zstd wire bytes")
		}
		if bytes.Equal(diskA, diskB) {
			t.Fatal("different local keys must yield different on-disk envelopes")
		}
		verA, err := storecrypto.KeyVersionOf(diskA)
		if err != nil || verA != 1 {
			t.Fatalf("A envelope key ver %d %v", verA, err)
		}
		verB, err := storecrypto.KeyVersionOf(diskB)
		if err != nil || verB != 7 {
			t.Fatalf("B envelope key ver %d %v", verB, err)
		}
	}

	// Decoded parity still holds (portability).
	readerB, _ := frB.Reader()
	rr, err := readerB.ReadRange(context.Background(), resB.GenerationID, 0, int64(len(full)))
	if err != nil || !bytes.Equal(rr.Data, full) {
		t.Fatalf("parity %v", err)
	}
}

// TestCryptoIsolation_Rotation: AC4 (rotation) — write v1; rotate write to v2 retain v1;
// still reads old frames; wire export pure zstd hash unchanged.
func TestCryptoIsolation_Rotation(t *testing.T) {
	parts := [][]byte{
		[]byte("rotate-frame-0\n"),
		[]byte("rotate-frame-1\n"),
	}
	wm, frames, full := buildImportFixture(t, parts)

	k1 := testKey(t, 1)
	k2 := testKey(t, 2)

	// Import under write key v1.
	meta, fr, fc1, sink := openEncryptedMember(t, "rotate", k1)
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	wireBefore := exportAllPure(t, meta, fr, res.GenerationID, fc1)
	var hashesBefore []string
	for _, f := range wireBefore {
		hashesBefore = append(hashesBefore, hexSHA(f.PureZstd))
	}

	// Rotate write to v2; retain v1 for read (Prev).
	fc2, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: k2, Prev: &k1})
	if err != nil {
		t.Fatal(err)
	}
	fr.SetCrypto(fc2)

	// Old frames still readable under rotated envelope.
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := reader.ReadRange(context.Background(), res.GenerationID, 0, int64(len(full)))
	if err != nil {
		t.Fatalf("read after rotation: %v", err)
	}
	if !bytes.Equal(rr.Data, full) {
		t.Fatal("decoded content must survive key rotation with Prev retained")
	}

	// Wire export still pure zstd with stable hash (manifest identity unchanged).
	wireAfter := exportAllPure(t, meta, fr, res.GenerationID, fc2)
	if len(wireAfter) != len(wireBefore) {
		t.Fatalf("frame count %d vs %d", len(wireAfter), len(wireBefore))
	}
	for i := range wireAfter {
		if !bytes.Equal(wireAfter[i].PureZstd, wireBefore[i].PureZstd) {
			t.Fatalf("rotation must not alter pure zstd bytes seq %d", i)
		}
		sum := hexSHA(wireAfter[i].PureZstd)
		if sum != hashesBefore[i] || sum != wm.Frames[i].ZstdSHA256 {
			t.Fatalf("wire zstd_sha256 unstable after rotation seq %d: %s vs %s vs manifest %s",
				i, sum, hashesBefore[i], wm.Frames[i].ZstdSHA256)
		}
		if len(wireAfter[i].PureZstd) >= 4 && string(wireAfter[i].PureZstd[:4]) == storecrypto.Magic {
			t.Fatal("wire must remain pure zstd after rotation")
		}
	}

	// New import on a second member with write=v2 only should still re-wrap from wire.
	// And a third store that rotates mid-life: import under v1, then write a second object under v2.
	meta2, fr2, _, sink2 := openEncryptedMemberRotated(t, "rotate-recv", k2, &k1)
	res2, err := fleetcache.ReplicateSealed(context.Background(), sink2, wm, wireAfter)
	if err != nil || res2.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("peer import after rotation wire %+v %v", res2, err)
	}
	// Receiver re-wraps under write key v2.
	chunks2, _ := meta2.ListChunks(context.Background(), res2.GenerationID)
	if len(chunks2) == 0 || chunks2[0].EncKeyVersion != 2 {
		t.Fatalf("receiver write key after re-wrap: %+v", chunks2)
	}
	reader2, err := fr2.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr2, err := reader2.ReadRange(context.Background(), res2.GenerationID, 0, int64(len(full)))
	if err != nil || !bytes.Equal(rr2.Data, full) {
		t.Fatalf("receiver parity %v", err)
	}

	// Drop Prev (v2-only) on original store: v1-sealed frames must fail closed.
	fcV2Only, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: k2})
	if err != nil {
		t.Fatal(err)
	}
	fr.SetCrypto(fcV2Only)
	reader, err = fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	_, err = reader.ReadRange(context.Background(), res.GenerationID, 0, int64(len(full)))
	if err == nil {
		t.Fatal("v2-only keyring must not open v1-sealed frames")
	}
	assertSecretFreeError(t, err, k1, k2)
}

// TestCryptoIsolation_WrongKeyVersionMaterial: wrong version number with unrelated material
// still fails closed (isolation is material-bound, not only version labels).
func TestCryptoIsolation_WrongKeyVersionMaterial(t *testing.T) {
	parts := [][]byte{[]byte("ver-label-trap\n")}
	wm, frames, full := buildImportFixture(t, parts)

	// Seal with material for version 5.
	real := testKey(t, 5)
	meta, fr, _, sink := openEncryptedMember(t, "ver-trap", real)
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil {
		t.Fatal(err)
	}
	chunks, _ := meta.ListChunks(context.Background(), res.GenerationID)
	c := chunks[0]

	// Same version label, different material.
	fakeMat := make([]byte, storecrypto.KeySize)
	for i := range fakeMat {
		fakeMat[i] = byte(0xAA ^ i)
	}
	fake := storecrypto.Key{Version: 5, Material: fakeMat}
	fcFake, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: fake})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.OpenFrameCompressed(fr.DataDir(), c, fcFake)
	if err == nil {
		t.Fatal("same version wrong material must fail")
	}
	assertSecretFreeError(t, err, real, fake)
	if strings.Contains(err.Error(), "ver-label-trap") {
		t.Fatalf("plaintext leak: %v", err)
	}

	// Real key recovers content.
	fcReal, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: real})
	if err != nil {
		t.Fatal(err)
	}
	z, err := store.OpenFrameCompressed(fr.DataDir(), c, fcReal)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := store.DecompressZstdFrame(z)
	if err != nil || !bytes.Equal(dec, full) {
		t.Fatalf("real key decode %v", err)
	}
}
