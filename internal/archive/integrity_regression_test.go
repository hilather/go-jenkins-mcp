package archive

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression: VerifyContentFrames skipped frames with empty FrameSHA256 and
// skipped pack_sha256 when empty — an anomalous (corrupt or tampered) pack
// with zeroed hash fields passed verification, since every writer in this
// repo always sets them. Empty hash fields now fail closed.
func regressionPack(t *testing.T) ([]byte, *SeekTable) {
	t.Helper()
	data, st, err := WritePack([]MemberInput{
		{Name: "a.log", Body: []byte("alpha body\n"), Mode: 0o600},
		{Name: "b.log", Body: []byte("beta body\n"), Mode: 0o600},
	}, WriteOptions{PackID: "pack-reg", TargetFrameBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	return data, st
}

func TestVerifyContentFrames_EmptyHashFailsClosed(t *testing.T) {
	t.Parallel()
	data, st := regressionPack(t)
	p, err := OpenPack(data)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Zero one frame hash: verification must fail closed (not skip).
	st2 := *st
	st2.Frames = append([]SeekFrame(nil), st.Frames...)
	st2.Frames[0].FrameSHA256 = ""
	p2 := &Pack{data: data, table: &st2}
	if err := p2.VerifyContentFrames(); err == nil {
		t.Fatal("empty frame_sha256 must fail closed")
	}

	// Zero the pack hash: must fail closed too.
	st3 := *st
	st3.Frames = append([]SeekFrame(nil), st.Frames...)
	st3.PackSHA256 = ""
	p3 := &Pack{data: data, table: &st3}
	if err := p3.VerifyContentFrames(); err == nil {
		t.Fatal("empty pack_sha256 must fail closed")
	}

	// Control: the untouched table verifies.
	if err := p.VerifyContentFrames(); err != nil {
		t.Fatal(err)
	}
}

// Regression: IsQuarantined matched strings.HasPrefix(name, packID+"-"), so
// pack "a" reported quarantined when only pack "a-b" had been quarantined
// ("a-b-<ts>.tar.zst" has prefix "a-"). The match now requires the exact
// <packID>-<timestamp> name shape.
func TestIsQuarantined_PrefixCollision(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	// Quarantine pack "a-b".
	packDir := filepath.Join(root, "packs")
	if err := os.MkdirAll(packDir, 0o700); err != nil {
		t.Fatal(err)
	}
	packPath := filepath.Join(packDir, "a-b.tar.zst")
	if err := os.WriteFile(packPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := QuarantinePack(root, "a-b", packPath); err != nil {
		t.Fatal(err)
	}
	if !IsQuarantined(root, "a-b") {
		t.Fatal("a-b must be quarantined")
	}
	if IsQuarantined(root, "a") {
		t.Fatal("pack a must NOT report quarantined when only a-b was quarantined")
	}
}

// Regression: two quarantines of the same packID within one second produced
// the same destination name (second-granularity timestamp) and os.Rename
// silently replaced the first quarantined file — destroying quarantine
// evidence. Colliding names now get a disambiguating suffix.
func TestQuarantinePack_SameSecondNoOverwrite(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	packDir := filepath.Join(root, "packs")
	if err := os.MkdirAll(packDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i, content := range []string{"first", "second"} {
		packPath := filepath.Join(root, "packs", "p.tar.zst")
		if err := os.WriteFile(packPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := QuarantinePack(root, "p", packPath); err != nil {
			t.Fatal(err)
		}
		_ = i
	}
	entries, err := os.ReadDir(filepath.Join(root, QuarantineDirName))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "p-") && strings.HasSuffix(e.Name(), ".tar.zst") {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("both quarantined copies must survive; found %d", count)
	}
}

// Regression: scanFrames exempted the FIRST skippable frame from the
// MaxSeekTableBytes bound (the `&& len(out) > 0` carve-out) — inverted
// relative to its own comment ("Only the seek table should be large
// skippable; still bound"; the seek table is the LAST frame). An oversized
// leading skippable frame is now rejected like any other.
func TestScanFrames_OversizedLeadingSkippableRejected(t *testing.T) {
	t.Parallel()
	// Hand-build an oversized skippable frame (writeSkippableFrame refuses to
	// emit one): magic + uint32 size + payload.
	psz := MaxSeekTableBytes + 8
	big := make([]byte, 0, 8+psz)
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], skippableMagicMin)
	big = append(big, hdr[:]...)
	binary.LittleEndian.PutUint32(hdr[:], uint32(psz))
	big = append(big, hdr[:]...)
	big = append(big, make([]byte, psz)...)

	// Giant skippable frame FIRST, then a valid content frame from a real pack.
	data, _ := regressionPack(t)
	buf := append(big, data...)
	if _, err := scanFrames(buf); err == nil {
		t.Fatal("oversized leading skippable frame must be rejected")
	}
	// Control: the same oversized frame in seek-table position (last) is also
	// rejected (bound applies everywhere), and a normal pack scans fine.
	if _, err := scanFrames(append(append([]byte{}, data...), big...)); err == nil {
		t.Fatal("oversized trailing skippable frame must be rejected")
	}
	if _, err := scanFrames(data); err != nil {
		t.Fatalf("normal pack must scan: %v", err)
	}
}

// Regression: PutPack declared a mutex it never locked and published via a
// shared <pack>.tmp path — concurrent PutPack with the same packID could
// interleave writes and publish torn content. PutPack is now serialized and
// uses an unpredictable temp name.
func TestFSStore_PutPackConcurrentSameID(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	s, err := NewFSStore(root)
	if err != nil {
		t.Fatal(err)
	}
	members := []MemberInput{{Name: "a.log", Body: []byte("body"), Mode: 0o600}}
	data, _, err := WritePack(members, WriteOptions{PackID: "pack-x", TargetFrameBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const n = 16
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			errs <- s.PutPack(ctx, PackDescriptor{PackID: "pack-x", Data: data})
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent PutPack: %v", err)
		}
	}
	// Final pack opens and verifies.
	p, err := OpenPack(data)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.VerifyContentFrames(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "pack-x.tar.zst")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "pack-x.tar.zst.tmp")); !os.IsNotExist(err) {
		t.Fatal("shared temp path must not remain (unpredictable temp names now)")
	}
}
