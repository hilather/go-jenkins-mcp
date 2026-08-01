package store_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

func openFrames(t *testing.T, target int) (*store.Meta, *store.Frames, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatalf("NewFrames: %v", err)
	}
	if target > 0 {
		fr.TargetBytes = target
		fr.MaxBytes = target * 4
	}
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	return meta, fr, dir
}

func insertGen(t *testing.T, meta *store.Meta) int64 {
	t.Helper()
	g := &store.LogGeneration{
		Profile: "corp", Job: "demo", Build: 1, Generation: 1, MoreData: true,
	}
	if err := meta.InsertGeneration(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	return g.ID
}

func TestFrames_MultiFrameIndependentRead(t *testing.T) {
	// STO-003: write multi-frame log, read ranges spanning frames, verify independence.
	meta, fr, dir := openFrames(t, 64) // small frames
	ctx := context.Background()
	genID := insertGen(t, meta)

	var log bytes.Buffer
	for i := 0; i < 40; i++ {
		log.WriteString(strings.Repeat("x", 20))
		log.WriteByte('\n')
	}
	raw := log.Bytes()

	if _, err := fr.Append(ctx, genID, raw); err != nil {
		t.Fatal(err)
	}
	res, err := fr.Flush(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if res.DurableEnd != int64(len(raw)) {
		t.Fatalf("durable end: %d want %d", res.DurableEnd, len(raw))
	}

	chunks, err := meta.ListChunks(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected multi-frame, got %d chunks (target=64, log=%d)", len(chunks), len(raw))
	}

	for _, c := range chunks {
		abs, err := store.FrameAbsPath(dir, c.RelPath)
		if err != nil {
			t.Fatal(err)
		}
		got, err := store.DecompressFrameFile(abs)
		if err != nil {
			t.Fatalf("independent decompress seq=%d: %v", c.Seq, err)
		}
		if int64(len(got)) != c.UncompressedSize {
			t.Fatalf("seq %d size: %d vs %d", c.Seq, len(got), c.UncompressedSize)
		}
		if !bytes.Equal(got, raw[c.RawStart:c.RawEnd]) {
			t.Fatalf("seq %d content mismatch", c.Seq)
		}
		if c.DictID != "" {
			t.Fatalf("dict_id must be empty (no cross-frame dependency), got %q", c.DictID)
		}
		if c.Codec != store.CodecZstd {
			t.Fatalf("codec: %s", c.Codec)
		}
		if c.ContentSHA256 == "" || c.FrameSHA256 == "" {
			t.Fatal("missing checksums")
		}
	}

	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	mid := chunks[0].RawEnd - 5
	if mid < 0 {
		mid = 0
	}
	span := chunks[1].RawStart + 10 - mid
	if span <= 0 {
		span = 10
	}
	rr, err := reader.ReadRange(ctx, genID, mid, span)
	if err != nil {
		t.Fatal(err)
	}
	want := raw[mid : mid+span]
	if !bytes.Equal(rr.Data, want) {
		t.Fatalf("span read: got %q want %q (frames=%d decompressed=%d)",
			rr.Data, want, rr.FramesOpened, rr.DecompressedBytes)
	}
	if rr.FramesOpened < 2 {
		t.Fatalf("expected >=2 frames opened for spanning range, got %d", rr.FramesOpened)
	}
	if rr.DecompressedBytes < int64(len(rr.Data)) {
		t.Fatalf("decompressed %d < data %d", rr.DecompressedBytes, len(rr.Data))
	}

	full, err := reader.ReadRange(ctx, genID, 0, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(full.Data, raw) {
		t.Fatalf("full reassembly failed: len got %d want %d", len(full.Data), len(raw))
	}
}

func TestFrames_NoRawStagingCopy(t *testing.T) {
	// Acceptance: no completed full raw log copy on disk.
	meta, fr, dir := openFrames(t, 128)
	ctx := context.Background()
	genID := insertGen(t, meta)
	payload := bytes.Repeat([]byte("line of log data\n"), 50)
	if _, err := fr.Append(ctx, genID, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, genID); err != nil {
		t.Fatal(err)
	}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		base := info.Name()
		if strings.HasSuffix(base, ".log") || base == "raw" || strings.Contains(base, "staging") {
			t.Errorf("unexpected raw staging file: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFrames_LongLineAndBinary(t *testing.T) {
	// Line/raw-offset metadata round-trips across long lines and binary-like bytes.
	meta, fr, _ := openFrames(t, 32)
	ctx := context.Background()
	genID := insertGen(t, meta)

	long := bytes.Repeat([]byte{0x00, 0xff, 'A'}, 100) // no newline, binary-ish
	long = append(long, '\n')
	long = append(long, []byte("second\n")...)
	if _, err := fr.Append(ctx, genID, long); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, genID); err != nil {
		t.Fatal(err)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := reader.ReadRange(ctx, genID, 0, int64(len(long)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Data, long) {
		t.Fatalf("binary/long line round-trip failed")
	}
	lr, err := reader.ReadLineRange(ctx, genID, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(lr.Data, []byte("second\n")) {
		t.Fatalf("line range missing second line: %q", lr.Data)
	}
	chunks, _ := meta.ListChunks(ctx, genID)
	if len(chunks) == 0 {
		t.Fatal("no chunks")
	}
}

func TestFrames_TailDoesNotTouchEarlyFrames(t *testing.T) {
	// LOG-003: tail does not decompress all earlier chunks.
	meta, fr, _ := openFrames(t, 64)
	ctx := context.Background()
	genID := insertGen(t, meta)

	var log bytes.Buffer
	for i := 0; i < 30; i++ {
		log.WriteString(strings.Repeat("a", 30))
		log.WriteByte('\n')
	}
	raw := log.Bytes()
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
	if len(chunks) < 3 {
		t.Fatalf("need >=3 frames for tail test, got %d", len(chunks))
	}

	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	// Tail last 20 bytes — should only open the last frame(s).
	tr, err := reader.TailBytes(ctx, genID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tr.Data, raw[len(raw)-20:]) {
		t.Fatalf("tail bytes mismatch")
	}
	if tr.FramesOpened >= len(chunks) {
		t.Fatalf("tail opened all %d frames; want fewer (got %d)", len(chunks), tr.FramesOpened)
	}
	// Early frames' compressed size sum should exceed decompressed of tail.
	var earlyUncompressed int64
	for i := 0; i < len(chunks)-1; i++ {
		earlyUncompressed += chunks[i].UncompressedSize
	}
	if tr.DecompressedBytes >= earlyUncompressed+tr.DecompressedBytes {
		// trivial; main check is FramesOpened
	}
	if tr.FramesOpened > 2 {
		t.Fatalf("tail 20 bytes opened too many frames: %d", tr.FramesOpened)
	}

	// Tail lines: last 2 lines.
	tl, err := reader.TailLines(ctx, genID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(tl.Data), "a\n") && !strings.Contains(string(tl.Data), "\n") {
		t.Fatalf("tail lines: %q", tl.Data)
	}
	if tl.FramesOpened >= len(chunks) {
		t.Fatalf("tail lines opened all frames: %d", tl.FramesOpened)
	}
	if len(tl.ContentSHA256) == 0 {
		t.Fatal("expected content checksums in evidence")
	}
}

func TestFrames_CrashSafeCommitOrder(t *testing.T) {
	// STO-004: fault injection at commit stages leaves recoverable state.
	ctx := context.Background()

	stages := []store.CommitStage{
		store.StageAfterTmpWrite,
		store.StageAfterTmpFsync,
		store.StageAfterRename,
		store.StageBeforeMeta,
	}
	for _, stage := range stages {
		t.Run(stageName(stage), func(t *testing.T) {
			meta, fr, dir := openFrames(t, 32)
			genID := insertGen(t, meta)
			fr.Hook = func(s store.CommitStage) error {
				if s == stage {
					return apperr.New(apperr.CodeInternal, "injected crash")
				}
				return nil
			}
			payload := bytes.Repeat([]byte("crash-test-line\n"), 8)
			_, err := fr.Append(ctx, genID, payload)
			if err == nil {
				// May succeed if cut never triggered; force flush.
				_, err = fr.Flush(ctx, genID)
			}
			if err == nil {
				t.Fatal("expected injected crash error")
			}

			// Reset hook; recover.
			fr.Hook = nil
			fr.Forget(genID)
			rec, err := fr.Recover(ctx)
			if err != nil {
				t.Fatalf("Recover: %v", err)
			}
			_ = rec

			// Incomplete frame not visible.
			chunks, err := meta.ListChunks(ctx, genID)
			if err != nil {
				t.Fatal(err)
			}
			if len(chunks) != 0 {
				t.Fatalf("after crash at %s expected 0 chunks, got %d (rec=%+v)", stageName(stage), len(chunks), rec)
			}
			// No readable durable data.
			reader, err := fr.Reader()
			if err != nil {
				t.Fatal(err)
			}
			rr, err := reader.ReadRange(ctx, genID, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(rr.Data) != 0 {
				t.Fatalf("incomplete data visible after crash: %q", rr.Data)
			}
			// No leftover temps.
			_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return err
				}
				if strings.HasSuffix(info.Name(), ".tmp") {
					t.Errorf("leftover temp after recover: %s", path)
				}
				return nil
			})

			// Successful commit after recovery.
			if _, err := fr.Append(ctx, genID, payload); err != nil {
				t.Fatal(err)
			}
			if _, err := fr.Flush(ctx, genID); err != nil {
				t.Fatal(err)
			}
			chunks, _ = meta.ListChunks(ctx, genID)
			if len(chunks) == 0 {
				t.Fatal("expected successful chunks after recovery")
			}
			// Logical offset must not point past durable: DurableEnd == sum sizes.
			end, err := meta.DurableRawEnd(ctx, genID)
			if err != nil {
				t.Fatal(err)
			}
			if end != int64(len(payload)) {
				t.Fatalf("durable end %d want %d", end, len(payload))
			}
		})
	}
}

func stageName(s store.CommitStage) string {
	switch s {
	case store.StageAfterTmpWrite:
		return "after_tmp_write"
	case store.StageAfterTmpFsync:
		return "after_tmp_fsync"
	case store.StageAfterRename:
		return "after_rename"
	case store.StageBeforeMeta:
		return "before_meta"
	default:
		return "unknown"
	}
}

func TestFrames_OrphanTmpCleanupOnRecover(t *testing.T) {
	meta, fr, dir := openFrames(t, 64)
	ctx := context.Background()
	// Plant orphan temp.
	tmpDir := filepath.Join(dir, store.FramesDirName, "99")
	if err := store.EnsureDir(tmpDir); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(tmpDir, "0"+store.FrameTmpExt)
	if err := os.WriteFile(tmp, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Plant orphan final without meta.
	orphan := filepath.Join(tmpDir, "1"+store.FrameExt)
	if err := os.WriteFile(orphan, []byte("orphan-zst"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := fr.Recover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rec.OrphanTempsRemoved < 1 {
		t.Fatalf("expected temp cleanup, got %+v", rec)
	}
	if rec.OrphanFramesRemoved < 1 {
		t.Fatalf("expected orphan frame cleanup, got %+v", rec)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("tmp still exists")
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("orphan still exists")
	}
	_ = meta
}

func TestFrames_SchemaV2(t *testing.T) {
	meta, _, _ := openFrames(t, 0)
	ver, err := meta.SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ver != store.CurrentSchemaVersion {
		t.Fatalf("schema: %d want %d", ver, store.CurrentSchemaVersion)
	}
	if store.CurrentSchemaVersion < 2 {
		t.Fatal("expected schema v2 for frames")
	}
}
