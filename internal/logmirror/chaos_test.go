package logmirror_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/archive"
	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
)

func TestChaos_TruncatedProgressiveMidFetch_ResumeOK(t *testing.T) {
	// Truncated progressive log body mid-fetch → partial frames durable, no panic, resume OK.
	var body strings.Builder
	for i := 0; i < 30; i++ {
		body.WriteString(strings.Repeat("P", 24))
		body.WriteByte('\n')
	}
	raw := []byte(body.String())

	// First pass: fetch until some durable frames, then inject disconnect.
	src := &logmirror.FakeSource{Log: raw, Running: true}
	m, key, fr, meta := openMachineWithFrames(t, src, 64)
	ctx := context.Background()
	m.FetchBytes = 40

	var last logmirror.State
	for i := 0; i < 8; i++ {
		st, err := m.Poll(ctx, key, false)
		if err != nil {
			t.Fatalf("Poll %d: %v", i, err)
		}
		last = st
		if st.DurableOffset > 0 {
			break
		}
	}
	if last.DurableOffset == 0 {
		// Force flush path: lower target and poll more.
		fr.TargetBytes = 32
		fr.MaxBytes = 128
		for i := 0; i < 10 && last.DurableOffset == 0; i++ {
			st, err := m.Poll(ctx, key, false)
			if err != nil {
				t.Fatal(err)
			}
			last = st
		}
	}
	if last.DurableOffset == 0 {
		t.Fatal("expected some durable frames before truncation fault")
	}
	durableBefore := last.DurableOffset
	genID := last.GenerationID
	chunksBefore, err := meta.ListChunks(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunksBefore) < 1 {
		t.Fatal("expected committed chunks")
	}

	// Inject network truncate / disconnect on next progressive fetch.
	src.FailOnce = errors.New("EOF: truncated progressive body mid-fetch")
	_, err = m.Poll(ctx, key, false)
	if err == nil {
		t.Fatal("expected mid-fetch fault")
	}
	// No panic; durable state unchanged.
	st, err := m.State(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if st.DurableOffset != durableBefore {
		t.Fatalf("durable moved after failed fetch: %d want %d", st.DurableOffset, durableBefore)
	}
	chunks, err := meta.ListChunks(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != len(chunksBefore) {
		t.Fatalf("chunk count changed after fault: %d vs %d", len(chunks), len(chunksBefore))
	}

	// Resume OK: complete build and seal.
	src.Running = false
	src.FailOnce = nil
	for i := 0; i < 40; i++ {
		st, err = m.Poll(ctx, key, true)
		if err != nil {
			t.Fatalf("resume Poll: %v", err)
		}
		if st.Sealed {
			break
		}
	}
	if !st.Sealed {
		t.Fatalf("expected sealed after resume: %s", st)
	}
	if st.DurableOffset != int64(len(raw)) {
		t.Fatalf("final durable %d want %d", st.DurableOffset, len(raw))
	}
	// Local reassembly matches full progressive body.
	rr, err := m.ReadRange(ctx, key, 0, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Data, raw) {
		t.Fatalf("reassembled log mismatch after resume (got %d want %d)", len(rr.Data), len(raw))
	}
}

func TestChaos_DiskFullOnPackWrite_L1Intact(t *testing.T) {
	// Disk-full simulation on pack write (failing PutPack) → L1 intact, no packed mark.
	meta, _, machine, dir := openPackEnv(t)
	ctx := context.Background()
	key := logmirror.LogKey{Profile: "corp", Job: "demo", Build: 99}
	body := []byte(strings.Repeat("pack-l1-line\n", 30))
	sealLog(t, machine, key, body)

	st, err := machine.State(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := meta.ListChunks(ctx, st.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) == 0 {
		t.Fatal("expected L1 chunks before pack")
	}

	dest := &failPutStore{err: apperr.New(apperr.CodeInternal, "no space left on device")}
	_, err = logmirror.PackGenerations(ctx, []logmirror.LogKey{key}, meta, dir, dest, logmirror.PackOptions{
		PackID: "pack-diskfull",
		Marker: meta,
	})
	if err == nil {
		t.Fatal("expected pack write failure")
	}

	// L1 still present and readable.
	chunks2, err := meta.ListChunks(ctx, st.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks2) != len(chunks) {
		t.Fatalf("L1 chunks changed: %d → %d", len(chunks), len(chunks2))
	}
	g, err := meta.GetGenerationByID(ctx, st.GenerationID)
	if err != nil || g == nil {
		t.Fatalf("generation missing: %v", err)
	}
	if g.PackedPackID != "" {
		t.Fatalf("must not mark packed after failed PutPack: %q", g.PackedPackID)
	}
	rr, err := machine.ReadRange(ctx, key, 0, int64(len(body)))
	if err != nil {
		t.Fatalf("L1 read after pack fail: %v", err)
	}
	if !bytes.Equal(rr.Data, body) {
		t.Fatal("L1 body mismatch after disk-full pack write")
	}
	// No durable pack published.
	if dest.putCalls != 1 {
		t.Fatalf("PutPack calls: %d", dest.putCalls)
	}
}

func TestChaos_CancelDuringPack_NoCorruptGeneration(t *testing.T) {
	// Cancelled context during pack → no corrupt generation; L1 intact; no partial trusted pack.
	meta, _, machine, dir := openPackEnv(t)
	ctx := context.Background()
	key := logmirror.LogKey{Profile: "corp", Job: "cancel-pack", Build: 3}
	body := []byte(strings.Repeat("cancel-line\n", 25))
	sealLog(t, machine, key, body)
	st, err := machine.State(ctx, key)
	if err != nil {
		t.Fatal(err)
	}

	cctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	dest := archive.NewMemoryStore()
	_, err = logmirror.PackGenerations(cctx, []logmirror.LogKey{key}, meta, dir, dest, logmirror.PackOptions{
		PackID: "pack-cancel",
		Marker: meta,
	})
	if err == nil {
		t.Fatal("expected cancelled pack")
	}
	if apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("want cancelled, got %s (%v)", apperr.CodeOf(err), err)
	}

	g, err := meta.GetGenerationByID(ctx, st.GenerationID)
	if err != nil || g == nil {
		t.Fatalf("generation: %v", err)
	}
	if !g.Sealed {
		t.Fatal("generation must remain sealed")
	}
	if g.PackedPackID != "" {
		t.Fatalf("must not mark packed on cancel: %q", g.PackedPackID)
	}
	// Memory store must not expose a trusted pack for the cancelled publish.
	if err := dest.Verify(ctx, archive.ArchiveRef{PackID: "pack-cancel"}); err == nil {
		// Verify may fail with not found — that is OK. Success would mean corrupt publish.
		t.Fatal("cancelled pack must not be published as verifiable")
	}
	rr, err := machine.ReadRange(ctx, key, 0, int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Data, body) {
		t.Fatal("L1 body changed after cancelled pack")
	}
}

func TestChaos_CancelDuringMirrorPoll_NoCorruptState(t *testing.T) {
	// Cancelled context during mirror poll → no panic; durable offset not advanced falsely.
	src := &logmirror.FakeSource{
		Log:     []byte(strings.Repeat("m\n", 50)),
		Running: true,
	}
	m, key, _, meta := openMachineWithFrames(t, src, 64)
	ctx := context.Background()
	// One successful poll first.
	st, err := m.Poll(ctx, key, false)
	if err != nil {
		t.Fatal(err)
	}
	off := st.CommittedOffset
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = m.Poll(cctx, key, false)
	if err == nil {
		// FakeSource checks ctx; machine may also check. Either error or no progress.
		t.Log("poll returned nil on cancelled ctx; checking no false advance")
	}
	st2, err := m.State(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	// SQLite offset must not exceed durable (crash-safe invariant).
	g, err := meta.GetLatestGeneration(ctx, key)
	if err != nil || g == nil {
		t.Fatal(err)
	}
	if g.JenkinsOffset > st2.DurableOffset {
		t.Fatalf("Regression: jenkins_offset %d past durable %d after cancel", g.JenkinsOffset, st2.DurableOffset)
	}
	_ = off
}

// failPutStore implements archive.ArchiveStore and always fails PutPack (disk-full).
type failPutStore struct {
	err      error
	putCalls int
}

func (f *failPutStore) PutPack(ctx context.Context, pack archive.PackDescriptor) error {
	f.putCalls++
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
	}
	if f.err != nil {
		return f.err
	}
	return apperr.New(apperr.CodeInternal, "put failed")
}

func (f *failPutStore) OpenEntry(ctx context.Context, ref archive.ArchiveRef) (io.ReadCloser, archive.EntryMetadata, error) {
	return nil, archive.EntryMetadata{}, apperr.New(apperr.CodeNotFound, "not found")
}

func (f *failPutStore) Verify(ctx context.Context, ref archive.ArchiveRef) error {
	return apperr.New(apperr.CodeNotFound, "not found")
}

func (f *failPutStore) DeletePack(ctx context.Context, ref archive.ArchiveRef) error {
	return nil
}

var _ archive.ArchiveStore = (*failPutStore)(nil)
