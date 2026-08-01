package logmirror_test

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/logmirror"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

func openMachineWithFrames(t *testing.T, src logmirror.ProgressiveSource, target int) (
	*logmirror.Machine, logmirror.LogKey, *store.Frames, *store.Meta,
) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	if target > 0 {
		fr.TargetBytes = target
		fr.MaxBytes = target * 4
	}
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	m := logmirror.NewMachine(meta, src)
	m.Frames = fr
	m.Reader = reader
	m.FetchBytes = 32
	key := logmirror.LogKey{Profile: "corp", Job: "demo", Build: 42}
	return m, key, fr, meta
}

func TestMachine_FramesProgressiveAndLocalRead(t *testing.T) {
	// End-to-end: Poll → independent frames → ReadRange/Tail without full decompress.
	var body strings.Builder
	for i := 0; i < 25; i++ {
		body.WriteString(strings.Repeat("L", 40))
		body.WriteByte('\n')
	}
	raw := []byte(body.String())
	src := &logmirror.FakeSource{Log: raw, Running: false}
	m, key, _, meta := openMachineWithFrames(t, src, 80)
	ctx := context.Background()

	var last logmirror.State
	for i := 0; i < 50; i++ {
		st, err := m.Poll(ctx, key, true)
		if err != nil {
			t.Fatalf("Poll: %v", err)
		}
		last = st
		if st.Sealed {
			break
		}
	}
	if !last.Sealed {
		t.Fatalf("expected sealed: %s", last)
	}
	if last.DurableOffset != int64(len(raw)) {
		t.Fatalf("durable: %d want %d (accepted=%d)", last.DurableOffset, len(raw), last.CommittedOffset)
	}

	chunks, err := meta.ListChunks(ctx, last.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected multi-frame, got %d", len(chunks))
	}

	// Byte range across frames.
	start := chunks[0].RawEnd - 3
	length := int64(20)
	rr, err := m.ReadRange(ctx, key, start, length)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Data, raw[start:start+length]) {
		t.Fatalf("ReadRange mismatch frames=%d", rr.FramesOpened)
	}
	if rr.Generation != last.Generation {
		t.Fatalf("generation evidence: %d", rr.Generation)
	}
	if len(rr.ContentSHA256) == 0 {
		t.Fatal("missing frame checksums in result")
	}

	// Tail must not open every early frame.
	tr, err := m.TailBytes(ctx, key, 15)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tr.Data, raw[len(raw)-15:]) {
		t.Fatalf("TailBytes mismatch")
	}
	if tr.FramesOpened >= len(chunks) {
		t.Fatalf("tail opened all frames: %d", tr.FramesOpened)
	}

	tl, err := m.TailLines(ctx, key, 3)
	if err != nil {
		t.Fatal(err)
	}
	if tl.FramesOpened >= len(chunks) {
		t.Fatalf("tail lines opened all frames: %d", tl.FramesOpened)
	}
	if !strings.Contains(string(tl.Data), "L") {
		t.Fatalf("tail lines empty? %q", tl.Data)
	}
}

func TestMachine_FramesCrashResumeDurableOnly(t *testing.T) {
	// After crash, resume from durable frame end (not uncommitted buffer).
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Large target so first small poll stays buffered (not durable).
	fr.TargetBytes = 1 << 20
	fr.MaxBytes = 2 << 20
	raw := []byte(strings.Repeat("abcdefg\n", 20)) // ~160 bytes
	src := &logmirror.FakeSource{Log: raw, Running: true}
	m := logmirror.NewMachine(meta, src)
	m.Frames = fr
	m.FetchBytes = 40
	key := logmirror.LogKey{Profile: "corp", Job: "j", Build: 1}
	ctx := context.Background()

	st, err := m.Poll(ctx, key, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.CommittedOffset != 40 {
		t.Fatalf("accepted after poll: %d", st.CommittedOffset)
	}
	if st.DurableOffset != 0 {
		t.Fatalf("expected no durable frames yet, durable=%d", st.DurableOffset)
	}
	// SQLite must not claim past durable.
	g, err := meta.GetLatestGeneration(ctx, key)
	if err != nil || g == nil {
		t.Fatal(err)
	}
	if g.JenkinsOffset != 0 {
		t.Fatalf("Regression: jenkins_offset past durable data: %d", g.JenkinsOffset)
	}
	_ = meta.Close()
	_ = fr.Close()

	// Restart: lost buffer; resume from durable 0 and re-fetch.
	meta2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta2.Close() })
	fr2, err := store.NewFrames(meta2, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fr2.Close() })
	if _, err := fr2.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	src.FetchCount = 0
	m2 := logmirror.NewMachine(meta2, src)
	m2.Frames = fr2
	m2.FetchBytes = 40
	st2, err := m2.State(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if st2.CommittedOffset != 0 {
		t.Fatalf("after restart expected offset 0, got %d", st2.CommittedOffset)
	}
	// Complete with small target so frames commit.
	fr2.TargetBytes = 50
	fr2.MaxBytes = 200
	src.Running = false
	for i := 0; i < 20; i++ {
		st2, err = m2.Poll(ctx, key, true)
		if err != nil {
			t.Fatal(err)
		}
		if st2.Sealed {
			break
		}
	}
	if st2.DurableOffset != int64(len(raw)) {
		t.Fatalf("final durable: %d want %d", st2.DurableOffset, len(raw))
	}
}
