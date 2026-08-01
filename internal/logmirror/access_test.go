package logmirror_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/logmirror"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

func openAccess(t *testing.T, src logmirror.ProgressiveSource) (*logmirror.Access, *logmirror.Machine) {
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
	fr.TargetBytes = 48
	fr.MaxBytes = 192
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
	m.FetchBytes = 24
	status := logmirror.NewFakeBuildStatus()
	status.Set("demo", 7, true)
	a := logmirror.NewAccess("corp", m)
	a.Status = status
	return a, m
}

func TestAccess_EnsureMirroredAndReadRange(t *testing.T) {
	raw := []byte(strings.Repeat("line-content-\n", 20))
	src := &logmirror.FakeSource{Log: raw, Running: false}
	a, _ := openAccess(t, src)
	ctx := context.Background()

	if err := a.EnsureMirrored(ctx, "demo", 7); err != nil {
		t.Fatalf("EnsureMirrored: %v", err)
	}
	logs, meta, err := a.ReadRange(ctx, "demo", 7, 0, 40)
	if err != nil {
		t.Fatal(err)
	}
	if logs != string(raw[:40]) {
		t.Fatalf("logs=%q want prefix", logs)
	}
	if meta.Offset != 0 || meta.Length != 40 {
		t.Fatalf("meta: %+v", meta)
	}
	if !meta.Sealed {
		t.Fatalf("expected sealed meta: %+v", meta)
	}
	if meta.TotalSize != len(raw) {
		t.Fatalf("totalSize=%d want %d", meta.TotalSize, len(raw))
	}

	// Tail
	tail, tmeta, err := a.Tail(ctx, "demo", 7, 15)
	if err != nil {
		t.Fatal(err)
	}
	wantTail := string(raw[len(raw)-15:])
	if tail != wantTail {
		t.Fatalf("tail=%q want %q", tail, wantTail)
	}
	if tmeta.Length != 15 {
		t.Fatalf("tail meta: %+v", tmeta)
	}
}

func TestAccess_EnsureMirrored_IdempotentWhenSealed(t *testing.T) {
	src := &logmirror.FakeSource{Log: []byte("already-here"), Running: false}
	a, _ := openAccess(t, src)
	ctx := context.Background()
	if err := a.EnsureMirrored(ctx, "demo", 7); err != nil {
		t.Fatal(err)
	}
	fetches := src.FetchCount
	if err := a.EnsureMirrored(ctx, "demo", 7); err != nil {
		t.Fatal(err)
	}
	if src.FetchCount != fetches {
		t.Fatalf("sealed re-ensure should not re-fetch: before=%d after=%d", fetches, src.FetchCount)
	}
}

func TestAccess_RunningBuildPartialMirror(t *testing.T) {
	// Long enough body so frame flush produces durable bytes while still running.
	src := &logmirror.FakeSource{Log: []byte(strings.Repeat("partial-log-data\n", 8)), Running: true}
	a, m := openAccess(t, src)
	status := logmirror.NewFakeBuildStatus()
	status.DefaultComplete = false
	status.Set("demo", 7, false)
	a.Status = status
	ctx := context.Background()
	if err := a.EnsureMirrored(ctx, "demo", 7); err != nil {
		t.Fatalf("partial mirror: %v", err)
	}
	st, err := m.State(ctx, logmirror.LogKey{Profile: "corp", Job: "demo", Build: 7})
	if err != nil {
		t.Fatal(err)
	}
	if st.Sealed {
		t.Fatal("running build should not seal")
	}
	if st.DurableOffset == 0 && st.CommittedOffset == 0 {
		t.Fatalf("expected some mirrored progress: %s", st)
	}
	// After flushPartial, durable should be readable for local tools.
	if st.DurableOffset == 0 {
		t.Fatalf("expected durable frames after partial mirror flush: %s", st)
	}
}
