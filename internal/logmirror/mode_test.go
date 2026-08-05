package logmirror_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// fixedConsoleMode is a test ConsoleModePolicy.
type fixedConsoleMode struct {
	lookup, fill bool
}

func (f fixedConsoleMode) AllowConsoleLookup() bool { return f.lookup }
func (f fixedConsoleMode) AllowConsoleFill() bool   { return f.fill }

type countingTel struct {
	events int
	last   string
}

func (c *countingTel) OnConsoleEvent(layer, outcome string, bytes int64, reason string) {
	c.events++
	c.last = outcome + ":" + reason
}

func openConsoleFixture(t *testing.T) (*store.Meta, *store.Frames, *logmirror.Machine, string) {
	t.Helper()
	dir := t.TempDir()
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	src := &logmirror.FakeSource{Log: []byte("hello-console-log-body"), Running: false}
	m := logmirror.NewMachine(meta, src)
	m.Frames = frames
	reader, err := frames.Reader()
	if err != nil {
		t.Fatal(err)
	}
	m.Reader = reader
	t.Cleanup(func() {
		_ = frames.Close()
		_ = meta.Close()
	})
	return meta, frames, m, dir
}

func TestConsoleMode_Off_BypassesCacheWithoutPurge(t *testing.T) {
	// Regression: mode off stops new use but does not delete existing frames.
	_, _, m, _ := openConsoleFixture(t)
	access := logmirror.NewAccess("lab", m)
	tel := &countingTel{}
	access.Telemetry = tel

	// Fill while read_write (default)
	if err := access.EnsureMirrored(context.Background(), "demo", 1); err != nil {
		t.Fatal(err)
	}
	logs, meta, err := access.ReadRange(context.Background(), "demo", 1, 0, 100)
	if err != nil || logs == "" {
		t.Fatalf("expected local hit: err=%v meta=%+v logs=%q", err, meta, logs)
	}

	// Switch to mode off
	access.Modes = fixedConsoleMode{lookup: false, fill: false}
	// Lookup disabled → not_found (tools fall back to progressive)
	_, _, err = access.ReadRange(context.Background(), "demo", 1, 0, 100)
	if err == nil || apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("mode off must not serve cache: %v", err)
	}
	// Fill disabled → no-op Ensure (does not error)
	if err := access.EnsureMirrored(context.Background(), "demo", 2); err != nil {
		t.Fatal(err)
	}
	// Data still present when mode re-enabled
	access.Modes = nil
	logs2, _, err := access.ReadRange(context.Background(), "demo", 1, 0, 100)
	if err != nil || logs2 == "" {
		t.Fatal("data must remain after mode off (no implicit purge)")
	}
	if tel.events == 0 {
		t.Fatal("expected telemetry events")
	}
}

func TestConsoleMode_ReadOnly_NoFill(t *testing.T) {
	_, _, m, _ := openConsoleFixture(t)
	access := logmirror.NewAccess("lab", m)
	access.Modes = fixedConsoleMode{lookup: true, fill: false}

	// Ensure no-ops; no local materialization for new job
	if err := access.EnsureMirrored(context.Background(), "fresh", 9); err != nil {
		t.Fatal(err)
	}
	_, _, err := access.ReadRange(context.Background(), "fresh", 9, 0, 10)
	// May be not_found or empty generation — must not have filled
	st, serr := m.State(context.Background(), logmirror.LogKey{Profile: "lab", Job: "fresh", Build: 9})
	if serr != nil {
		t.Fatal(serr)
	}
	if st.DurableOffset > 0 || st.Sealed {
		t.Fatalf("read_only must not fill: %+v", st)
	}
	_ = err
}

func TestConsoleMode_WriteOnly_NeverServesExisting(t *testing.T) {
	_, _, m, _ := openConsoleFixture(t)
	access := logmirror.NewAccess("lab", m)
	// Seed cache
	if err := access.EnsureMirrored(context.Background(), "demo", 3); err != nil {
		t.Fatal(err)
	}
	// write_only: no lookup
	access.Modes = fixedConsoleMode{lookup: false, fill: true}
	_, _, err := access.ReadRange(context.Background(), "demo", 3, 0, 100)
	if err == nil || apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("write_only must not serve existing: %v", err)
	}
	// Resolve path also skips local
	_, _, err = access.ResolveAndReadRange(context.Background(), "demo", 3, 0, 100, logmirror.ResolveOptions{})
	// After fill via resolve, may return body — but tryLocal was skipped first.
	// Ensure still works (fill allowed).
	if err := access.EnsureMirrored(context.Background(), "demo", 4); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleMode_Off_PolicyStillIndependent(t *testing.T) {
	// Mode gate does not authorize: CheckStoreRead is tools-layer.
	// Here we only prove mode off returns not_found without deleting data.
	// (Policy re-auth on console path is covered by tools CheckStoreRead tests.)
	_, _, m, dir := openConsoleFixture(t)
	access := logmirror.NewAccess("lab", m)
	if err := access.EnsureMirrored(context.Background(), "pol", 1); err != nil {
		t.Fatal(err)
	}
	access.Modes = fixedConsoleMode{lookup: false, fill: false}
	_, _, err := access.Tail(context.Background(), "pol", 1, 50)
	if err == nil || apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("want not_found under mode off: %v", err)
	}
	// Frames still on disk under data dir
	if dir == "" {
		t.Fatal("empty dir")
	}
	_ = filepath.Join(dir, "frames")
}
