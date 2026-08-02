package tools_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

// Regression (FLC-032): MirrorLogAccess.ReadRange must not drop partial durable
// frames when EnsureMirrored returns CodeQuota (Peer nil / mode-off path).
// Pre-FLC readLogsViaAccess ignored non-cancel Ensure errors and still served
// committed frames; ResolveAnd* returns (logs, meta, ensureErr) which must not
// be discarded as a hard failure.
func TestMirrorLogAccess_PartialEnsureQuotaStillServesRange(t *testing.T) {
	// Body large enough that a tiny MaxBytes budget leaves durable frames mid-mirror.
	raw := []byte(strings.Repeat("partial-mirror-line-XXXXXXXX\n", 80)) // ~2.4 KiB
	src := &logmirror.FakeSource{Log: raw, Running: true}               // stay unsealed / progressive
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
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
	m.FetchBytes = 64 // small progressive fetches

	access := logmirror.NewAccess("corp", m)
	// Tight per-log budget so EnsureMirrored (inside ResolveAnd*) hits CodeQuota
	// after writing durable frames — first call has no prior local hit.
	access.MaxBytes = 96
	access.MaxPolls = 8
	status := logmirror.NewFakeBuildStatus()
	status.DefaultComplete = false
	status.Set("demo", 7, false)
	access.Status = status
	// Peer nil — mode-off / origin-only path under test.
	if access.Peer != nil {
		t.Fatal("Peer must be nil for this regression")
	}

	// Prove Ensure alone would surface quota with partial frames (fixture sanity).
	ensureErr := access.EnsureMirrored(context.Background(), "demo", 7)
	if ensureErr == nil {
		t.Fatal("expected CodeQuota (or budget) from tight MaxBytes; fixture may need tightening")
	}
	if apperr.CodeOf(ensureErr) != apperr.CodeQuota {
		t.Logf("ensure err code=%s msg=%v", apperr.CodeOf(ensureErr), ensureErr)
	}
	st, err := m.State(context.Background(), logmirror.LogKey{Profile: "corp", Job: "demo", Build: 7})
	if err != nil {
		t.Fatal(err)
	}
	if st.DurableOffset <= 0 {
		t.Fatalf("expected durable partial frames; durable=%d ensure=%v", st.DurableOffset, ensureErr)
	}

	// Second generation: empty local, tight budget — ResolveAnd must return
	// (partial, ensureErr) and MirrorLogAccess must keep the body (not drop on err).
	// Use a new job so tryLocal misses and Ensure residual path is exercised.
	src.SetLog(raw) // same body for job demo-2
	accessB := logmirror.NewAccess("corp", m)
	accessB.MaxBytes = 96
	accessB.MaxPolls = 8
	status.Set("demo-2", 7, false)
	accessB.Status = status
	mla := tools.NewMirrorLogAccess(accessB)

	// Drive the real ResolveAnd path: no pre-seed for demo-2.
	const wantLen = 20
	logs, lm, err := mla.ReadRange(context.Background(), "demo-2", 7, 0, wantLen)
	if err != nil {
		t.Fatalf("Regression: MirrorLogAccess.ReadRange must not hard-fail on Ensure residual with durable frames: %v", err)
	}
	if len(logs) == 0 {
		t.Fatal("Regression: expected non-empty partial logs from durable frames")
	}
	if int64(len(logs)) > wantLen {
		t.Fatalf("length %d > requested %d", len(logs), wantLen)
	}
	if !strings.HasPrefix(string(raw), logs) {
		t.Fatalf("partial body mismatch: got %q", logs)
	}
	if lm.TotalSize <= 0 && lm.Length <= 0 {
		t.Fatalf("meta should reflect partial mirror: %+v", lm)
	}

	// Also cover preferPartialMirror when local already durable but Ensure re-hits quota
	// (Resolve local-hits first with nil err — still must serve).
	mla2 := tools.NewMirrorLogAccess(access) // demo already partial on machine
	logs2, _, err2 := mla2.ReadRange(context.Background(), "demo", 7, 0, wantLen)
	if err2 != nil || len(logs2) == 0 {
		t.Fatalf("local partial hit must serve: err=%v len=%d", err2, len(logs2))
	}
}

// Regression: Tail also prefers partial durable frames under Ensure residual.
func TestMirrorLogAccess_PartialEnsureQuotaStillServesTail(t *testing.T) {
	raw := []byte(strings.Repeat("tail-partial-YYYYYYYY\n", 60))
	src := &logmirror.FakeSource{Log: raw, Running: true}
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
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
	m.FetchBytes = 64

	access := logmirror.NewAccess("corp", m)
	access.MaxBytes = 96
	access.MaxPolls = 8
	status := logmirror.NewFakeBuildStatus()
	status.DefaultComplete = false
	status.Set("demo", 9, false)
	access.Status = status

	if err := access.EnsureMirrored(context.Background(), "demo", 9); err == nil {
		t.Fatal("expected budget residual from EnsureMirrored")
	}
	st, err := m.State(context.Background(), logmirror.LogKey{Profile: "corp", Job: "demo", Build: 9})
	if err != nil || st.DurableOffset <= 0 {
		t.Fatalf("need durable partial: st=%+v err=%v", st, err)
	}

	access2 := logmirror.NewAccess("corp", m)
	access2.MaxBytes = 1
	access2.MaxPolls = 1
	access2.Status = status
	mla := tools.NewMirrorLogAccess(access2)

	logs, _, err := mla.Tail(context.Background(), "demo", 9, 12)
	if err != nil {
		t.Fatalf("Regression: Tail must serve partial on Ensure residual: %v", err)
	}
	if len(logs) == 0 {
		t.Fatal("expected non-empty tail from partial durable frames")
	}
}
