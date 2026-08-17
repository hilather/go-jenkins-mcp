package logmirror_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// Regression: re-mirroring a stage log silently discarded the new content
// while reporting success. The first mirror seals the generation; a second
// mirror hit the sealed branch in appendLocked, which routes to
// startNewGeneration — a pull-mode rewrite path that deliberately drops the
// segment body. The pushed bytes were lost and the new generation was left
// empty/unsealed forever (stage keys are push-only; nothing re-polls them).
// MirrorStageLogBytes now treats the push body as a full fresh snapshot:
// identical content is a no-op; changed content rotates the generation and
// the snapshot is written into it.
func TestMirrorStageLogBytes_RemirrorWritesNewSnapshot(t *testing.T) {
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
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	m := logmirror.NewMachine(meta, &logmirror.FakeSource{Log: []byte("console\n"), Running: false})
	m.Frames = fr
	m.Reader = reader
	a := logmirror.NewAccess("corp", m)
	ctx := context.Background()
	stageKey := logmirror.StageLogKey("corp", "demo", 7, "12")

	// First mirror seals the generation.
	st1, err := a.MirrorStageLogBytes(ctx, "demo", 7, "12", []byte("stage v1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !st1.Sealed {
		t.Fatalf("first mirror must seal: %+v", st1)
	}

	// Identical re-mirror: no-op success, same generation, content intact.
	st2, err := a.MirrorStageLogBytes(ctx, "demo", 7, "12", []byte("stage v1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if st2.Generation != st1.Generation {
		t.Fatalf("identical re-mirror must not rotate: gen %d → %d", st1.Generation, st2.Generation)
	}
	rr, err := m.ReadRange(ctx, stageKey, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if string(rr.Data) != "stage v1\n" {
		t.Fatalf("after identical re-mirror: %q", rr.Data)
	}

	// Changed re-mirror (log grew): new content must be stored and readable.
	st3, err := a.MirrorStageLogBytes(ctx, "demo", 7, "12", []byte("stage v1\nstage v2\n"))
	if err != nil {
		t.Fatal(err)
	}
	rr2, err := m.ReadRange(ctx, stageKey, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if string(rr2.Data) != "stage v1\nstage v2\n" {
		t.Fatalf("changed re-mirror lost content: %q (state=%+v)", rr2.Data, st3)
	}
	if st3.Generation == st1.Generation {
		t.Fatal("changed content must rotate the generation")
	}
	if !st3.Sealed {
		t.Fatalf("re-mirrored snapshot must seal: %+v", st3)
	}
}

// Regression (review follow-up): the check-compare-rotate-append-seal sequence
// as separate locked calls raced under concurrent re-mirrors — one caller
// could skip the sealed handling while another rotated, or two full snapshots
// concatenated into one generation. AppendSnapshot runs the whole sequence
// under one per-key lock hold. Concurrent pushes must leave the mirror holding
// exactly one of the pushed snapshots — never empty, never concatenated.
func TestMirrorStageLogBytes_ConcurrentRemirrorConsistent(t *testing.T) {
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
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	m := logmirror.NewMachine(meta, &logmirror.FakeSource{Log: []byte("console\n"), Running: false})
	m.Frames = fr
	m.Reader = reader
	a := logmirror.NewAccess("corp", m)
	ctx := context.Background()
	stageKey := logmirror.StageLogKey("corp", "demo", 7, "12")

	snapshots := [][]byte{[]byte("stage v1\n"), []byte("stage v1\nstage v2\n")}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if _, err := a.MirrorStageLogBytes(ctx, "demo", 7, "12", snapshots[(w+i)%2]); err != nil {
					t.Errorf("mirror: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	rr, err := m.ReadRange(ctx, stageKey, 0, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	got := string(rr.Data)
	if got != string(snapshots[0]) && got != string(snapshots[1]) {
		t.Fatalf("mirror holds %q — must be exactly one pushed snapshot (never empty/concatenated)", got)
	}
	// And the mirror is sealed + readable (no wedged empty generation).
	st, err := m.State(ctx, stageKey)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Sealed {
		t.Fatalf("final state must be sealed: %+v", st)
	}
}
