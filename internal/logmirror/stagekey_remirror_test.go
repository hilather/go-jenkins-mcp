package logmirror_test

import (
	"context"
	"path/filepath"
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
