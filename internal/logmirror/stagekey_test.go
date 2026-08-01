package logmirror_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/logmirror"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

func TestStageLogKey_DistinctFromConsole(t *testing.T) {
	console := logmirror.LogKey{Profile: "corp", Job: "demo", Build: 7}
	stage := logmirror.StageLogKey("corp", "demo", 7, "12")
	if stage.String() == console.String() {
		t.Fatal("stage key must differ from console")
	}
	if stage.Job != "demo#stage:12" {
		t.Fatalf("job = %q", stage.Job)
	}
}

func TestMirrorStageLogBytes_DoesNotTouchConsole(t *testing.T) {
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

	src := &logmirror.FakeSource{Log: []byte("console-body\n"), Running: false}
	m := logmirror.NewMachine(meta, src)
	m.Frames = fr
	m.Reader = reader

	consoleKey := logmirror.LogKey{Profile: "corp", Job: "demo", Build: 7}
	if _, err := m.Append(context.Background(), consoleKey, logmirror.Segment{
		Data: []byte("console-body\n"), ReportedNextOffset: 13, MoreData: false, BuildComplete: true,
	}); err != nil {
		t.Fatal(err)
	}
	// Flush console frames so durable offset is set.
	if _, err := m.Append(context.Background(), consoleKey, logmirror.Segment{
		Data: nil, ReportedNextOffset: 13, MoreData: false, BuildComplete: true,
	}); err != nil {
		// optional
		_ = err
	}
	before, err := m.State(context.Background(), consoleKey)
	if err != nil {
		t.Fatal(err)
	}

	a := logmirror.NewAccess("corp", m)
	st, err := a.MirrorStageLogBytes(context.Background(), "demo", 7, "12", []byte("stage-only-log\n"))
	if err != nil {
		t.Fatal(err)
	}
	if st.CommittedOffset <= 0 && st.DurableOffset <= 0 {
		t.Fatalf("stage state = %+v", st)
	}

	after, err := m.State(context.Background(), consoleKey)
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != before.Generation || after.DurableOffset != before.DurableOffset {
		t.Fatalf("console corrupted: before=%+v after=%+v", before, after)
	}

	// Stage key readable from frames when durable.
	stageKey := logmirror.StageLogKey("corp", "demo", 7, "12")
	rr, err := m.ReadRange(context.Background(), stageKey, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if string(rr.Data) != "stage-only-log\n" {
		t.Fatalf("data = %q (state=%+v)", rr.Data, st)
	}
}
