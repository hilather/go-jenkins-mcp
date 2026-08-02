package logmirror_test

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/archive"
	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// openPackEnv builds meta+frames+machine for L1→L2 packing tests.
func openPackEnv(t *testing.T) (*store.Meta, *store.Frames, *logmirror.Machine, string) {
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
	// Small frames so multi-frame L1 path is exercised.
	fr.TargetBytes = 48
	fr.MaxBytes = 128
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	m := logmirror.NewMachine(meta, nil)
	m.Frames = fr
	m.Reader = reader
	return meta, fr, m, dir
}

func sealLog(t *testing.T, m *logmirror.Machine, key logmirror.LogKey, body []byte) {
	t.Helper()
	ctx := context.Background()
	st, err := m.Append(ctx, key, logmirror.Segment{
		Data:               body,
		ReportedNextOffset: int64(len(body)),
		MoreData:           false,
		BuildComplete:      true,
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !st.Sealed {
		st, err = m.Seal(ctx, key)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
	}
	if !st.Sealed {
		t.Fatal("expected sealed generation")
	}
}

func TestPackGenerations_L1StoreToOpenPack(t *testing.T) {
	// Regression: L1 frames via store → pack → read member via OpenPack / ArchiveStore.
	meta, fr, machine, dir := openPackEnv(t)
	ctx := context.Background()

	keyA := logmirror.LogKey{Profile: "corp", Job: "demo", Build: 1}
	keyB := logmirror.LogKey{Profile: "corp", Job: "other", Build: 2}
	bodyA := []byte(strings.Repeat("line-a\n", 20))
	bodyB := []byte("short-b\n")
	sealLog(t, machine, keyA, bodyA)
	sealLog(t, machine, keyB, bodyB)

	stA, err := machine.State(ctx, keyA)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := meta.ListChunks(ctx, stA.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Logf("note: bodyA produced %d L1 frames (target=%d); multi-frame preferred", len(chunks), fr.TargetBytes)
	}

	dest := archive.NewMemoryStore()
	res, err := logmirror.PackGenerations(ctx, []logmirror.LogKey{keyA, keyB}, meta, dir, dest, logmirror.PackOptions{
		PackID:        "pack-l1-test",
		AffinityGroup: "test-affinity",
	})
	if err != nil {
		t.Fatalf("PackGenerations: %v", err)
	}
	if res.PackID != "pack-l1-test" {
		t.Fatalf("pack id %q", res.PackID)
	}
	if res.MemberCount != 2 {
		t.Fatalf("members %d", res.MemberCount)
	}
	if !res.CopiedFrames {
		t.Fatal("expected L1 frame copy path")
	}

	entries, err := dest.ListEntries(ctx, "pack-l1-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("list entries %d", len(entries))
	}
	var foundA bool
	for _, e := range entries {
		rc, _, err := dest.OpenEntry(ctx, archive.ArchiveRef{PackID: "pack-l1-test", EntryID: e.EntryID})
		if err != nil {
			t.Fatalf("OpenEntry %s: %v", e.EntryID, err)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(rc); err != nil {
			_ = rc.Close()
			t.Fatal(err)
		}
		_ = rc.Close()
		if e.Name == "logs/demo/1/consoleText" {
			foundA = true
			if !bytes.Equal(buf.Bytes(), bodyA) {
				t.Fatalf("member %s body mismatch got=%d want=%d", e.Name, buf.Len(), len(bodyA))
			}
		}
	}
	if !foundA {
		t.Fatalf("demo member not found in %+v", entries)
	}
	if err := dest.Verify(ctx, archive.ArchiveRef{PackID: "pack-l1-test"}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestPackCollection_SealedOnly(t *testing.T) {
	ctx := context.Background()
	mf := &multiFake{}
	mf.source("job-a").SetLog([]byte("aaa\n"))
	mf.source("job-b").SetLog([]byte("bbb\n"))

	meta, fr, _, dir := openPackEnv(t)
	m := logmirror.NewMachine(meta, mf)
	m.Frames = fr
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	m.Reader = reader
	c := logmirror.NewCoordinator("corp", m, logmirror.DefaultCollectionBounds())
	status := logmirror.NewFakeBuildStatus()
	status.Set("job-a", 1, true)
	status.Set("job-b", 2, true)
	c.Status = status

	acq, err := c.Acquire(ctx, []logmirror.LogRequest{
		{Job: "job-a", Build: 1},
		{Job: "job-b", Build: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range acq.Results {
		if r.Err != nil {
			t.Fatalf("acquire %v: %v", r.Key, r.Err)
		}
		if !r.State.Sealed {
			t.Fatalf("not sealed: %v", r.Key)
		}
	}

	dest := archive.NewMemoryStore()
	packRes, err := c.PackCollection(ctx, acq.CollectionID, meta, dir, dest, logmirror.PackOptions{
		PackID: "coll-pack-1",
	})
	if err != nil {
		t.Fatalf("PackCollection: %v", err)
	}
	if packRes.MemberCount != 2 {
		t.Fatalf("members %d", packRes.MemberCount)
	}

	entries, err := dest.ListEntries(ctx, "coll-pack-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries %d", len(entries))
	}
	for _, e := range entries {
		rc, _, err := dest.OpenEntry(ctx, archive.ArchiveRef{PackID: "coll-pack-1", EntryID: e.EntryID})
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(rc)
		_ = rc.Close()
		if buf.Len() == 0 {
			t.Fatalf("empty member %s", e.Name)
		}
	}
}

func TestPackGenerations_DerivesAffinityFromKeys(t *testing.T) {
	// Regression: empty AffinityGroup → profile=<id>|job=<fullName> on pack catalog.
	meta, _, machine, dir := openPackEnv(t)
	ctx := context.Background()
	keyA := logmirror.LogKey{Profile: "corp", Job: "folder/demo", Build: 1}
	keyB := logmirror.LogKey{Profile: "corp", Job: "folder/demo", Build: 2}
	sealLog(t, machine, keyA, []byte(strings.Repeat("a\n", 20)))
	sealLog(t, machine, keyB, []byte(strings.Repeat("b\n", 20)))

	dest := archive.NewMemoryStore()
	res, err := logmirror.PackGenerations(ctx, []logmirror.LogKey{keyA, keyB}, meta, dir, dest, logmirror.PackOptions{
		PackID: "pack-aff-1",
		// AffinityGroup intentionally empty — derived from members.
	})
	if err != nil {
		t.Fatalf("PackGenerations: %v", err)
	}
	want := "profile=corp|job=folder/demo"
	if res.AffinityGroup != want {
		t.Fatalf("AffinityGroup %q want %q", res.AffinityGroup, want)
	}
	if info, ok := dest.PackInfo("pack-aff-1"); !ok {
		t.Fatal("pack not in catalog")
	} else if info.AffinityGroup != want {
		t.Fatalf("catalog affinity %q", info.AffinityGroup)
	}

	// Mixed jobs still pack when forced; label is mixed.
	keyC := logmirror.LogKey{Profile: "corp", Job: "other", Build: 1}
	sealLog(t, machine, keyC, []byte("c\n"))
	res2, err := logmirror.PackGenerations(ctx, []logmirror.LogKey{keyA, keyC}, meta, dir, dest, logmirror.PackOptions{
		PackID: "pack-aff-mixed",
	})
	if err != nil {
		t.Fatalf("mixed pack: %v", err)
	}
	if res2.AffinityGroup != logmirror.AffinityGroupMixed {
		t.Fatalf("mixed affinity %q", res2.AffinityGroup)
	}
}

func TestPackGenerations_RejectsUnsealed(t *testing.T) {
	meta, _, machine, dir := openPackEnv(t)
	ctx := context.Background()
	key := logmirror.LogKey{Profile: "corp", Job: "run", Build: 9}
	if _, err := machine.Append(ctx, key, logmirror.Segment{
		Data: []byte("running\n"), ReportedNextOffset: 8, MoreData: true, BuildComplete: false,
	}); err != nil {
		t.Fatal(err)
	}
	dest := archive.NewMemoryStore()
	_, err := logmirror.PackGenerations(ctx, []logmirror.LogKey{key}, meta, dir, dest, logmirror.PackOptions{PackID: "x"})
	if err == nil {
		t.Fatal("expected reject unsealed")
	}
}

func TestPackGenerations_JournalLiteMarkPacked(t *testing.T) {
	// Regression: verify before PutPack; mark packed after; L1 frames remain.
	meta, _, machine, dir := openPackEnv(t)
	ctx := context.Background()
	key := logmirror.LogKey{Profile: "corp", Job: "demo", Build: 3}
	body := []byte(strings.Repeat("line\n", 30))
	sealLog(t, machine, key, body)

	// Count L1 frames before pack.
	st, err := machine.State(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	chunksBefore, err := meta.ListChunks(ctx, st.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunksBefore) == 0 {
		t.Fatal("expected L1 frames")
	}

	dest := archive.NewMemoryStore()
	res, err := logmirror.PackGenerations(ctx, []logmirror.LogKey{key}, meta, dir, dest, logmirror.PackOptions{
		PackID: "pack-mark-1",
		Marker: meta,
	})
	if err != nil {
		t.Fatalf("PackGenerations: %v", err)
	}
	if !res.MarkedPacked {
		t.Fatal("expected MarkedPacked")
	}
	g, err := meta.GetGenerationByID(ctx, st.GenerationID)
	if err != nil || g == nil {
		t.Fatalf("load gen: %v", err)
	}
	if g.PackedPackID != "pack-mark-1" {
		t.Fatalf("packed_pack_id %q", g.PackedPackID)
	}
	// L1 still present.
	chunksAfter, err := meta.ListChunks(ctx, st.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunksAfter) != len(chunksBefore) {
		t.Fatalf("L1 chunks changed: before=%d after=%d", len(chunksBefore), len(chunksAfter))
	}
	if err := dest.Verify(ctx, archive.ArchiveRef{PackID: "pack-mark-1"}); err != nil {
		t.Fatal(err)
	}
}

func TestPackGenerations_RejectsCrossProfile(t *testing.T) {
	meta, _, machine, dir := openPackEnv(t)
	ctx := context.Background()
	// openPackEnv uses profile path corp; create second key with wrong profile on same meta is awkward.
	// Unit isolation is enforced on keys slice without needing two DBs.
	keyA := logmirror.LogKey{Profile: "corp", Job: "a", Build: 1}
	keyB := logmirror.LogKey{Profile: "other", Job: "b", Build: 1}
	sealLog(t, machine, keyA, []byte("a\n"))
	// Insert sealed gen for foreign profile key via Append (store allows any profile string).
	sealLog(t, machine, keyB, []byte("b\n"))
	dest := archive.NewMemoryStore()
	_, err := logmirror.PackGenerations(ctx, []logmirror.LogKey{keyA, keyB}, meta, dir, dest, logmirror.PackOptions{PackID: "x"})
	if err == nil {
		t.Fatal("expected cross-profile reject")
	}
}

func TestPackCollectionBatches_Rollover(t *testing.T) {
	ctx := context.Background()
	mf := &multiFake{}
	for _, job := range []string{"j1", "j2", "j3"} {
		mf.source(job).SetLog([]byte(strings.Repeat(job+"\n", 40)))
	}
	meta, fr, _, dir := openPackEnv(t)
	m := logmirror.NewMachine(meta, mf)
	m.Frames = fr
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	m.Reader = reader
	c := logmirror.NewCoordinator("corp", m, logmirror.DefaultCollectionBounds())
	status := logmirror.NewFakeBuildStatus()
	status.Set("j1", 1, true)
	status.Set("j2", 2, true)
	status.Set("j3", 3, true)
	c.Status = status

	acq, err := c.Acquire(ctx, []logmirror.LogRequest{
		{Job: "j1", Build: 1},
		{Job: "j2", Build: 2},
		{Job: "j3", Build: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range acq.Results {
		if r.Err != nil {
			t.Fatalf("acquire: %v", r.Err)
		}
	}

	dest := archive.NewMemoryStore()
	results, err := c.PackCollectionBatches(ctx, acq.CollectionID, meta, dir, dest, logmirror.PackOptions{
		PackID: "roll",
		Marker: meta,
		Bounds: logmirror.PackRolloverBounds{
			MaxMembers:           1, // force one member per pack
			MaxUncompressedBytes: 1 << 30,
			MaxFrames:            1 << 20,
		},
	})
	if err != nil {
		t.Fatalf("PackCollectionBatches: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("want 3 packs from rollover, got %d", len(results))
	}
	for _, res := range results {
		if res.MemberCount != 1 {
			t.Fatalf("pack %s members %d", res.PackID, res.MemberCount)
		}
		if !res.MarkedPacked {
			t.Fatalf("pack %s not marked", res.PackID)
		}
		if err := dest.Verify(ctx, archive.ArchiveRef{PackID: res.PackID}); err != nil {
			t.Fatal(err)
		}
	}
}
