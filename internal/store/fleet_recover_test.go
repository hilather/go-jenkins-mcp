package store_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

func TestFleetRecover_StagingInvisibleAfterReopen(t *testing.T) {
	// Begin import, write < frames_total, close meta, reopen + Recover:
	// no committed mapping hit.
	parts := [][]byte{[]byte("one\n"), []byte("two\n")}
	wm, frames, _ := buildImportFixture(t, parts)
	dir := filepath.Join(t.TempDir(), "profiles", "recv")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	sink := store.NewPeerImportSink(meta, fr)
	importID, genID, err := sink.Begin(context.Background(), wm)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteFrame(context.Background(), importID, genID, wm.Frames[0], frames[0].PureZstd); err != nil {
		t.Fatal(err)
	}
	// Simulate process exit: close stores.
	_ = fr.Close()
	_ = meta.Close()

	// Restart.
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
	rec, err := fr2.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Fleet.StagingAborted < 1 {
		t.Fatalf("expected staging abort on recover: %+v", rec.Fleet)
	}
	if _, ok, err := meta2.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); err != nil || ok {
		t.Fatalf("staging must not become committed hit ok=%v err=%v", ok, err)
	}
	// Journal aborted.
	j, err := meta2.GetFleetImport(context.Background(), importID)
	if err != nil || j.Status != store.FleetImportAborted {
		t.Fatalf("%+v %v", j, err)
	}
	// Idempotent second recover.
	rec2, err := fr2.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec2.Fleet.StagingAborted != 0 {
		t.Fatalf("second recover should not re-abort: %+v", rec2.Fleet)
	}
	// Full re-import after recovery still works.
	sink2 := store.NewPeerImportSink(meta2, fr2)
	res, err := fleetcache.RunImport(context.Background(), sink2, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestFleetRecover_QuarantineCorruptCommitted(t *testing.T) {
	parts := [][]byte{[]byte("alpha\n"), []byte("beta\n")}
	wm, frames, full := buildImportFixture(t, parts)
	meta, fr, dir := openImportStore(t)
	sink := store.NewPeerImportSink(meta, fr)
	res, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil {
		t.Fatal(err)
	}
	// Healthy hit first.
	if _, ok, _ := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); !ok {
		t.Fatal("expected committed")
	}
	chunks, err := meta.ListChunks(context.Background(), res.GenerationID)
	if err != nil || len(chunks) < 1 {
		t.Fatal(err)
	}
	// Corrupt frame file on disk (bit flip) while leaving meta.
	abs, err := store.FrameAbsPath(dir, chunks[0].RelPath)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	onDisk[len(onDisk)/2] ^= 0xff
	if err := os.WriteFile(abs, onDisk, 0o600); err != nil {
		t.Fatal(err)
	}

	rec, err := fr.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Fleet.MappingsQuarantined < 1 {
		t.Fatalf("expected quarantine: %+v", rec.Fleet)
	}
	// Not a healthy hit.
	if _, ok, err := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); err != nil || ok {
		t.Fatalf("quarantined must not be committed hit ok=%v err=%v", ok, err)
	}
	any, ok, err := meta.GetFleetMappingAny(context.Background(), wm.LocatorHash)
	if err != nil || !ok || any.Status != store.FleetMappingQuarantined {
		t.Fatalf("expected quarantined residual status: %+v ok=%v err=%v", any, ok, err)
	}
	// Residual codes secret-free (no locator/path in residuals list).
	for _, r := range rec.Fleet.Residuals {
		if len(r) > 40 || filepath.IsAbs(r) || containsSecretShape(r) {
			t.Fatalf("residual not secret-free: %q", r)
		}
	}
	// Double recovery idempotent: still quarantined, no error, quarantine count 0.
	rec2, err := fr.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec2.Fleet.MappingsQuarantined != 0 {
		t.Fatalf("second recover re-quarantine: %+v", rec2.Fleet)
	}
	any2, ok, _ := meta.GetFleetMappingAny(context.Background(), wm.LocatorHash)
	if !ok || any2.Status != store.FleetMappingQuarantined {
		t.Fatalf("%+v", any2)
	}
	_ = full
}

// Regression (skeptic): quarantine must not trap the locator forever —
// complete RunImport after Recover quarantine must restore a committed hit.
func TestFleetRecover_QuarantineThenReimportRestoresHit(t *testing.T) {
	parts := [][]byte{[]byte("restore-a\n"), []byte("restore-b\n")}
	wm, frames, full := buildImportFixture(t, parts)
	meta, fr, dir := openImportStore(t)
	sink := store.NewPeerImportSink(meta, fr)
	res, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := meta.ListChunks(context.Background(), res.GenerationID)
	if err != nil || len(chunks) < 1 {
		t.Fatal(err)
	}
	abs, err := store.FrameAbsPath(dir, chunks[0].RelPath)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	onDisk[len(onDisk)/2] ^= 0xff
	if err := os.WriteFile(abs, onDisk, 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := fr.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Fleet.MappingsQuarantined < 1 {
		t.Fatalf("expected quarantine first: %+v", rec.Fleet)
	}
	if _, ok, _ := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); ok {
		t.Fatal("must not be committed hit while quarantined")
	}

	// Complete re-import of same sealed version must succeed and restore hit.
	res2, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil {
		t.Fatalf("re-import after quarantine must not fail: %v", err)
	}
	if res2.Status != fleetcache.ImportStatusCommitted && res2.Status != fleetcache.ImportStatusIdempotent {
		// Fresh gen after quarantine → committed (not idempotent of old gen).
		t.Fatalf("status %+v", res2)
	}
	m, ok, err := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash)
	if err != nil || !ok {
		t.Fatalf("expected committed hit after re-import ok=%v err=%v", ok, err)
	}
	if m.Status != store.FleetMappingCommitted {
		t.Fatalf("%+v", m)
	}
	if m.GenerationID != res2.GenerationID && res2.GenerationID != 0 {
		// Prefer the new import generation when status is committed.
		if res2.Status == fleetcache.ImportStatusCommitted && m.GenerationID != res2.GenerationID {
			t.Fatalf("mapping gen %d vs import gen %d", m.GenerationID, res2.GenerationID)
		}
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := reader.ReadRange(context.Background(), m.GenerationID, 0, int64(len(full)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Data, full) {
		t.Fatalf("restored body len=%d want=%d", len(rr.Data), len(full))
	}
}

func TestFleetRecover_MissingFrameFileQuarantine(t *testing.T) {
	parts := [][]byte{[]byte("x\n")}
	wm, frames, _ := buildImportFixture(t, parts)
	meta, fr, dir := openImportStore(t)
	sink := store.NewPeerImportSink(meta, fr)
	res, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil {
		t.Fatal(err)
	}
	chunks, _ := meta.ListChunks(context.Background(), res.GenerationID)
	abs, _ := store.FrameAbsPath(dir, chunks[0].RelPath)
	if err := os.Remove(abs); err != nil {
		t.Fatal(err)
	}
	// Recover may also delete chunk row for missing file (STO-004) then health fails.
	rec, err := fr.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// After missing-file chunk delete, mapping should be quarantined if still committed.
	if _, ok, _ := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); ok {
		// If still committed, health should have quarantined — fail.
		if rec.Fleet.MappingsQuarantined < 1 {
			t.Fatalf("expected quarantine or no committed hit: fleet=%+v missingFiles=%d", rec.Fleet, rec.MissingFiles)
		}
	}
}

func TestFleetRecover_CleanDBNoop(t *testing.T) {
	_, fr, _ := openImportStore(t)
	rec, err := fr.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Fleet.StagingAborted != 0 || rec.Fleet.MappingsQuarantined != 0 {
		t.Fatalf("%+v", rec.Fleet)
	}
	rec2, err := fr.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec2.Fleet.StagingAborted != 0 || rec2.Fleet.MappingsQuarantined != 0 {
		t.Fatalf("%+v", rec2.Fleet)
	}
}

func containsSecretShape(s string) bool {
	return len(s) == 64 || // full locator hex
		filepath.IsAbs(s) ||
		s == "Bearer" ||
		len(s) > 80
}
