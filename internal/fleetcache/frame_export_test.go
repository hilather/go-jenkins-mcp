package fleetcache_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestValidateFrameExportRequest(t *testing.T) {
	t.Parallel()
	lh := strings.Repeat("ab", 32)
	if err := fleetcache.ValidateFrameExportRequest(fleetcache.FrameExportRequest{LocatorHash: lh, Seq: 0}); err != nil {
		t.Fatal(err)
	}
	if err := fleetcache.ValidateFrameExportRequest(fleetcache.FrameExportRequest{LocatorHash: "bad", Seq: 0}); err == nil {
		t.Fatal("bad locator")
	}
	if err := fleetcache.ValidateFrameExportRequest(fleetcache.FrameExportRequest{LocatorHash: lh, Seq: -1}); err == nil {
		t.Fatal("neg seq")
	}
	if err := fleetcache.ValidateFrameExportRequest(fleetcache.FrameExportRequest{
		LocatorHash: lh, Seq: 0, DeclaredZstdSize: fleetcache.MaxZstdFrameBytes + 1,
	}); err == nil {
		t.Fatal("oversize declared")
	}
}

func TestVerifyPureZstdFrame_AndReadExact(t *testing.T) {
	t.Parallel()
	payload := []byte("not-really-zstd-but-bytes")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	if err := fleetcache.VerifyPureZstdFrame(payload, int64(len(payload)), hexSum); err != nil {
		t.Fatal(err)
	}
	if err := fleetcache.VerifyPureZstdFrame(payload, int64(len(payload))+1, hexSum); err == nil {
		t.Fatal("size mismatch")
	}
	if err := fleetcache.VerifyPureZstdFrame(payload, int64(len(payload)), strings.Repeat("0", 64)); err == nil {
		t.Fatal("hash mismatch")
	}

	// Exact body + extra bytes fail closed.
	body := append(append([]byte{}, payload...), 0xFF)
	got, err := fleetcache.ReadExactFrameBody(bytes.NewReader(body), int64(len(payload)))
	if err == nil {
		t.Fatal("expected extra bytes")
	}
	if apperr.CodeOf(err) != apperr.CodeUpstreamProtocol {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
	_ = got
	// Early EOF.
	_, err = fleetcache.ReadExactFrameBody(bytes.NewReader(payload[:3]), int64(len(payload)))
	if err == nil {
		t.Fatal("expected early EOF")
	}
	// Happy exact.
	got, err = fleetcache.ReadExactFrameBody(bytes.NewReader(payload), int64(len(payload)))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("%v %q", err, got)
	}
}

type memFrameExport struct {
	objects map[string]fleetcache.LocalSealedObject
	frames  map[int]fleetcache.PureZstdFrame // seq → frame
	calls   atomic.Int64
}

func (m *memFrameExport) ResolveSealed(lh string) (fleetcache.LocalSealedObject, bool) {
	o, ok := m.objects[lh]
	return o, ok
}

func (m *memFrameExport) ExportFrame(ctx context.Context, generationID int64, seq int) (fleetcache.PureZstdFrame, error) {
	if err := ctx.Err(); err != nil {
		return fleetcache.PureZstdFrame{}, err
	}
	m.calls.Add(1)
	f, ok := m.frames[seq]
	if !ok {
		return fleetcache.PureZstdFrame{}, apperr.New(apperr.CodeNotFound, "frame seq missing")
	}
	// Copy so callers cannot mutate store.
	cp := append([]byte(nil), f.Bytes...)
	return fleetcache.PureZstdFrame{Bytes: cp, Size: int64(len(cp)), SHA256: f.SHA256, Seq: seq}, nil
}

func frameAssert(t *testing.T, key []byte, lh string) fleetcache.Assertion {
	t.Helper()
	now := time.Now().UTC()
	a, err := fleetcache.IssueAssertion(key, fleetcache.AssertionClaims{
		FleetID: "fleet", RequestingMemberID: "edge", LocatorHash: lh,
		Operation: fleetcache.OpFrame, IssuedAt: now, ExpiresAt: now.Add(20 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestServeFrameExport_ParityDenyNotMaterial(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	lh := strings.Repeat("11", 32)
	payload := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x01, 0x02, 0x03} // zstd magic-ish + junk
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	backend := &memFrameExport{
		objects: map[string]fleetcache.LocalSealedObject{
			lh: {GenerationID: 9, Sealed: true, Materialized: true, FleetID: "fleet"},
		},
		frames: map[int]fleetcache.PureZstdFrame{
			0: {Bytes: payload, Size: int64(len(payload)), SHA256: hexSum, Seq: 0},
			1: {Bytes: append([]byte{}, payload...), Size: int64(len(payload)), SHA256: hexSum, Seq: 1},
		},
	}
	now := time.Now().UTC()
	res, err := fleetcache.ServeFrameExport(context.Background(), backend, backend, fleetcache.FrameExportRequest{
		LocatorHash: lh, Seq: 0,
	}, frameAssert(t, key, lh), fleetcache.ServeFrameExportOptions{
		AssertionKey: key, Nonces: fleetcache.NewMemoryNonceStore(), Now: now, FleetID: "fleet",
	})
	if err != nil || res.Status != fleetcache.FrameExportOK {
		t.Fatalf("%+v %v", res, err)
	}
	if !bytes.Equal(res.Bytes, payload) || res.SHA256 != hexSum || res.Size != int64(len(payload)) {
		t.Fatalf("%+v", res)
	}
	// Only one frame buffered (size == single frame).
	if int64(len(res.Bytes)) != res.Size {
		t.Fatal("must buffer only one frame")
	}

	// Wrong op (read) denied before export.
	aRead, _ := fleetcache.IssueAssertion(key, fleetcache.AssertionClaims{
		FleetID: "fleet", RequestingMemberID: "edge", LocatorHash: lh,
		Operation: fleetcache.OpRead, IssuedAt: now, ExpiresAt: now.Add(20 * time.Second),
	})
	callsBefore := backend.calls.Load()
	_, err = fleetcache.ServeFrameExport(context.Background(), backend, backend, fleetcache.FrameExportRequest{
		LocatorHash: lh, Seq: 0,
	}, aRead, fleetcache.ServeFrameExportOptions{
		AssertionKey: key, Nonces: fleetcache.NewMemoryNonceStore(), Now: now, FleetID: "fleet",
	})
	if err == nil || backend.calls.Load() != callsBefore {
		t.Fatalf("deny before export: err=%v calls=%d→%d", err, callsBefore, backend.calls.Load())
	}

	// Not materialized.
	backend.objects[lh] = fleetcache.LocalSealedObject{GenerationID: 9, Sealed: true, Materialized: false, FleetID: "fleet"}
	res2, err := fleetcache.ServeFrameExport(context.Background(), backend, backend, fleetcache.FrameExportRequest{
		LocatorHash: lh, Seq: 0,
	}, frameAssert(t, key, lh), fleetcache.ServeFrameExportOptions{
		AssertionKey: key, Nonces: fleetcache.NewMemoryNonceStore(), Now: now, FleetID: "fleet",
	})
	if err != nil || res2.Status != fleetcache.FrameExportNotMaterial {
		t.Fatalf("%+v %v", res2, err)
	}
}

func TestStreamAdmission_CapAndCancel(t *testing.T) {
	t.Parallel()
	adm := fleetcache.NewStreamAdmission(2)
	r1, err := adm.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := adm.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if adm.InUse() != 2 {
		t.Fatalf("in use %d", adm.InUse())
	}
	// Non-blocking full.
	if _, ok := adm.TryAcquire(); ok {
		t.Fatal("cap full")
	}
	// Cancel while waiting for third slot.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = adm.Acquire(ctx)
	if err == nil {
		t.Fatal("expected cancel while full")
	}
	r1()
	r2()
	if adm.InUse() != 0 {
		t.Fatalf("released in use %d", adm.InUse())
	}
	// Double release must not panic (once).
	r1()
}

func TestServeFrameExport_AdmissionReleasedOnCancel(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	lh := strings.Repeat("22", 32)
	payload := []byte("frame-body-data")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	// Exporter blocks until ctx cancelled.
	var started sync.WaitGroup
	started.Add(1)
	backend := &blockingExport{
		memFrameExport: memFrameExport{
			objects: map[string]fleetcache.LocalSealedObject{
				lh: {GenerationID: 1, Sealed: true, Materialized: true, FleetID: "fleet"},
			},
			frames: map[int]fleetcache.PureZstdFrame{
				0: {Bytes: payload, Size: int64(len(payload)), SHA256: hexSum, Seq: 0},
			},
		},
		started: &started,
	}
	adm := fleetcache.NewStreamAdmission(1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan fleetcache.FrameExportResult, 1)
	go func() {
		res, _ := fleetcache.ServeFrameExport(ctx, backend, backend, fleetcache.FrameExportRequest{
			LocatorHash: lh, Seq: 0,
		}, frameAssert(t, key, lh), fleetcache.ServeFrameExportOptions{
			AssertionKey: key, Nonces: fleetcache.NewMemoryNonceStore(),
			Now: time.Now().UTC(), FleetID: "fleet", Admission: adm,
		})
		done <- res
	}()
	started.Wait()
	if adm.InUse() != 1 {
		t.Fatalf("expected admission held during export, inUse=%d", adm.InUse())
	}
	cancel()
	res := <-done
	if res.Status != fleetcache.FrameExportCancelled && res.Status != fleetcache.FrameExportUnavailable {
		// cancel during ExportFrame
		if adm.InUse() != 0 {
			t.Fatalf("admission not released: %d status=%s", adm.InUse(), res.Status)
		}
	}
	// Drain admission release from defer.
	time.Sleep(20 * time.Millisecond)
	if adm.InUse() != 0 {
		t.Fatalf("admission leak: %d", adm.InUse())
	}
}

type blockingExport struct {
	memFrameExport
	started *sync.WaitGroup
}

func (b *blockingExport) ExportFrame(ctx context.Context, generationID int64, seq int) (fleetcache.PureZstdFrame, error) {
	b.started.Done()
	<-ctx.Done()
	return fleetcache.PureZstdFrame{}, ctx.Err()
}

// Ensure ReadExact works with LimitReader-style EOF without extra bytes.
func TestReadExactFrameBody_EOFAfterExact(t *testing.T) {
	t.Parallel()
	p := []byte("abcd")
	got, err := fleetcache.ReadExactFrameBody(io.NopCloser(bytes.NewReader(p)), 4)
	if err != nil || string(got) != "abcd" {
		t.Fatalf("%v %q", err, got)
	}
}
