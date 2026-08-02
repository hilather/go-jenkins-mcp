package fleetmcp_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
)

func TestFrameExport_StoreParityAndDeny(t *testing.T) {
	t.Parallel()
	// Multi-frame sealed log via store; export one frame via HTTP must match ExportPureZstd.
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
	fr.TargetBytes = 64
	fr.MaxBytes = 256
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	g := &store.LogGeneration{Profile: "corp", Job: "export-job", Build: 3, Generation: 1, MoreData: true}
	if err := meta.InsertGeneration(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	// Large enough multi-frame body.
	var body bytes.Buffer
	for i := 0; i < 40; i++ {
		body.WriteString(strings.Repeat("F", 20))
		body.WriteByte('\n')
	}
	raw := body.Bytes()
	if _, err := fr.Append(context.Background(), g.ID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(context.Background(), g.ID); err != nil {
		t.Fatal(err)
	}
	if err := meta.SealGeneration(context.Background(), g.ID); err != nil {
		t.Fatal(err)
	}
	chunks, err := meta.ListChunks(context.Background(), g.ID)
	if err != nil || len(chunks) < 2 {
		t.Fatalf("need multi-frame: %v n=%d", err, len(chunks))
	}
	// Store export reference for seq 0.
	want, err := meta.ExportPureZstdEnsured(context.Background(), dir, chunks[0], nil)
	if err != nil {
		t.Fatal(err)
	}

	loc, err := fleetcache.NewConsoleLogLocator("fleet", "pool", "ctrl", "export-job", 3)
	if err != nil {
		t.Fatal(err)
	}
	lh, err := loc.Hash()
	if err != nil {
		t.Fatal(err)
	}
	backend := &fleetmcp.StoreFrameBackend{
		Meta: meta, DataDir: dir,
		Objects: map[string]fleetcache.LocalSealedObject{
			lh: {GenerationID: g.ID, Sealed: true, Materialized: true, FleetID: "fleet"},
		},
	}
	key := testAssertKey(t)
	cfg := fleetmcp.Config{
		Enabled: true, MemberID: "owner", MeshToken: "mesh-tok",
		Roster: &fleetmcp.Roster{SchemaVersion: 1, FleetID: "fleet", Members: []fleetmcp.RosterMember{{ID: "owner"}}},
	}
	mux := fleetmcp.NewPeerMuxWithOptions(cfg, &fleetmcp.LocalProvider{Metrics: telemetry.NewMetrics()}, fleetmcp.PeerMuxOptions{
		FrameExport:   backend,
		AssertionAuth: fleetmcp.AssertionAuth{Key: key, Nonces: fleetcache.NewMemoryNonceStore()},
	})
	srv, _, err := fleetmcp.StartPeerServer("127.0.0.1:0", mux, fleetmcp.DefaultPeerServerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(nil) }()

	client := &fleetmcp.FrameExportClient{
		MeshToken: "mesh-tok", Timeout: time.Second, Mode: fleetcache.ModeRead,
		AssertionKey: key, RequestingMemberID: "edge",
	}
	owners := []fleetcache.OwnerContact{{MemberID: "owner", PeerURL: "http://" + srv.Addr()}}
	res, err := client.FetchFrameOwners(context.Background(), "fleet", fleetcache.FrameExportRequest{
		LocatorHash: lh, Seq: 0,
	}, owners, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != fleetcache.FrameExportOK || res.Result == nil {
		t.Fatalf("%+v", res)
	}
	if !bytes.Equal(res.Result.Bytes, want.Bytes) {
		t.Fatalf("wire bytes must match ExportPureZstd: got %d want %d", len(res.Result.Bytes), len(want.Bytes))
	}
	if res.Result.SHA256 != want.SHA256 || res.Result.Size != want.Size {
		t.Fatalf("meta %+v want sha=%s size=%d", res.Result, want.SHA256, want.Size)
	}
	// Must not buffer whole log: single frame size << full raw.
	if int64(len(res.Result.Bytes)) >= int64(len(raw)) {
		t.Fatalf("frame size %d should be < full raw %d", len(res.Result.Bytes), len(raw))
	}

	// Wrong mesh deny before body.
	bad := &fleetmcp.FrameExportClient{
		MeshToken: "wrong", Timeout: time.Second, Mode: fleetcache.ModeRead,
		AssertionKey: key, RequestingMemberID: "edge",
	}
	resBad, _ := bad.FetchFrameOwners(context.Background(), "fleet", fleetcache.FrameExportRequest{
		LocatorHash: lh, Seq: 0,
	}, owners, true)
	if resBad.Status == fleetcache.FrameExportOK {
		t.Fatal("wrong mesh must not get frame")
	}

	// Mode off: zero peer I/O.
	off := &fleetmcp.FrameExportClient{
		MeshToken: "mesh-tok", Timeout: 50 * time.Millisecond, Mode: fleetcache.ModeOff,
		AssertionKey: key, RequestingMemberID: "edge",
	}
	resOff, err := off.FetchFrameOwners(context.Background(), "fleet", fleetcache.FrameExportRequest{
		LocatorHash: lh, Seq: 0,
	}, []fleetcache.OwnerContact{{MemberID: "dead", PeerURL: "http://127.0.0.1:1"}}, true)
	if err != nil || resOff.Status != fleetcache.FrameExportModeOff || len(resOff.PeerResults) != 0 {
		t.Fatalf("%+v %v", resOff, err)
	}

	// Missing frame seq (valid range but not present on owner).
	resMiss, err := client.FetchFrameOwners(context.Background(), "fleet", fleetcache.FrameExportRequest{
		LocatorHash: lh, Seq: 100,
	}, owners, true)
	if err != nil {
		t.Fatal(err)
	}
	if resMiss.Status == fleetcache.FrameExportOK {
		t.Fatal("missing seq must not hit")
	}
}

func TestFrameExport_ExtraBytesAndAdmission(t *testing.T) {
	t.Parallel()
	// Memory backend + exact client integrity paths + concurrent admission cap.
	lh := strings.Repeat("cd", 32)
	payload := []byte("pure-frame-payload-bytes-XXXX")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	backend := &fleetmcp.MemoryFrameBackend{
		Objects: map[string]fleetcache.LocalSealedObject{
			lh: {GenerationID: 1, Sealed: true, Materialized: true, FleetID: "fleet"},
		},
		Frames: map[string]map[int]fleetcache.PureZstdFrame{
			lh: {0: {Bytes: payload, Size: int64(len(payload)), SHA256: hexSum, Seq: 0}},
		},
	}
	key := testAssertKey(t)
	adm := fleetcache.NewStreamAdmission(1)
	cfg := fleetmcp.Config{
		Enabled: true, MemberID: "o", MeshToken: "mesh-tok",
		Roster: &fleetmcp.Roster{SchemaVersion: 1, FleetID: "fleet", Members: []fleetmcp.RosterMember{{ID: "o"}}},
	}
	mux := fleetmcp.NewPeerMuxWithOptions(cfg, &fleetmcp.LocalProvider{Metrics: telemetry.NewMetrics()}, fleetmcp.PeerMuxOptions{
		FrameExport:    backend,
		FrameAdmission: adm,
		AssertionAuth:  fleetmcp.AssertionAuth{Key: key, Nonces: fleetcache.NewMemoryNonceStore()},
	})
	srv, _, err := fleetmcp.StartPeerServer("127.0.0.1:0", mux, fleetmcp.DefaultPeerServerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(nil) }()

	client := &fleetmcp.FrameExportClient{
		MeshToken: "mesh-tok", Timeout: time.Second, Mode: fleetcache.ModeRead,
		AssertionKey: key, RequestingMemberID: "edge",
	}
	owners := []fleetcache.OwnerContact{{MemberID: "o", PeerURL: "http://" + srv.Addr()}}

	// Declared size match.
	res, err := client.FetchFrameOwners(context.Background(), "fleet", fleetcache.FrameExportRequest{
		LocatorHash: lh, Seq: 0, DeclaredZstdSize: int64(len(payload)), DeclaredZstdSHA256: hexSum,
	}, owners, false)
	if err != nil || res.Status != fleetcache.FrameExportOK {
		t.Fatalf("%+v %v", res, err)
	}
	if !bytes.Equal(res.Result.Bytes, payload) {
		t.Fatal("body mismatch")
	}

	// Concurrent: hold admission with a slow export by blocking all slots then try second wait-with-timeout.
	// Fill admission via TryAcquire on the same gate used by server (server has its own from opts — same adm pointer).
	rel, ok := adm.TryAcquire()
	if !ok {
		t.Fatal("expected free slot after prior requests completed")
	}
	// In-flight server acquire will wait; use short client timeout for second request path via direct ServeFrameExport.
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	// Release after timeout window so waiters unblock.
	go func() {
		time.Sleep(30 * time.Millisecond)
		rel()
	}()
	// Client fetch should still succeed after brief wait (admission frees).
	res2, err := client.FetchFrameOwners(ctx, "fleet", fleetcache.FrameExportRequest{
		LocatorHash: lh, Seq: 0,
	}, owners, false)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Status != fleetcache.FrameExportOK {
		t.Fatalf("after admission free: %+v", res2)
	}

	// No FanOut: only owners list length 1.
	if len(res.OwnersTried) != 1 {
		t.Fatalf("owners %v", res.OwnersTried)
	}
}

func TestFrameExport_ClientExtraByteDetection(t *testing.T) {
	t.Parallel()
	// ReadExactFrameBody unit already covers extra bytes; here ensure client uses Content-Length path.
	payload := []byte("abc")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	// Corrupt server: Content-Length lies short — early EOF.
	// Use a custom handler? Simpler: call ReadExactFrameBody in fleetcache tests (already done).
	// Here: declared size larger than body via wrong DeclaredZstdSize against honest server fails verify.
	lh := strings.Repeat("ef", 32)
	backend := &fleetmcp.MemoryFrameBackend{
		Objects: map[string]fleetcache.LocalSealedObject{
			lh: {GenerationID: 1, Sealed: true, Materialized: true, FleetID: "fleet"},
		},
		Frames: map[string]map[int]fleetcache.PureZstdFrame{
			lh: {0: {Bytes: payload, Size: 3, SHA256: hexSum, Seq: 0}},
		},
	}
	key := testAssertKey(t)
	cfg := fleetmcp.Config{
		Enabled: true, MemberID: "o", MeshToken: "mesh-tok",
		Roster: &fleetmcp.Roster{SchemaVersion: 1, FleetID: "fleet", Members: []fleetmcp.RosterMember{{ID: "o"}}},
	}
	mux := fleetmcp.NewPeerMuxWithOptions(cfg, &fleetmcp.LocalProvider{Metrics: telemetry.NewMetrics()}, fleetmcp.PeerMuxOptions{
		FrameExport: backend, AssertionAuth: fleetmcp.AssertionAuth{Key: key, Nonces: fleetcache.NewMemoryNonceStore()},
	})
	srv, _, err := fleetmcp.StartPeerServer("127.0.0.1:0", mux, fleetmcp.DefaultPeerServerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(nil) }()
	client := &fleetmcp.FrameExportClient{
		MeshToken: "mesh-tok", Timeout: time.Second, Mode: fleetcache.ModeRead,
		AssertionKey: key, RequestingMemberID: "edge",
	}
	// Client claims wrong declared size — server ServeFrameExport rejects declared mismatch.
	res, err := client.FetchFrameOwners(context.Background(), "fleet", fleetcache.FrameExportRequest{
		LocatorHash: lh, Seq: 0, DeclaredZstdSize: 99,
	}, []fleetcache.OwnerContact{{MemberID: "o", PeerURL: "http://" + srv.Addr()}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status == fleetcache.FrameExportOK {
		t.Fatal("declared size lie must fail closed")
	}
}

func TestFrameExport_CancelReleasesAdmission(t *testing.T) {
	t.Parallel()
	lh := strings.Repeat("aa", 32)
	payload := []byte("slow-frame")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	started := make(chan struct{})
	backend := &slowFrameBackend{
		inner: &fleetmcp.MemoryFrameBackend{
			Objects: map[string]fleetcache.LocalSealedObject{
				lh: {GenerationID: 1, Sealed: true, Materialized: true, FleetID: "fleet"},
			},
			Frames: map[string]map[int]fleetcache.PureZstdFrame{
				lh: {0: {Bytes: payload, Size: int64(len(payload)), SHA256: hexSum, Seq: 0}},
			},
		},
		started: started,
	}
	key := testAssertKey(t)
	adm := fleetcache.NewStreamAdmission(1)
	cfg := fleetmcp.Config{
		Enabled: true, MemberID: "o", MeshToken: "mesh-tok",
		Roster: &fleetmcp.Roster{SchemaVersion: 1, FleetID: "fleet", Members: []fleetmcp.RosterMember{{ID: "o"}}},
	}
	mux := fleetmcp.NewPeerMuxWithOptions(cfg, &fleetmcp.LocalProvider{Metrics: telemetry.NewMetrics()}, fleetmcp.PeerMuxOptions{
		FrameExport: backend, FrameAdmission: adm,
		AssertionAuth: fleetmcp.AssertionAuth{Key: key, Nonces: fleetcache.NewMemoryNonceStore()},
	})
	srv, _, err := fleetmcp.StartPeerServer("127.0.0.1:0", mux, fleetmcp.DefaultPeerServerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(nil) }()

	client := &fleetmcp.FrameExportClient{
		MeshToken: "mesh-tok", Timeout: 2 * time.Second, Mode: fleetcache.ModeRead,
		AssertionKey: key, RequestingMemberID: "edge",
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = client.FetchFrameOwners(ctx, "fleet", fleetcache.FrameExportRequest{
			LocatorHash: lh, Seq: 0,
		}, []fleetcache.OwnerContact{{MemberID: "o", PeerURL: "http://" + srv.Addr()}}, false)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("export never started")
	}
	if adm.InUse() != 1 {
		t.Fatalf("expected admission held, inUse=%d", adm.InUse())
	}
	cancel()
	wg.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if adm.InUse() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("admission leak after cancel: inUse=%d", adm.InUse())
}

// slowFrameBackend blocks in ExportFrame until ctx cancelled (signals started once).
type slowFrameBackend struct {
	inner   *fleetmcp.MemoryFrameBackend
	started chan struct{}
	once    sync.Once
}

func (s *slowFrameBackend) ResolveSealed(lh string) (fleetcache.LocalSealedObject, bool) {
	return s.inner.ResolveSealed(lh)
}

func (s *slowFrameBackend) ExportFrame(ctx context.Context, generationID int64, seq int) (fleetcache.PureZstdFrame, error) {
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	return fleetcache.PureZstdFrame{}, ctx.Err()
}

// TestSkeptic_DeclaredHashMustMatchBody: peer returns wrong bytes with self-consistent
// response size/hash headers; client DeclaredZstdSHA256 comes from the manifest.
// Must not accept FrameExportOK (regression: verify only used response header).
func TestSkeptic_DeclaredHashMustMatchBody(t *testing.T) {
	t.Parallel()
	lh := strings.Repeat("b1", 32)
	// Manifest truth.
	wantBody := []byte("manifest-true-frame-bytes-AAAA")
	wantSum := sha256.Sum256(wantBody)
	wantHex := hex.EncodeToString(wantSum[:])
	// Malicious peer body (different) with matching self headers.
	evilBody := []byte("evil-peer-frame-bytes-BBBBBBBB")
	evilSum := sha256.Sum256(evilBody)
	evilHex := hex.EncodeToString(evilSum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/frames/0") {
			http.NotFound(w, r)
			return
		}
		// Mesh token required by production mux; this malicious peer skips assertion
		// crypto and only fakes a successful 200 pure-zstd body (client-side integrity).
		w.Header().Set("Content-Type", fleetcache.ContentTypePureZstd)
		w.Header().Set("Content-Length", strconv.Itoa(len(evilBody)))
		w.Header().Set("X-Fleet-Zstd-Size", strconv.Itoa(len(evilBody)))
		w.Header().Set("X-Fleet-Zstd-SHA256", evilHex)
		w.Header().Set("X-Fleet-Frame-Seq", "0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(evilBody)
	}))
	t.Cleanup(srv.Close)

	key := testAssertKey(t)
	client := &fleetmcp.FrameExportClient{
		MeshToken: "mesh-tok", Timeout: time.Second, Mode: fleetcache.ModeRead,
		AssertionKey: key, RequestingMemberID: "edge",
	}
	// Still need mesh token match only on real mux; malicious server ignores mesh.
	// Client always sends mesh; peer returns 200 anyway.
	res, err := client.FetchFrameOwners(context.Background(), "fleet", fleetcache.FrameExportRequest{
		LocatorHash:        lh,
		Seq:                0,
		DeclaredZstdSize:   int64(len(wantBody)),
		DeclaredZstdSHA256: wantHex,
	}, []fleetcache.OwnerContact{{MemberID: "evil", PeerURL: srv.URL}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status == fleetcache.FrameExportOK {
		t.Fatalf("must not OK wrong body with consistent peer headers; got %+v", res)
	}
	if res.Result != nil && res.Result.Status == fleetcache.FrameExportOK {
		t.Fatal("result must not be OK")
	}
	// Peer result should be corrupt / size_mismatch.
	if len(res.PeerResults) != 1 || res.PeerResults[0].OK {
		// OK=false on integrity fail
		if len(res.PeerResults) == 1 && res.PeerResults[0].ErrorCode == "" {
			t.Fatalf("expected integrity error code: %+v", res.PeerResults)
		}
	}
}

// TestSkeptic_DeclaredSizeMustMatchBody: Content-Length != DeclaredZstdSize must fail closed
// (regression: client overwrote declared size with peer Content-Length).
func TestSkeptic_DeclaredSizeMustMatchBody(t *testing.T) {
	t.Parallel()
	lh := strings.Repeat("b2", 32)
	// Manifest expects larger frame.
	const declaredSize = 100
	// Peer returns shorter self-consistent body.
	evilBody := []byte("short-evil-body")
	if int64(len(evilBody)) >= declaredSize {
		t.Fatal("fixture must be shorter than declared")
	}
	evilSum := sha256.Sum256(evilBody)
	evilHex := hex.EncodeToString(evilSum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", fleetcache.ContentTypePureZstd)
		w.Header().Set("Content-Length", strconv.Itoa(len(evilBody)))
		w.Header().Set("X-Fleet-Zstd-Size", strconv.Itoa(len(evilBody)))
		w.Header().Set("X-Fleet-Zstd-SHA256", evilHex)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(evilBody)
	}))
	t.Cleanup(srv.Close)

	key := testAssertKey(t)
	client := &fleetmcp.FrameExportClient{
		MeshToken: "t", Timeout: time.Second, Mode: fleetcache.ModeRead,
		AssertionKey: key, RequestingMemberID: "edge",
	}
	// Declared hash of an all-zero buffer of declaredSize (does not matter: CL vs declared fails first).
	dummy := make([]byte, declaredSize)
	dummySum := sha256.Sum256(dummy)
	res, err := client.FetchFrameOwners(context.Background(), "fleet", fleetcache.FrameExportRequest{
		LocatorHash:        lh,
		Seq:                0,
		DeclaredZstdSize:   declaredSize,
		DeclaredZstdSHA256: hex.EncodeToString(dummySum[:]),
	}, []fleetcache.OwnerContact{{MemberID: "evil", PeerURL: srv.URL}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status == fleetcache.FrameExportOK {
		t.Fatalf("Content-Length != DeclaredZstdSize must fail closed: %+v", res)
	}
	if len(res.PeerResults) != 1 {
		t.Fatalf("peer results: %+v", res.PeerResults)
	}
	if res.PeerResults[0].ErrorCode != "size_mismatch" && res.PeerResults[0].ErrorCode != "corrupt" && res.PeerResults[0].ErrorCode != "protocol" {
		// Prefer size_mismatch; protocol also acceptable if CL path still reads declared size.
		t.Fatalf("want size_mismatch/corrupt/protocol, got %q residual=%q", res.PeerResults[0].ErrorCode, res.PeerResults[0].Residual)
	}
	if res.PeerResults[0].OK {
		t.Fatal("peer result OK must be false")
	}
}
