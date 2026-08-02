package fleetmcp_test

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
)

func testAssertKey(t *testing.T) []byte {
	t.Helper()
	return fleetcache.DeriveAssertionKey([]byte("mesh-pilot-secret-material!!"), "fleet-cache-assert-v1")
}

func openSealedLog(t *testing.T, raw []byte) (*store.Meta, *store.LogReader, int64, string) {
	t.Helper()
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
	fr.TargetBytes = 256
	fr.MaxBytes = 1024
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	g := &store.LogGeneration{Profile: "corp", Job: "demo", Build: 9, Generation: 1, MoreData: true}
	if err := meta.InsertGeneration(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Append(context.Background(), g.ID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(context.Background(), g.ID); err != nil {
		t.Fatal(err)
	}
	if err := meta.SealGeneration(context.Background(), g.ID); err != nil {
		t.Fatal(err)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	return meta, reader, g.ID, dir
}

func TestDecodedRead_OwnerHTTP_ParityCapsDeny(t *testing.T) {
	t.Parallel()
	// Build sealed log larger than 64 KiB request ceiling.
	var log bytes.Buffer
	for i := 0; i < 5000; i++ {
		log.WriteString(strings.Repeat("Z", 20))
		log.WriteByte('\n')
	}
	raw := log.Bytes()
	if len(raw) < 70<<10 {
		t.Fatalf("fixture too small: %d", len(raw))
	}
	meta, reader, genID, _ := openSealedLog(t, raw)
	_ = meta

	loc, err := fleetcache.NewConsoleLogLocator("fleet", "pool", "ctrl", "demo", 9)
	if err != nil {
		t.Fatal(err)
	}
	lh, err := loc.Hash()
	if err != nil {
		t.Fatal(err)
	}
	// Local LogReader expected parity slice.
	localWant, err := reader.ReadRange(context.Background(), genID, 0, 1024)
	if err != nil {
		t.Fatal(err)
	}

	backend := &fleetmcp.StoreDecodedBackend{
		Meta:   meta,
		Reader: reader,
		Objects: map[string]fleetcache.LocalSealedObject{
			lh: {GenerationID: genID, Sealed: true, Materialized: true, FleetID: "fleet"},
		},
	}
	key := testAssertKey(t)
	cfg := fleetmcp.Config{
		Enabled: true, MemberID: "owner-a", MeshToken: "mesh-tok",
		Roster: &fleetmcp.Roster{SchemaVersion: 1, FleetID: "fleet", Members: []fleetmcp.RosterMember{
			{ID: "owner-a", PeerURL: "http://a"},
		}},
	}
	mux := fleetmcp.NewPeerMuxWithOptions(cfg, &fleetmcp.LocalProvider{Metrics: telemetry.NewMetrics()}, fleetmcp.PeerMuxOptions{
		DecodedRead: backend,
		AssertionAuth: fleetmcp.AssertionAuth{
			Key:    key,
			Nonces: fleetcache.NewMemoryNonceStore(),
		},
	})
	srv, _, err := fleetmcp.StartPeerServer("127.0.0.1:0", mux, fleetmcp.DefaultPeerServerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(nil) }()

	client := &fleetmcp.DecodedReadClient{
		MeshToken:          "mesh-tok",
		Timeout:            time.Second,
		Mode:               fleetcache.ModeRead,
		AssertionKey:       key,
		RequestingMemberID: "edge-1",
	}
	owners := []fleetcache.OwnerContact{{MemberID: "owner-a", PeerURL: "http://" + srv.Addr()}}

	// Happy path: 1 KiB of larger object.
	res, err := client.ReadOwners(context.Background(), "fleet", fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Start: 0, Length: 1024,
	}, owners, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != fleetcache.DecodedReadOK || res.Result == nil {
		t.Fatalf("%+v", res)
	}
	if int64(len(res.Result.Data)) != 1024 {
		t.Fatalf("got %d bytes — must not stream full object (%d)", len(res.Result.Data), len(raw))
	}
	if !bytes.Equal(res.Result.Data, localWant.Data) {
		t.Fatal("peer decoded body must match local LogReader")
	}

	// Scope deny: claim max is issued from client based on request; force bad key.
	badClient := &fleetmcp.DecodedReadClient{
		MeshToken: "mesh-tok", Timeout: time.Second, Mode: fleetcache.ModeRead,
		AssertionKey:       fleetcache.DeriveAssertionKey([]byte("wrong-secret-material!!!!"), "fleet-cache-assert-v1"),
		RequestingMemberID: "edge-1",
	}
	resBad, err := badClient.ReadOwners(context.Background(), "fleet", fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: 10,
	}, owners, true)
	if err != nil {
		// may be nil with unavailable
		_ = err
	}
	if resBad.Status == fleetcache.DecodedReadOK {
		t.Fatal("wrong assertion key must not return body")
	}

	// Not materialized.
	backend.Objects[lh] = fleetcache.LocalSealedObject{
		GenerationID: genID, Sealed: true, Materialized: false, FleetID: "fleet",
	}
	resNM, err := client.ReadOwners(context.Background(), "fleet", fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: 10,
	}, owners, true)
	if err != nil {
		t.Fatal(err)
	}
	if resNM.Status != fleetcache.DecodedReadNotMaterialized {
		t.Fatalf("not materialized: %+v", resNM)
	}

	// Mode off: zero peer contact.
	off := &fleetmcp.DecodedReadClient{
		MeshToken: "mesh-tok", Timeout: 50 * time.Millisecond, Mode: fleetcache.ModeOff,
		AssertionKey: key, RequestingMemberID: "edge-1",
	}
	resOff, err := off.ReadOwners(context.Background(), "fleet", fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: 10,
	}, []fleetcache.OwnerContact{{MemberID: "dead", PeerURL: "http://127.0.0.1:1"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if resOff.Status != fleetcache.DecodedReadModeOff || len(resOff.PeerResults) != 0 {
		t.Fatalf("%+v", resOff)
	}
}

func TestDecodedRead_MissTimeoutNoFanOut(t *testing.T) {
	t.Parallel()
	key := testAssertKey(t)
	lh := strings.Repeat("ab", 32)
	client := &fleetmcp.DecodedReadClient{
		MeshToken: "mesh-tok", Timeout: 80 * time.Millisecond, Mode: fleetcache.ModeRead,
		AssertionKey: key, RequestingMemberID: "edge-1",
	}
	// Only two owners (bounded) — closed port.
	owners := []fleetcache.OwnerContact{
		{MemberID: "a", PeerURL: "http://127.0.0.1:1"},
		{MemberID: "b", PeerURL: "http://127.0.0.1:1"},
	}
	res, err := client.ReadOwners(context.Background(), "fleet", fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: 8,
	}, owners, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != fleetcache.DecodedReadUnavailable {
		t.Fatalf("%+v", res)
	}
	if !res.OriginFallbackRecommended {
		t.Fatal("timeout should recommend origin")
	}
	if len(res.OwnersTried) != 2 {
		t.Fatalf("owners tried %v", res.OwnersTried)
	}
}

func TestDecodedRead_MemoryBackend_ServePath(t *testing.T) {
	t.Parallel()
	// Direct ServeDecodedRead parity path already in fleetcache; this checks HTTP wiring with Memory backend.
	lh := strings.Repeat("cd", 32)
	body := []byte(strings.Repeat("hello-world-line\n", 100))
	backend := &fleetmcp.MemoryDecodedBackend{
		Body: body,
		Objects: map[string]fleetcache.LocalSealedObject{
			lh: {GenerationID: 1, Sealed: true, Materialized: true, FleetID: "fleet"},
		},
	}
	key := testAssertKey(t)
	cfg := fleetmcp.Config{
		Enabled: true, MemberID: "o", MeshToken: "mesh-tok",
		Roster: &fleetmcp.Roster{SchemaVersion: 1, FleetID: "fleet", Members: []fleetmcp.RosterMember{{ID: "o"}}},
	}
	mux := fleetmcp.NewPeerMuxWithOptions(cfg, &fleetmcp.LocalProvider{Metrics: telemetry.NewMetrics()}, fleetmcp.PeerMuxOptions{
		DecodedRead:   backend,
		AssertionAuth: fleetmcp.AssertionAuth{Key: key, Nonces: fleetcache.NewMemoryNonceStore()},
	})
	srv, _, err := fleetmcp.StartPeerServer("127.0.0.1:0", mux, fleetmcp.DefaultPeerServerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(nil) }()

	client := &fleetmcp.DecodedReadClient{
		MeshToken: "mesh-tok", Timeout: time.Second, Mode: fleetcache.ModeRead,
		AssertionKey: key, RequestingMemberID: "edge",
	}
	res, err := client.ReadOwners(context.Background(), "fleet", fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Start: 0, Length: 32,
	}, []fleetcache.OwnerContact{{MemberID: "o", PeerURL: "http://" + srv.Addr()}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != fleetcache.DecodedReadOK || !bytes.Equal(res.Result.Data, body[:32]) {
		t.Fatalf("%+v", res)
	}
	// Deny-before-body: wrong fleet in assertion (client stamps fleetID from arg).
	// Use empty fleet on server roster mismatch via wrong fleetID on client request.
	// Server expects fleet from roster; assertion fleet is client-supplied — Verify checks Expected.FleetID.
	// Issue wrong op is covered in fleetcache; here wrong mesh token:
	bad := &fleetmcp.DecodedReadClient{
		MeshToken: "nope", Timeout: time.Second, Mode: fleetcache.ModeRead,
		AssertionKey: key, RequestingMemberID: "edge",
	}
	res2, _ := bad.ReadOwners(context.Background(), "fleet", fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: 8,
	}, []fleetcache.OwnerContact{{MemberID: "o", PeerURL: "http://" + srv.Addr()}}, true)
	if res2.Status == fleetcache.DecodedReadOK {
		t.Fatal("wrong mesh must fail")
	}
	// Scope deny should not increment reads beyond happy path count.
	callsAfterHappy := backend.ReadCalls
	// Over-ceiling request (length > absolute) rejected client-side validation.
	_, err = client.ReadOwners(context.Background(), "fleet", fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: fleetcache.AbsoluteDecodedReadCeiling + 1,
	}, []fleetcache.OwnerContact{{MemberID: "o", PeerURL: "http://" + srv.Addr()}}, true)
	if err == nil {
		t.Fatal("expected over absolute reject")
	}
	if backend.ReadCalls != callsAfterHappy {
		t.Fatalf("over-ceiling must not hit owner body: calls %d→%d", callsAfterHappy, backend.ReadCalls)
	}
}
