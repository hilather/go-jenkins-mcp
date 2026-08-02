package fleetmcp_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
)

func TestPeerLogCoordinator_ModeOffNoIO(t *testing.T) {
	t.Parallel()
	// Would dial if mode gate missing.
	c := &fleetmcp.PeerLogCoordinator{
		Mode: fleetcache.ModeOff,
		Read: &fleetmcp.DecodedReadClient{
			MeshToken: "t", Timeout: 50 * time.Millisecond, Mode: fleetcache.ModeOff,
			AssertionKey: testAssertKey(t), RequestingMemberID: "e",
		},
		Owners: func(string) []fleetcache.OwnerContact {
			return []fleetcache.OwnerContact{{MemberID: "x", PeerURL: "http://127.0.0.1:1"}}
		},
		FleetID: "fleet", CachePool: "pool", Controller: "ctrl",
	}
	out, hit, err := c.TryRead(context.Background(), logmirror.PeerReadRequest{
		Job: "j", Build: 1, Kind: logmirror.PeerReadByteRange, Length: 8,
	})
	if err != nil || hit || out.Data != nil {
		t.Fatalf("mode off: hit=%v err=%v out=%+v", hit, err, out)
	}
}

func TestPeerLogCoordinator_FreshnessDeny(t *testing.T) {
	t.Parallel()
	gate := fleetcache.NewFreshnessGate(30*time.Second, func(ctx context.Context, k fleetcache.AuthzKey) (bool, string, error) {
		return false, fleetcache.ReasonAuthzPolicyDeny, nil
	})
	c := &fleetmcp.PeerLogCoordinator{
		Mode: fleetcache.ModeRead, FleetID: "fleet", CachePool: "pool", Controller: "ctrl",
		Freshness: gate, FreshSubject: "sub-hash",
		Read: &fleetmcp.DecodedReadClient{Mode: fleetcache.ModeRead, MeshToken: "t", AssertionKey: testAssertKey(t), RequestingMemberID: "e"},
		Owners: func(string) []fleetcache.OwnerContact {
			t.Fatal("must not plan owners after deny")
			return nil
		},
	}
	_, hit, err := c.TryRead(context.Background(), logmirror.PeerReadRequest{
		Job: "job", Build: 1, Kind: logmirror.PeerReadByteRange, Length: 4,
	})
	if hit || err == nil {
		t.Fatal("expected freshness deny")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthorization {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
}

func TestPeerLogCoordinator_PeerHitViaHTTP(t *testing.T) {
	t.Parallel()
	lh := strings.Repeat("ef", 32)
	body := []byte(strings.Repeat("coord-hit-body\n", 40))
	backend := &fleetmcp.MemoryDecodedBackend{
		Body:    body,
		Objects: map[string]fleetcache.LocalSealedObject{
			// Use real locator hash from coordinator.
		},
	}
	key := testAssertKey(t)
	// Precompute locator.
	loc, err := fleetcache.NewConsoleLogLocator("fleet", "pool", "ctrl", "demo", 3)
	if err != nil {
		t.Fatal(err)
	}
	realLH, err := loc.Hash()
	if err != nil {
		t.Fatal(err)
	}
	_ = lh
	backend.Objects = map[string]fleetcache.LocalSealedObject{
		realLH: {GenerationID: 1, Sealed: true, Materialized: true, FleetID: "fleet"},
	}
	cfg := fleetmcp.Config{
		Enabled: true, MemberID: "owner", MeshToken: "mesh-tok",
		Roster: &fleetmcp.Roster{SchemaVersion: 1, FleetID: "fleet", Members: []fleetmcp.RosterMember{{ID: "owner"}}},
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

	gate := fleetcache.NewFreshnessGate(30*time.Second, func(ctx context.Context, k fleetcache.AuthzKey) (bool, string, error) {
		return true, fleetcache.ReasonAuthzOK, nil
	})
	coord := &fleetmcp.PeerLogCoordinator{
		Mode: fleetcache.ModeRead, FleetID: "fleet", CachePool: "pool", Controller: "ctrl",
		Freshness: gate, FreshSubject: "sub",
		Owners: func(locatorHash string) []fleetcache.OwnerContact {
			if locatorHash != realLH {
				t.Fatalf("locator %s", locatorHash)
			}
			return []fleetcache.OwnerContact{{MemberID: "owner", PeerURL: "http://" + srv.Addr()}}
		},
		Read: &fleetmcp.DecodedReadClient{
			MeshToken: "mesh-tok", Timeout: time.Second, Mode: fleetcache.ModeRead,
			AssertionKey: key, RequestingMemberID: "edge",
		},
	}
	out, hit, err := coord.TryRead(context.Background(), logmirror.PeerReadRequest{
		Job: "demo", Build: 3, Kind: logmirror.PeerReadByteRange, Start: 0, Length: 20,
	})
	if err != nil || !hit {
		t.Fatalf("hit=%v err=%v", hit, err)
	}
	if string(out.Data) != string(body[:20]) {
		t.Fatalf("got %q", out.Data)
	}
	if out.Source != "peer" {
		t.Fatalf("%+v", out)
	}
}
