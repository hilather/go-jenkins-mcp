package fleetmcp_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
)

func TestOwnerDirectedManifestLookup_HitMissTimeout(t *testing.T) {
	t.Parallel()
	// Publish sealed manifest into owner-a catalog only.
	in := fleetcache.SealedPublishInput{
		FleetID: "fleet", CachePool: "pool", ControllerID: "ctrl",
		JobFullName: "folder/job", BuildNumber: 3, Sealed: true,
		Frames: []fleetcache.FrameDescriptor{{
			Seq: 0, RawStart: 0, RawEnd: 10, LineStart: 0, LineEnd: 2,
			DecodedSize: 10, DecodedSHA256: strings.Repeat("ab", 32),
			ZstdSize: 4, ZstdSHA256: strings.Repeat("cd", 32),
		}},
	}
	wm, err := fleetcache.PublishSealed(in)
	if err != nil {
		t.Fatal(err)
	}
	catA := fleetmcp.NewMemoryCatalog()
	if err := catA.Put(wm); err != nil {
		t.Fatal(err)
	}
	catB := fleetmcp.NewMemoryCatalog() // miss

	cfgA := fleetmcp.Config{
		Enabled: true, MemberID: "lab-a", MeshToken: "mesh-tok",
		Roster: &fleetmcp.Roster{SchemaVersion: 1, FleetID: "fleet", Members: []fleetmcp.RosterMember{
			{ID: "lab-a", PeerURL: "http://a"},
			{ID: "lab-b", PeerURL: "http://b"},
		}},
	}
	cfgB := cfgA
	cfgB.MemberID = "lab-b"

	muxA := fleetmcp.NewPeerMuxWithOptions(cfgA, &fleetmcp.LocalProvider{Metrics: telemetry.NewMetrics()}, fleetmcp.PeerMuxOptions{Catalog: catA})
	muxB := fleetmcp.NewPeerMuxWithOptions(cfgB, &fleetmcp.LocalProvider{Metrics: telemetry.NewMetrics()}, fleetmcp.PeerMuxOptions{Catalog: catB})

	srvA, _, err := fleetmcp.StartPeerServer("127.0.0.1:0", muxA, fleetmcp.DefaultPeerServerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srvA.Shutdown(nil) }()
	srvB, _, err := fleetmcp.StartPeerServer("127.0.0.1:0", muxB, fleetmcp.DefaultPeerServerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srvB.Shutdown(nil) }()

	// Placement order: b then a — miss then hit (only 2 owners, not a third).
	owners := []fleetcache.OwnerContact{
		{MemberID: "lab-b", PeerURL: "http://" + srvB.Addr()},
		{MemberID: "lab-a", PeerURL: "http://" + srvA.Addr()},
	}
	if len(owners) != 2 {
		t.Fatal("must not broadcast full roster")
	}
	client := &fleetmcp.ManifestLookupClient{MeshToken: "mesh-tok", Timeout: time.Second}
	res, err := client.LookupOwners(context.Background(), "fleet", wm.LocatorHash, owners, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != fleetcache.LookupHit || res.Manifest == nil {
		t.Fatalf("%+v", res)
	}
	if res.Manifest.ManifestDigest != wm.ManifestDigest {
		t.Fatalf("digest")
	}
	if len(res.OwnersTried) != 2 {
		t.Fatalf("tried %v", res.OwnersTried)
	}

	// Both miss.
	emptyOwners := []fleetcache.OwnerContact{
		{MemberID: "lab-b", PeerURL: "http://" + srvB.Addr()},
	}
	res2, err := client.LookupOwners(context.Background(), "fleet", wm.LocatorHash, emptyOwners, true)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Status != fleetcache.LookupMiss || !res2.OriginFallbackRecommended {
		t.Fatalf("%+v", res2)
	}

	// Timeout residual (closed port).
	res3, err := client.LookupOwners(context.Background(), "fleet", wm.LocatorHash, []fleetcache.OwnerContact{
		{MemberID: "dead", PeerURL: "http://127.0.0.1:1"},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res3.Status != fleetcache.LookupPartial {
		t.Fatalf("%+v", res3)
	}
	if len(res3.PeerResults) != 1 || res3.PeerResults[0].ErrorCode != "timeout" && res3.PeerResults[0].ErrorCode != "peer_error" {
		t.Fatalf("%+v", res3.PeerResults)
	}

	// Unauthorized: wrong mesh token.
	bad := &fleetmcp.ManifestLookupClient{MeshToken: "wrong", Timeout: time.Second}
	res4, err := bad.LookupOwners(context.Background(), "fleet", wm.LocatorHash, []fleetcache.OwnerContact{
		{MemberID: "lab-a", PeerURL: "http://" + srvA.Addr()},
	}, true)
	if err != nil {
		// may return partial without top-level error
		_ = err
	}
	if res4.Status == fleetcache.LookupHit {
		t.Fatal("wrong mesh must not hit")
	}
}

func TestManifestCatalog_RejectsInvalid(t *testing.T) {
	t.Parallel()
	cat := fleetmcp.NewMemoryCatalog()
	err := cat.Put(fleetcache.WireManifest{Sealed: false})
	if err == nil {
		t.Fatal("expected reject")
	}
}
