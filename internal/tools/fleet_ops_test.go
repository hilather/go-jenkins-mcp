package tools_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestFleetOps_NotRegisteredByDefault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	names := listToolNames(t, ctx, &tools.RegisterOptions{})
	for n := range names {
		if strings.HasPrefix(n, "fleet_") {
			t.Fatalf("unexpected fleet tool without fleet mode: %s", n)
		}
	}
}

func TestFleetOps_RegisteredWhenEnabled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg, local, peers := testFleetService(t)
	svc := fleetmcp.New(cfg, local, peers)
	if !svc.Enabled() {
		t.Fatal("enabled")
	}
	names := listToolNames(t, ctx, &tools.RegisterOptions{FleetOps: svc})
	for _, want := range fleetmcp.ToolCatalog() {
		if _, ok := names[want]; !ok {
			t.Fatalf("missing %s in %v", want, keys(names))
		}
	}
	// admin_* still not present without EnableAdminOps
	if _, ok := names["admin_metrics"]; ok {
		t.Fatal("admin_metrics should not register from fleet alone")
	}
}

func TestFleetOps_CallMetricsAggregate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg, local, peers := testFleetService(t)
	svc := fleetmcp.New(cfg, local, peers)

	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{FleetOps: svc})

	// Call via Collect path used by tools (same entry).
	env := svc.Collect(ctx, fleetmcp.CollectionMetrics)
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"collection":"metrics"`) {
		t.Fatalf("%s", raw)
	}
	if env.Summary.MembersTotal < 2 {
		t.Fatalf("%+v", env.Summary)
	}
	// Secret canary
	if strings.Contains(string(raw), cfg.MeshToken) {
		t.Fatal("mesh token in result")
	}
	if strings.Contains(string(raw), "Bearer ") || strings.Contains(string(raw), "password") {
		t.Fatalf("secret-shaped: %s", raw)
	}
}

func TestFleetOps_NilServiceNoTools(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Disabled service
	svc := fleetmcp.New(fleetmcp.Config{Enabled: false}, nil, nil)
	names := listToolNames(t, ctx, &tools.RegisterOptions{FleetOps: svc})
	for n := range names {
		if strings.HasPrefix(n, "fleet_") {
			t.Fatalf("disabled fleet still registered %s", n)
		}
	}
}

func testFleetService(t *testing.T) (fleetmcp.Config, *fleetmcp.LocalProvider, fleetmcp.PeerFetcher) {
	t.Helper()
	m := telemetry.NewMetrics()
	m.Inc(telemetry.MetricMCPToolOK, 1)
	peerLocal := &fleetmcp.LocalProvider{Metrics: telemetry.NewMetrics(), Version: "peer"}
	peerLocal.Metrics.Inc(telemetry.MetricMCPToolOK, 4)
	mux := fleetmcp.NewPeerMux(fleetmcp.Config{
		Enabled: true, MemberID: "edge-b", MeshToken: "fleet-mesh-token",
		Roster: &fleetmcp.Roster{
			SchemaVersion: 1, FleetID: "corp",
			Members: []fleetmcp.RosterMember{
				{ID: "edge-a", PeerURL: "http://a"},
				{ID: "edge-b", PeerURL: "http://b"},
			},
		},
	}, peerLocal)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := fleetmcp.Config{
		Enabled:         true,
		MemberID:        "edge-a",
		TrustConfigured: true,
		MeshToken:       "fleet-mesh-token",
		PeerTimeout:     0, // default
		Overall:         0,
		MaxParallel:     4,
		Roster: &fleetmcp.Roster{
			SchemaVersion: 1,
			FleetID:       "corp",
			BundleSeq:     2,
			Members: []fleetmcp.RosterMember{
				{ID: "edge-a", PeerURL: "http://local"},
				{ID: "edge-b", PeerURL: srv.URL},
			},
		},
	}
	local := &fleetmcp.LocalProvider{Metrics: m, Version: "coord", Commit: "c1"}
	peers := &fleetmcp.HTTPPeerFetcher{MeshToken: "fleet-mesh-token"}
	return cfg, local, peers
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestResolveConfig_FileIntegration(t *testing.T) {
	// Structural: roster file + resolve used by serve path.
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.json")
	if err := os.WriteFile(path, []byte(`{
	  "schema_version": 1,
	  "fleet_id": "corp",
	  "members": [
	    {"id":"edge-a","peer_url":"https://a.example:9443"},
	    {"id":"edge-b","peer_url":"https://b.example:9443"}
	  ]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := fleetmcp.ResolveConfig(fleetmcp.ResolveOptions{
		ModeFlag:        "1",
		MemberIDFlag:    "edge-a",
		RosterPathFlag:  path,
		MeshTokenInline: "tok",
	})
	if err != nil || !cfg.Enabled {
		t.Fatalf("%+v %v", cfg, err)
	}
	// Tool registration gate uses Enabled()
	svc := fleetmcp.New(cfg, &fleetmcp.LocalProvider{}, nil)
	if !svc.Enabled() {
		t.Fatal("enabled")
	}
}
