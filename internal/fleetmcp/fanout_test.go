package fleetmcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
)

type mapFetcher map[string]any // peer id -> payload or error string "ERR:timeout"

func (m mapFetcher) Fetch(_ context.Context, peer fleetmcp.RosterMember, _ fleetmcp.Collection) (any, time.Duration, error) {
	v, ok := m[peer.ID]
	if !ok {
		return nil, 0, errPeer("missing")
	}
	if s, ok := v.(string); ok && strings.HasPrefix(s, "ERR:") {
		code := strings.TrimPrefix(s, "ERR:")
		if code == "timeout" {
			return nil, 5 * time.Millisecond, errTimeout()
		}
		return nil, 0, errPeer(code)
	}
	return v, time.Millisecond, nil
}

type simpleErr struct{ code, msg string }

func (e simpleErr) Error() string { return e.msg }

func errTimeout() error {
	return &timeoutErr{simpleErr{code: "timeout", msg: "timeout"}}
}

type timeoutErr struct{ simpleErr }

func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func errPeer(code string) error {
	return simpleErr{code: code, msg: code}
}

// Use apperr-compatible codes via fleetmcp by calling real HTTP peer for timeout tests.

func TestFanOut_LocalAndPeerMetrics(t *testing.T) {
	t.Parallel()
	m := telemetry.NewMetrics()
	m.Inc(telemetry.MetricMCPToolOK, 3)
	cfg := fleetmcp.Config{
		Enabled:         true,
		MemberID:        "edge-a",
		TrustConfigured: true,
		MeshToken:       "tok",
		PeerTimeout:     time.Second,
		Overall:         3 * time.Second,
		MaxParallel:     4,
		Roster: &fleetmcp.Roster{
			SchemaVersion: 1,
			FleetID:       "corp",
			BundleSeq:     1,
			Members: []fleetmcp.RosterMember{
				{ID: "edge-a", PeerURL: "http://local"},
				{ID: "edge-b", PeerURL: "http://peer-b"},
			},
		},
	}
	local := &fleetmcp.LocalProvider{Metrics: m, Version: "v1", Commit: "abc"}
	peers := mapFetcher{
		"edge-b": map[string]any{
			"available": true,
			"counters":  map[string]int64{telemetry.MetricMCPToolOK: 7},
			"gauges":    map[string]int64{},
		},
	}
	env := fleetmcp.FanOut(context.Background(), cfg, local, peers, fleetmcp.CollectionMetrics)
	if env.Incomplete {
		t.Fatalf("complete: %+v", env)
	}
	if env.Summary.MembersOK != 2 || env.NotMultiPodHA != true {
		t.Fatalf("%+v", env.Summary)
	}
	if env.CoordinatorID != "edge-a" || env.Collection != "metrics" {
		t.Fatalf("%+v", env)
	}
	// Aggregate allowlisted sums: 3+7=10
	sums, _ := env.Aggregate["allowlisted_counter_sums"].(map[string]int64)
	if sums == nil {
		// may be map[string]any after nothing - it's built as map[string]int64
		if raw, ok := env.Aggregate["allowlisted_counter_sums"].(map[string]int64); ok {
			sums = raw
		}
	}
	if sums[telemetry.MetricMCPToolOK] != 10 {
		t.Fatalf("sum=%v aggregate=%+v", sums, env.Aggregate)
	}
	// Bogus peer id not in roster cannot appear.
	for _, mem := range env.Members {
		if mem.ID == "evil" {
			t.Fatal("invented peer")
		}
	}
}

func TestFanOut_PartialFailure(t *testing.T) {
	t.Parallel()
	cfg := fleetmcp.Config{
		Enabled:         true,
		MemberID:        "edge-a",
		TrustConfigured: true,
		MeshToken:       "tok",
		PeerTimeout:     time.Second,
		Overall:         3 * time.Second,
		MaxParallel:     4,
		Roster: &fleetmcp.Roster{
			SchemaVersion: 1,
			FleetID:       "corp",
			Members: []fleetmcp.RosterMember{
				{ID: "edge-a", PeerURL: "http://local"},
				{ID: "edge-b", PeerURL: "http://peer-b"},
				{ID: "edge-c", PeerURL: "http://peer-c"},
			},
		},
	}
	local := &fleetmcp.LocalProvider{Version: "v1"}
	// Use real HTTP: good peer + dead peer via httptest and closed listener.
	goodLocal := &fleetmcp.LocalProvider{
		Metrics: telemetry.NewMetrics(),
		Version: "v-peer",
	}
	goodMux := fleetmcp.NewPeerMux(fleetmcp.Config{
		Enabled: true, MemberID: "edge-b", MeshToken: "tok",
		Roster: cfg.Roster,
	}, goodLocal)
	goodSrv := httptest.NewServer(goodMux)
	defer goodSrv.Close()

	// Update roster peer URLs for real HTTP fetcher
	cfg.Roster.Members[1].PeerURL = goodSrv.URL
	cfg.Roster.Members[2].PeerURL = "http://127.0.0.1:1" // closed

	fetcher := &fleetmcp.HTTPPeerFetcher{MeshToken: "tok", Timeout: 200 * time.Millisecond}
	env := fleetmcp.FanOut(context.Background(), cfg, local, fetcher, fleetmcp.CollectionHealth)
	if !env.Incomplete {
		t.Fatal("expected incomplete")
	}
	var okB, failC bool
	for _, m := range env.Members {
		if m.ID == "edge-b" && m.OK {
			okB = true
		}
		if m.ID == "edge-c" && !m.OK && m.ErrorCode != "" {
			failC = true
		}
		if m.ID == "edge-a" && !m.OK {
			t.Fatalf("local should ok: %+v", m)
		}
	}
	if !okB || !failC {
		t.Fatalf("members: %+v", env.Members)
	}
}

func TestPeerMux_AuthAndMetrics(t *testing.T) {
	t.Parallel()
	m := telemetry.NewMetrics()
	m.Inc(telemetry.MetricToolCalls, 2)
	cfg := fleetmcp.Config{
		Enabled: true, MemberID: "edge-a", MeshToken: "mesh-tok",
		Roster: &fleetmcp.Roster{
			SchemaVersion: 1, FleetID: "corp",
			Members: []fleetmcp.RosterMember{{ID: "edge-a", PeerURL: "http://x"}},
		},
	}
	mux := fleetmcp.NewPeerMux(cfg, &fleetmcp.LocalProvider{Metrics: m})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Unauthorized
	res, err := http.Get(srv.URL + fleetmcp.PeerPathPrefix + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", res.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+fleetmcp.PeerPathPrefix+"/metrics", nil)
	req.Header.Set(fleetmcp.MeshTokenHeader, "mesh-tok")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "mesh-tok") || strings.Contains(string(raw), "token=") {
		t.Fatalf("secret in body: %s", raw)
	}
	if body["available"] != true {
		t.Fatalf("%+v", body)
	}
}

func TestFanOut_SecretCanary(t *testing.T) {
	t.Parallel()
	const canary = "super-secret-token-value-XYZ"
	cfg := fleetmcp.Config{
		Enabled: true, MemberID: "a", TrustConfigured: true, MeshToken: canary,
		Roster: &fleetmcp.Roster{
			SchemaVersion: 1, FleetID: "f",
			Members: []fleetmcp.RosterMember{
				{ID: "a", PeerURL: "http://a"},
				{ID: "b", PeerURL: "http://b"},
			},
		},
	}
	local := &fleetmcp.LocalProvider{Version: "1"}
	peers := mapFetcher{"b": map[string]any{"status": "ok", "version": "1"}}
	env := fleetmcp.FanOut(context.Background(), cfg, local, peers, fleetmcp.CollectionHealth)
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canary) {
		t.Fatalf("mesh token leaked into fleet envelope: %s", raw)
	}
	if strings.Contains(string(raw), "Authorization") {
		t.Fatal("Authorization in envelope")
	}
}

func TestService_EnabledAndCatalog(t *testing.T) {
	t.Parallel()
	cat := fleetmcp.ToolCatalog()
	need := []string{"fleet_metrics", "fleet_health", "fleet_list_members", "fleet_doctor", "fleet_cache_status", "fleet_version", "fleet_residual_status"}
	for _, n := range need {
		found := false
		for _, c := range cat {
			if c == n {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing %s in %v", n, cat)
		}
	}
	svc := fleetmcp.New(fleetmcp.Config{}, nil, nil)
	if svc.Enabled() {
		t.Fatal("disabled config")
	}
}

func TestHTTPPeerFetcher_UsesRosterURLOnly(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get(fleetmcp.MeshTokenHeader) != "t" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	f := &fleetmcp.HTTPPeerFetcher{MeshToken: "t", Timeout: time.Second}
	// Call only with roster member pointing at srv — not arbitrary URL from outside.
	pl, _, err := f.Fetch(context.Background(), fleetmcp.RosterMember{ID: "b", PeerURL: srv.URL}, fleetmcp.CollectionHealth)
	if err != nil {
		t.Fatal(err)
	}
	if pl == nil || hits.Load() != 1 {
		t.Fatalf("payload=%v hits=%d", pl, hits.Load())
	}
}
