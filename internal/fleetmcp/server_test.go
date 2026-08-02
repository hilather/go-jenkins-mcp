package fleetmcp_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
)

func TestPeerServer_StartHealthShutdown(t *testing.T) {
	t.Parallel()
	m := telemetry.NewMetrics()
	m.Inc(telemetry.MetricToolCalls, 1)
	cfg := fleetmcp.Config{
		Enabled: true, MemberID: "edge-a", MeshToken: "mesh-tok",
		Roster: &fleetmcp.Roster{
			SchemaVersion: 1, FleetID: "corp",
			Members: []fleetmcp.RosterMember{{ID: "edge-a", PeerURL: "http://x"}},
		},
	}
	mux := fleetmcp.NewPeerMux(cfg, &fleetmcp.LocalProvider{Metrics: m, Version: "test"})
	opts := fleetmcp.DefaultPeerServerOptions()
	if opts.ReadHeaderTimeout <= 0 || opts.MaxHeaderBytes <= 0 {
		t.Fatalf("defaults must be non-zero: %+v", opts)
	}

	// Bind ephemeral port.
	ps, errCh, err := fleetmcp.StartPeerServer("127.0.0.1:0", mux, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = ps.Shutdown(ctx)
	}()

	addr := ps.Addr()
	if addr == "" {
		t.Fatal("empty addr")
	}
	// Ensure listener is up.
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("dial: %v", lastErr)
	}

	// Authenticated health.
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+fleetmcp.PeerPathPrefix+"/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(fleetmcp.MeshTokenHeader, "mesh-tok")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("status %d body %s", res.StatusCode, body)
	}
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "mesh-tok") {
		t.Fatalf("token leak: %s", raw)
	}

	// Unauthorized still rejected.
	res2, err := http.Get("http://" + addr + fleetmcp.PeerPathPrefix + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = res2.Body.Close()
	if res2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d", res2.StatusCode)
	}

	// Graceful shutdown must not hang.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := ps.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ps.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not exit after Shutdown")
	}
	// Drain errCh without requiring error.
	select {
	case <-errCh:
	case <-time.After(time.Second):
	}
}

func TestListenPeer_BindFailClosed(t *testing.T) {
	t.Parallel()
	// Occupy a port then try to bind the same address.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	_, err = fleetmcp.ListenPeer(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), fleetmcp.DefaultPeerServerOptions())
	if err == nil {
		t.Fatal("expected bind failure")
	}
}

func TestListenPeer_EmptyAddr(t *testing.T) {
	t.Parallel()
	_, err := fleetmcp.ListenPeer("", http.NotFoundHandler(), fleetmcp.DefaultPeerServerOptions())
	if err == nil {
		t.Fatal("expected error")
	}
}
