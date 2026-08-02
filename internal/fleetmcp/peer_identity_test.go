package fleetmcp_test

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
)

func TestValidatePeerURLTransport(t *testing.T) {
	t.Parallel()
	// Loopback http OK.
	if err := fleetmcp.ValidatePeerURLTransport("http://127.0.0.1:9443", fleetmcp.PeerURLOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := fleetmcp.ValidatePeerURLTransport("http://localhost:1", fleetmcp.PeerURLOptions{}); err != nil {
		t.Fatal(err)
	}
	// Non-loopback http fail closed.
	err := fleetmcp.ValidatePeerURLTransport("http://edge.example.com:9443", fleetmcp.PeerURLOptions{})
	if err == nil {
		t.Fatal("expected https required")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "token") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("secret-like error: %v", err)
	}
	// Non-loopback https OK.
	if err := fleetmcp.ValidatePeerURLTransport("https://edge.example.com:9443", fleetmcp.PeerURLOptions{}); err != nil {
		t.Fatal(err)
	}
	// Lab residual allow insecure.
	if err := fleetmcp.ValidatePeerURLTransport("http://edge.example.com:9443", fleetmcp.PeerURLOptions{AllowInsecureHTTP: true}); err != nil {
		t.Fatal(err)
	}
	// Credentials rejected.
	if err := fleetmcp.ValidatePeerURLTransport("https://u:p@h/", fleetmcp.PeerURLOptions{}); err == nil {
		t.Fatal("expected cred reject")
	}
}

func TestParseRoster_RejectsNonLoopbackHTTP(t *testing.T) {
	t.Parallel()
	// Production-shaped cleartext peer must fail closed on default ParseRoster.
	_, err := fleetmcp.ParseRoster([]byte(`{
	  "schema_version":1,"fleet_id":"corp",
	  "members":[{"id":"a","peer_url":"http://edge.example.com:9443"}]
	}`))
	if err == nil {
		t.Fatal("expected non-loopback http reject")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("%v", err)
	}
	// Lab residual opt-in.
	r, err := fleetmcp.ParseRosterOpts([]byte(`{
	  "schema_version":1,"fleet_id":"corp",
	  "members":[{"id":"a","peer_url":"http://edge.example.com:9443"}]
	}`), fleetmcp.RosterParseOptions{PeerURL: fleetmcp.PeerURLOptions{AllowInsecureHTTP: true}})
	if err != nil || r.MemberByID("a") == nil {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestResolveConfig_RejectsNonLoopbackHTTPWithoutLabFlag(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.json")
	raw := `{
	  "schema_version":1,"fleet_id":"corp",
	  "members":[
	    {"id":"edge-a","peer_url":"http://edge.example.com:9443"}
	  ]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := fleetmcp.ResolveConfig(fleetmcp.ResolveOptions{
		ModeFlag:        "1",
		MemberIDFlag:    "edge-a",
		RosterPathFlag:  path,
		MeshTokenInline: "mesh",
	})
	if err == nil {
		t.Fatal("expected production-shaped http peer fail closed")
	}
	// Lab residual.
	cfg, err := fleetmcp.ResolveConfig(fleetmcp.ResolveOptions{
		ModeFlag:              "1",
		MemberIDFlag:          "edge-a",
		RosterPathFlag:        path,
		MeshTokenInline:       "mesh",
		AllowInsecureHTTPFlag: "1",
	})
	if err != nil || !cfg.Enabled || !cfg.AllowInsecureHTTP {
		t.Fatalf("%+v %v", cfg, err)
	}
	if cfg.TrustResidual.UniqueNodeIdentity {
		t.Fatal("must not claim unique node identity Done")
	}
}

func TestDefaultTrustResidual(t *testing.T) {
	t.Parallel()
	tr := fleetmcp.DefaultTrustResidual()
	if !tr.MeshTokenPilot || tr.UniqueNodeIdentity {
		t.Fatalf("%+v", tr)
	}
	if tr.Residual == "" || strings.Contains(strings.ToLower(tr.Residual), "token=") {
		t.Fatalf("%+v", tr)
	}
}

func TestPeerMux_UnauthorizedBodySecretFree(t *testing.T) {
	t.Parallel()
	const mesh = "super-secret-mesh-token-value"
	cfg := fleetmcp.Config{
		Enabled: true, MemberID: "a", MeshToken: mesh,
		Roster: &fleetmcp.Roster{
			SchemaVersion: 1, FleetID: "f",
			Members: []fleetmcp.RosterMember{{ID: "a", PeerURL: "http://127.0.0.1:1"}},
		},
	}
	mux := fleetmcp.NewPeerMux(cfg, &fleetmcp.LocalProvider{})
	ps, _, err := fleetmcp.StartPeerServer("127.0.0.1:0", mux, fleetmcp.DefaultPeerServerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ps.Shutdown(nil) }()

	// Unauthorized request — must 401 and never echo mesh secret.
	res, err := http.Get("http://" + ps.Addr() + fleetmcp.PeerPathPrefix + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d body %s", res.StatusCode, body)
	}
	if strings.Contains(string(body), mesh) || strings.Contains(string(body), "super-secret") {
		t.Fatalf("mesh secret leaked in response: %s", body)
	}
}
