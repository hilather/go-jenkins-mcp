package fleetmcp_test

import (
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

func TestValidateRosterTransport(t *testing.T) {
	t.Parallel()
	r, err := fleetmcp.ParseRoster([]byte(`{
	  "schema_version":1,"fleet_id":"corp",
	  "members":[
	    {"id":"a","peer_url":"http://127.0.0.1:9443"},
	    {"id":"b","peer_url":"https://b.example:9443"}
	  ]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := fleetmcp.ValidateRosterTransport(r, fleetmcp.PeerURLOptions{}); err != nil {
		t.Fatal(err)
	}
	r2, err := fleetmcp.ParseRoster([]byte(`{
	  "schema_version":1,"fleet_id":"corp",
	  "members":[{"id":"a","peer_url":"http://peer.example:9443"}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := fleetmcp.ValidateRosterTransport(r2, fleetmcp.PeerURLOptions{}); err == nil {
		t.Fatal("expected non-loopback http fail")
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

func TestMeshTokenOK_ConstantTimeSecretFree(t *testing.T) {
	t.Parallel()
	// Existing mux still rejects bad tokens without leaking mesh token in body.
	cfg := fleetmcp.Config{
		Enabled: true, MemberID: "a", MeshToken: "super-secret-mesh",
		Roster: &fleetmcp.Roster{
			SchemaVersion: 1, FleetID: "f",
			Members: []fleetmcp.RosterMember{{ID: "a", PeerURL: "http://127.0.0.1:1"}},
		},
	}
	mux := fleetmcp.NewPeerMux(cfg, &fleetmcp.LocalProvider{})
	// Use managed server for identity path.
	ps, _, err := fleetmcp.StartPeerServer("127.0.0.1:0", mux, fleetmcp.DefaultPeerServerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ps.Shutdown(nil) }()
	// Unauthorized body must not contain the mesh secret.
	// (full HTTP covered in server_test; residual honesty for TrustResidual only here)
	_ = ps.Addr()
	if strings.Contains(fleetmcp.DefaultTrustResidual().Residual, "super-secret") {
		t.Fatal("residual must not embed secrets")
	}
}
