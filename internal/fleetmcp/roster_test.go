package fleetmcp_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
)

func TestParseRoster_Valid(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
	  "schema_version": 1,
	  "fleet_id": "corp",
	  "bundle_seq": 3,
	  "members": [
	    {"id": "a", "peer_url": "https://a.example:9443", "profile_id": "site-a"},
	    {"id": "b", "peer_url": "http://127.0.0.1:9444", "profile_id": "site-b"}
	  ]
	}`)
	r, err := fleetmcp.ParseRoster(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.FleetID != "corp" || len(r.Members) != 2 {
		t.Fatalf("%+v", r)
	}
	if r.MemberByID("a") == nil || r.MemberByID("missing") != nil {
		t.Fatal("MemberByID")
	}
	peers := r.PeerMembers("a")
	if len(peers) != 1 || peers[0].ID != "b" {
		t.Fatalf("peers: %+v", peers)
	}
}

func TestParseRoster_Reject(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ``},
		{"bad schema", `{"schema_version":2,"fleet_id":"x","members":[{"id":"a","peer_url":"https://a"}]}`},
		{"no fleet id", `{"schema_version":1,"fleet_id":"","members":[{"id":"a","peer_url":"https://a"}]}`},
		{"no members", `{"schema_version":1,"fleet_id":"x","members":[]}`},
		{"dup id", `{"schema_version":1,"fleet_id":"x","members":[{"id":"a","peer_url":"https://a"},{"id":"a","peer_url":"https://b"}]}`},
		{"cred url", `{"schema_version":1,"fleet_id":"x","members":[{"id":"a","peer_url":"https://u:p@h/"}]}`},
		{"bad scheme", `{"schema_version":1,"fleet_id":"x","members":[{"id":"a","peer_url":"ftp://h"}]}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := fleetmcp.ParseRoster([]byte(tc.raw))
			if err == nil {
				t.Fatal("expected error")
			}
			if apperr.CodeOf(err) == "" {
				t.Fatalf("typed: %v", err)
			}
		})
	}
}

func TestLoadRosterFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.json")
	if err := os.WriteFile(path, []byte(`{
	  "schema_version": 1,
	  "fleet_id": "corp",
	  "members": [{"id":"a","peer_url":"https://a.example"}]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := fleetmcp.LoadRosterFile(path)
	if err != nil || r.MemberByID("a") == nil {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestResolveConfig_OffAndFailClosed(t *testing.T) {
	t.Parallel()
	cfg, err := fleetmcp.ResolveConfig(fleetmcp.ResolveOptions{ModeFlag: ""})
	if err != nil || cfg.Enabled {
		t.Fatalf("off: %+v %v", cfg, err)
	}
	// Mode on but incomplete.
	_, err = fleetmcp.ResolveConfig(fleetmcp.ResolveOptions{
		ModeFlag:     "1",
		MemberIDFlag: "a",
	})
	if err == nil || !strings.Contains(err.Error(), "roster") {
		t.Fatalf("want roster error: %v", err)
	}
}

func TestResolveConfig_Valid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.json")
	raw := `{
	  "schema_version": 1,
	  "fleet_id": "corp",
	  "members": [
	    {"id":"edge-a","peer_url":"https://a.example:9443"},
	    {"id":"edge-b","peer_url":"https://b.example:9443"}
	  ]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	// Wrong member id.
	_, err := fleetmcp.ResolveConfig(fleetmcp.ResolveOptions{
		ModeFlag:         "true",
		MemberIDFlag:     "missing",
		RosterPathFlag:   path,
		MeshTokenInline:  "secret-token",
	})
	if err == nil {
		t.Fatal("expected missing member")
	}
	// No trust.
	_, err = fleetmcp.ResolveConfig(fleetmcp.ResolveOptions{
		ModeFlag:       "1",
		MemberIDFlag:   "edge-a",
		RosterPathFlag: path,
	})
	if err == nil || !strings.Contains(err.Error(), "mesh") {
		t.Fatalf("trust: %v", err)
	}
	cfg, err := fleetmcp.ResolveConfig(fleetmcp.ResolveOptions{
		ModeFlag:        "1",
		MemberIDFlag:    "edge-a",
		RosterPathFlag:  path,
		MeshTokenInline: "mesh-secret",
		PeerListenFlag:  "127.0.0.1:9443",
	})
	if err != nil || !cfg.Enabled || cfg.MemberID != "edge-a" {
		t.Fatalf("%+v %v", cfg, err)
	}
	if !cfg.TrustConfigured || cfg.Roster.FleetID != "corp" {
		t.Fatalf("%+v", cfg)
	}
}
