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
		{"non-loopback http", `{"schema_version":1,"fleet_id":"x","members":[{"id":"a","peer_url":"http://edge.example.com:9443"}]}`},
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

func TestParseRoster_CacheEligibilityOptional(t *testing.T) {
	t.Parallel()
	// Legacy v1 without cache still loads (ops fan-out path).
	raw := []byte(`{
	  "schema_version": 1,
	  "fleet_id": "corp",
	  "members": [
	    {"id": "ops-only", "peer_url": "https://ops.example:9443"},
	    {
	      "id": "cache-a",
	      "peer_url": "https://a.example:9443",
	      "cache": {
	        "enabled": true,
	        "controller_id": "jenkins-prod",
	        "pool": "jenkins-prod-logs",
	        "capacity_weight": 100,
	        "failure_domain": "zone-a",
	        "protocols": ["fleet-cache/1"]
	      }
	    },
	    {
	      "id": "cache-b",
	      "peer_url": "https://b.example:9443",
	      "cache": {
	        "enabled": true,
	        "controller_id": "jenkins-prod",
	        "pool": "jenkins-prod-logs",
	        "protocols": ["fleet-cache/1"],
	        "draining": true
	      }
	    },
	    {
	      "id": "other-controller",
	      "peer_url": "https://c.example:9443",
	      "cache": {
	        "enabled": true,
	        "controller_id": "jenkins-other",
	        "pool": "jenkins-prod-logs",
	        "protocols": ["fleet-cache/1"]
	      }
	    }
	  ]
	}`)
	r, err := fleetmcp.ParseRoster(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.MemberByID("ops-only").Cache != nil && r.MemberByID("ops-only").Cache.Enabled {
		t.Fatal("ops-only must not be cache-enabled")
	}
	// Default weight when omitted.
	if r.MemberByID("cache-b").Cache.CapacityWeight != fleetmcp.DefaultCacheCapacityWeight {
		t.Fatalf("default weight: %d", r.MemberByID("cache-b").Cache.CapacityWeight)
	}
	elig := r.CacheEligibleMembers("jenkins-prod", "jenkins-prod-logs", fleetmcp.CacheEligibleOptions{
		Protocol: "fleet-cache/1",
	})
	if len(elig) != 1 || elig[0].ID != "cache-a" {
		t.Fatalf("eligible without draining: %+v", elig)
	}
	withDrain := r.CacheEligibleMembers("jenkins-prod", "jenkins-prod-logs", fleetmcp.CacheEligibleOptions{
		Protocol:        "fleet-cache/1",
		IncludeDraining: true,
	})
	if len(withDrain) != 2 {
		t.Fatalf("with drain: %+v", withDrain)
	}
	// Cross-controller never mixed into same eligibility set.
	other := r.CacheEligibleMembers("jenkins-other", "jenkins-prod-logs", fleetmcp.CacheEligibleOptions{
		Protocol: "fleet-cache/1",
	})
	if len(other) != 1 || other[0].ID != "other-controller" {
		t.Fatalf("other: %+v", other)
	}
	// Wrong pool → empty.
	if len(r.CacheEligibleMembers("jenkins-prod", "wrong-pool", fleetmcp.CacheEligibleOptions{Protocol: "fleet-cache/1"})) != 0 {
		t.Fatal("wrong pool")
	}
}

func TestParseRoster_CacheEnabledFailClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
	}{
		{"missing controller", `{
		  "schema_version":1,"fleet_id":"x",
		  "members":[{"id":"a","peer_url":"https://a",
		    "cache":{"enabled":true,"pool":"p","protocols":["fleet-cache/1"]}}]
		}`},
		{"missing pool", `{
		  "schema_version":1,"fleet_id":"x",
		  "members":[{"id":"a","peer_url":"https://a",
		    "cache":{"enabled":true,"controller_id":"c","protocols":["fleet-cache/1"]}}]
		}`},
		{"missing protocols", `{
		  "schema_version":1,"fleet_id":"x",
		  "members":[{"id":"a","peer_url":"https://a",
		    "cache":{"enabled":true,"controller_id":"c","pool":"p"}}]
		}`},
		{"neg weight", `{
		  "schema_version":1,"fleet_id":"x",
		  "members":[{"id":"a","peer_url":"https://a",
		    "cache":{"enabled":true,"controller_id":"c","pool":"p","capacity_weight":-1,"protocols":["fleet-cache/1"]}}]
		}`},
		{"weight too high", `{
		  "schema_version":1,"fleet_id":"x",
		  "members":[{"id":"a","peer_url":"https://a",
		    "cache":{"enabled":true,"controller_id":"c","pool":"p","capacity_weight":100000,"protocols":["fleet-cache/1"]}}]
		}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := fleetmcp.ParseRoster([]byte(tc.raw))
			if err == nil {
				t.Fatal("expected error")
			}
			if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
				t.Fatalf("code: %v", err)
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

// TestLabRosterFile loads the shipped FLC-003 lab roster (real fixture path).
// Lab uses docker DNS hostnames over http — requires AllowInsecureHTTP residual.
func TestLabRosterFile(t *testing.T) {
	t.Parallel()
	// CWD is package dir under go test; walk up to module root.
	root := findModuleRoot(t)
	path := filepath.Join(root, "testdata", "fleet-cache-lab", "roster.json")
	// Strict load must fail (non-loopback http://member-*).
	if _, err := fleetmcp.LoadRosterFile(path); err == nil {
		t.Fatal("expected strict load to reject lab cleartext hostnames")
	}
	r, err := fleetmcp.LoadRosterFileOpts(path, fleetmcp.RosterParseOptions{
		PeerURL: fleetmcp.PeerURLOptions{AllowInsecureHTTP: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.FleetID != "fleet-cache-lab" || len(r.Members) != 3 {
		t.Fatalf("%+v", r)
	}
	elig := r.CacheEligibleMembers("jenkins-lab", "jenkins-lab-logs", fleetmcp.CacheEligibleOptions{
		Protocol: "fleet-cache/1",
	})
	if len(elig) != 3 {
		t.Fatalf("eligible: %+v", elig)
	}
	// Independent member ids for independent data dirs in compose.
	for _, id := range []string{"lab-a", "lab-b", "lab-c"} {
		if r.MemberByID(id) == nil {
			t.Fatalf("missing %s", id)
		}
	}
}

func findModuleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("go.mod not found")
	return ""
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
		ModeFlag:        "true",
		MemberIDFlag:    "missing",
		RosterPathFlag:  path,
		MeshTokenInline: "secret-token",
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
