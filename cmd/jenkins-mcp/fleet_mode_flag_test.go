package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
)

// Regression: bare --fleet-mode must enable mode and must not steal the next
// flag as its value (String flag bug: --fleet-mode --fleet-member-id edge-a).
func TestFleetModeCLI_BareFlagEnablesAndPreservesMemberID(t *testing.T) {
	fs := flag.NewFlagSet("serve-fleet-regression", flag.ContinueOnError)
	fleetMode := fs.Bool("fleet-mode", false, "")
	memberID := fs.String("fleet-member-id", "", "")
	roster := fs.String("fleet-roster", "", "")
	// Documented-style argv (agent-usage / fleet-mcp-ops).
	args := []string{
		"--fleet-mode",
		"--fleet-member-id", "edge-a",
		"--fleet-roster", "/etc/jenkins-mcp/fleet/roster.json",
	}
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !*fleetMode {
		t.Fatal("bare --fleet-mode must set Bool true")
	}
	if *memberID != "edge-a" {
		t.Fatalf("member-id stolen by fleet-mode string flag: got %q", *memberID)
	}
	if *roster != "/etc/jenkins-mcp/fleet/roster.json" {
		t.Fatalf("roster: %q", *roster)
	}
	// Same mapping serve uses into ResolveConfig.
	if fleetModeResolveFlag(*fleetMode) != "1" {
		t.Fatal("resolve flag mapping")
	}
}

func TestFleetModeResolveFlag_EnvStillWorksWhenCLIUnset(t *testing.T) {
	if fleetModeResolveFlag(false) != "" {
		t.Fatal("unset CLI must leave ModeFlag empty for env fallback")
	}
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
	// Documented path: CLI bool true + member + roster + mesh token → Enabled.
	cfg, err := fleetmcp.ResolveConfig(fleetmcp.ResolveOptions{
		ModeFlag:        fleetModeResolveFlag(true),
		MemberIDFlag:    "edge-a",
		RosterPathFlag:  path,
		MeshTokenInline: "mesh-secret",
	})
	if err != nil || !cfg.Enabled {
		t.Fatalf("documented enable path: %+v %v", cfg, err)
	}
	// CLI false + env enable.
	cfg, err = fleetmcp.ResolveConfig(fleetmcp.ResolveOptions{
		ModeFlag:        fleetModeResolveFlag(false),
		MemberIDFlag:    "edge-a",
		RosterPathFlag:  path,
		MeshTokenInline: "mesh-secret",
		Getenv: func(k string) string {
			if k == fleetmcp.EnvFleetMode {
				return "1"
			}
			return ""
		},
	})
	if err != nil || !cfg.Enabled {
		t.Fatalf("env enable with CLI unset: %+v %v", cfg, err)
	}
	// CLI false + env unset → off (not error).
	cfg, err = fleetmcp.ResolveConfig(fleetmcp.ResolveOptions{
		ModeFlag: fleetModeResolveFlag(false),
		Getenv:   func(string) string { return "" },
	})
	if err != nil || cfg.Enabled {
		t.Fatalf("default off: %+v %v", cfg, err)
	}
}

func TestFleetModeEnvTruthy(t *testing.T) {
	if !fleetModeEnvTruthy("1") || !fleetModeEnvTruthy("true") {
		t.Fatal("truthy")
	}
	if fleetModeEnvTruthy("") || fleetModeEnvTruthy("0") || fleetModeEnvTruthy("false") {
		t.Fatal("falsy")
	}
}
