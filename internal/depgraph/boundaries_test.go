package depgraph_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const modulePath = "github.com/hilather/go-jenkins-mcp"

// Architecture packages that must exist as importable packages (FND-004).
var requiredPackages = []string{
	"internal/app",
	"internal/config",
	"internal/profile",
	"internal/auth",
	"internal/gateway",
	"internal/adapter",
	"internal/keyring",
	"internal/jenkins",
	"internal/capabilities",
	"internal/mcpserver",
	"internal/tools",
	"internal/policy",
	"internal/logmirror",
	"internal/store",
	"internal/store/crypto",
	"internal/archive",
	"internal/search",
	"internal/diagnostics",
	"internal/mutation",
	"internal/redact",
	"internal/audit",
	"internal/telemetry",
	"internal/update",
	"internal/otelx",
	"internal/telemetry/fleet",
	"internal/contracts",
	"internal/apperr",
	"internal/admin",
	"internal/adminops",
	"internal/fleetmcp",
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	// boundaries_test lives in internal/depgraph; module root is ../..
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("go.mod not found at %s: %v", root, err)
	}
	return root
}

func TestRequiredPackagesExist(t *testing.T) {
	root := moduleRoot(t)
	for _, rel := range requiredPackages {
		dir := filepath.Join(root, rel)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Errorf("missing package dir %s: %v", rel, err)
			continue
		}
		hasGo := false
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".go") {
				hasGo = true
				break
			}
		}
		if !hasGo {
			t.Errorf("package %s has no .go files", rel)
		}
	}
}

func goListImports(t *testing.T, root string) map[string][]string {
	t.Helper()
	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PATH="+os.Getenv("PATH"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	dec := json.NewDecoder(&stdout)
	out := make(map[string][]string)
	for dec.More() {
		var p struct {
			ImportPath string
			Imports    []string
		}
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decode go list json: %v", err)
		}
		// Only track first-party packages.
		if !strings.HasPrefix(p.ImportPath, modulePath+"/") && p.ImportPath != modulePath {
			continue
		}
		var imports []string
		for _, imp := range p.Imports {
			if strings.HasPrefix(imp, modulePath+"/") {
				imports = append(imports, imp)
			}
		}
		out[p.ImportPath] = imports
	}
	return out
}

func TestJenkinsDoesNotImportMCPOrTools(t *testing.T) {
	root := moduleRoot(t)
	imports := goListImports(t, root)
	jenkins := modulePath + "/internal/jenkins"
	for _, imp := range imports[jenkins] {
		if strings.Contains(imp, "modelcontextprotocol") ||
			strings.HasSuffix(imp, "/internal/tools") ||
			strings.HasSuffix(imp, "/internal/mcpserver") {
			t.Errorf("jenkins imports forbidden package %s", imp)
		}
	}
	// Also forbid any import path containing mcp sdk for this package.
	for _, imp := range imports[jenkins] {
		if strings.Contains(imp, "/mcp") {
			t.Errorf("jenkins imports mcp-related package %s", imp)
		}
	}
}

func TestToolsDoesNotImportNetHTTP(t *testing.T) {
	// go list Imports includes stdlib. Tools must not construct raw Jenkins HTTP;
	// forbidding net/http keeps handlers on the jenkins client boundary.
	root := moduleRoot(t)
	cmd := exec.Command("go", "list", "-json", "./internal/tools")
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go list tools: %v\n%s", err, stderr.String())
	}
	var p struct {
		ImportPath string
		Imports    []string
	}
	if err := json.NewDecoder(&stdout).Decode(&p); err != nil {
		t.Fatal(err)
	}
	for _, imp := range p.Imports {
		if imp == "net/http" {
			t.Errorf("internal/tools must not import net/http (use jenkins client)")
		}
	}
}

func TestNoInternalImportCycles(t *testing.T) {
	root := moduleRoot(t)
	imports := goListImports(t, root)

	// Build adjacency of first-party packages and detect cycles via DFS.
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int)
	var stack []string
	var cycle []string

	var dfs func(n string) bool
	dfs = func(n string) bool {
		color[n] = gray
		stack = append(stack, n)
		for _, m := range imports[n] {
			if !strings.HasPrefix(m, modulePath) {
				continue
			}
			switch color[m] {
			case gray:
				// cycle
				cycle = append([]string{}, stack...)
				cycle = append(cycle, m)
				return true
			case white:
				if dfs(m) {
					return true
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[n] = black
		return false
	}

	for pkg := range imports {
		if color[pkg] == white {
			if dfs(pkg) {
				t.Fatalf("import cycle detected: %s", strings.Join(cycle, " -> "))
			}
		}
	}
}

// Allowed dependency edges among foundation packages (documented direction).
// Key may import any listed value; imports of unlisted first-party packages fail
// unless they appear here. Empty allow means "no first-party imports yet".
// Leaf infrastructure: contracts, redact have the fewest deps.
func TestDependencyDirection(t *testing.T) {
	root := moduleRoot(t)
	imports := goListImports(t, root)

	// Short names for readability.
	allow := map[string][]string{
		"internal/contracts": {},
		"internal/redact":    {},
		"internal/apperr":    {"internal/redact"},
		// AUTH-001/002/004: providers + whoAmI verify via jenkins client;
		// Wave 28: IdentityReverifyGate optional audit sink (privacy-preserving).
		"internal/auth": {"internal/contracts", "internal/keyring", "internal/apperr", "internal/profile", "internal/jenkins", "internal/audit"},
		// GWY-001/002: AgentCore credential provider + identity → policy.Subject.
		// HOST-007 subject-invalidate residual: optional privacy-preserving audit emit.
		"internal/gateway": {"internal/apperr", "internal/contracts", "internal/policy", "internal/auth", "internal/audit"},
		// GWY-003 lite: offline security/performance qualification harness.
		// Residual-status offline honesty embeds diagnostics.BuildGatewayResidualStatus.
		"internal/gateway/qualify": {"internal/gateway", "internal/apperr", "internal/contracts", "internal/auth", "internal/diagnostics"},
		// INT-001: optional adapters; no Jenkins client by default.
		// INT-003: may use net/http for optional HTTPS JSON backend (stdlib only + apperr).
		"internal/adapter": {"internal/apperr"},
		"internal/keyring": {"internal/apperr"},
		// CFG-001: XDG paths only in config; profile owns schema + store.
		"internal/config":  {},
		"internal/profile": {"internal/contracts", "internal/apperr", "internal/config"},
		// POL-001/002: RO gate + overlay + subjects.
		"internal/policy": {"internal/apperr", "internal/config", "internal/contracts", "internal/jenkins"},
		// LOG-002: progressive state machine may use jenkins + store metadata.
		"internal/logmirror": {"internal/store", "internal/jenkins", "internal/apperr", "internal/archive"},
		// STO-001/002: secure dirs + SQLite metadata; no tools/mcp.
		// ARC-009: optional AEAD lives in store/crypto (stdlib only + apperr).
		// ARC-009: AEAD pure crypto; key load/wiring is cmd (not store→keyring).
		"internal/store":        {"internal/apperr", "internal/store/crypto"},
		"internal/store/crypto": {"internal/apperr"},
		"internal/archive":      {"internal/apperr"},
		"internal/search":       {"internal/store", "internal/apperr"},
		// Wave 34 QA-005: ValidateHTTPConfig pure residual canary (KD-008).
		// Wave 35 UPD-001: doctor update_lkg on-disk re-verify via internal/update.
		// Wave 43 INT-001: offline adapter_framework_residual canary (adapter leaf → apperr only).
		// Wave 46 MGR-002: fleet_telemetry_force_off_residual canary (fleet ForceOff pure offline).
		// Wave 47 UPD-001: update_lkg_residual offline residual honesty canary (update package).
		// Wave 48 MUT-001: mutation_confirm_cooldown_residual offline canary (mutation Manager + audit.Memory).
		// HOST-008: gateway env posture (multi_user / credential_mode / ha residual) for doctor.
		"internal/diagnostics": {"internal/apperr", "internal/redact", "internal/telemetry", "internal/telemetry/fleet", "internal/store", "internal/auth", "internal/profile", "internal/policy", "internal/config", "internal/keyring", "internal/jenkins", "internal/archive", "internal/mcpserver", "internal/update", "internal/adapter", "internal/mutation", "internal/audit", "internal/gateway"},
		"internal/audit":       {"internal/redact"},
		"internal/telemetry":   {"internal/redact"},
		// MGR-002: fleet health export schema, local queue, optional HTTPS exporter.
		"internal/telemetry/fleet": {"internal/apperr", "internal/config", "internal/telemetry"},
		// UPD-001: signed update manifests (stdlib crypto only + apperr/config).
		"internal/update":       {"internal/apperr", "internal/config"},
		"internal/capabilities": {},
		// mcpserver: official MCP SDK + apperr; no jenkins/tools (tools register on *mcp.Server from cmd).
		"internal/mcpserver": {"internal/apperr"},
		// app: serve-time cache maintenance wires store/logmirror/archive/telemetry (ARC-007/005).
		"internal/app": {"internal/apperr", "internal/archive", "internal/logmirror", "internal/store", "internal/telemetry"},
		// jenkins is leaf w.r.t. MCP/tools; may use contracts/apperr later.
		"internal/jenkins": {"internal/apperr"},
		// tools may use jenkins + policy + contracts/apperr; never net/http (checked elsewhere).
		"internal/mutation": {"internal/apperr", "internal/audit", "internal/policy", "internal/redact"},
		// tools may use store Meta for durable survey compact cache (schema v7).
		// Wave 45 Track B: operator_caps_snapshot reports auth + mcpserver constants
		// (identity re-verify TTL bounds, Streamable HTTP MaxBodyBytes); both are
		// cycle-free leaves (auth/mcpserver do not import tools).
		"internal/tools": {"internal/jenkins", "internal/apperr", "internal/contracts", "internal/policy", "internal/audit", "internal/telemetry", "internal/redact", "internal/search", "internal/logmirror", "internal/diagnostics", "internal/mutation", "internal/otelx", "internal/correlate", "internal/store", "internal/auth", "internal/mcpserver", "internal/adminops", "internal/fleetmcp"},
		// depgraph is test-only package for this suite; production imports of it are empty.
		"internal/otelx":     {},
		"internal/correlate": {}, // INT-004 pure extractors (no network, no jenkins).
		"internal/depgraph":  {},
		// UI-002 / ADR 0014: local admin BFF (read path); no MCP tools, no raw Jenkins HTTP.
		// UI-002 / UI-004 / UI-007 / UI-008 / ADR 0014: local admin BFF.
		// UI-007: store for cache quota/evict; auth for credential presence only.
		// UI-008: uiembed for packaged/embedded SPA assets.
		"internal/admin": {
			"internal/admin/uiembed",
			"internal/apperr", "internal/audit", "internal/auth", "internal/config",
			"internal/diagnostics", "internal/keyring", "internal/policy",
			"internal/gateway", "internal/profile", "internal/store", "internal/telemetry",
			"internal/saml", // POL-007 admin SSO SP
		},
		// POL-007: SAML SP pure validation + attribute/role maps (stdlib crypto/xml).
		"internal/saml": {
			"internal/apperr", "internal/auth", "internal/contracts", "internal/policy",
		},
		// MCP-OPS: shared admin day-2 ops for admin_* tools (not HTTP; not MCP SDK).
		"internal/adminops": {
			"internal/admin", "internal/apperr", "internal/audit", "internal/config",
			"internal/diagnostics", "internal/gateway", "internal/policy",
			"internal/profile", "internal/store", "internal/telemetry",
		},
		// Fleet MCP: roster + peer fan-out for fleet_* tools (not multi-pod HA).
		"internal/fleetmcp": {
			"internal/apperr", "internal/diagnostics", "internal/store", "internal/telemetry",
		},
		// UI-008: embed-only SPA assets; stdlib only (no other internal imports).
		"internal/admin/uiembed": {},
		// HOST-012…015: opt-in OAuth lab helpers (stdlib only; no other internal imports).
		"internal/authlab": {},
	}

	for pkgPath, imps := range imports {
		rel := strings.TrimPrefix(pkgPath, modulePath+"/")
		if strings.HasPrefix(rel, "cmd/") {
			// cmd may wire many packages; skip strict allow-list for entrypoints.
			continue
		}
		allowed, known := allow[rel]
		if !known {
			// New internal packages must be added to the allow map deliberately.
			if strings.HasPrefix(rel, "internal/") {
				t.Errorf("package %s not listed in dependency allow map; update FND-004 test", rel)
			}
			continue
		}
		allowSet := map[string]bool{}
		for _, a := range allowed {
			allowSet[a] = true
		}
		for _, imp := range imps {
			impRel := strings.TrimPrefix(imp, modulePath+"/")
			if !strings.HasPrefix(impRel, "internal/") {
				continue
			}
			if !allowSet[impRel] {
				t.Errorf("%s imports %s which is not in its FND-004 allow list %v",
					rel, impRel, allowed)
			}
		}
	}
}

func TestCoreJenkinsPathIndependentOfAdapters(t *testing.T) {
	root := moduleRoot(t)
	imports := goListImports(t, root)
	adapterPkg := modulePath + "/internal/adapter"
	for _, pkg := range []string{
		modulePath + "/internal/jenkins",
		modulePath + "/internal/tools",
		modulePath + "/internal/policy",
		modulePath + "/internal/logmirror",
		modulePath + "/internal/store",
	} {
		for _, imp := range imports[pkg] {
			if imp == adapterPkg {
				t.Errorf("%s must not import internal/adapter (core path independent)", pkg)
			}
		}
	}
	// Adapter must not import jenkins (auth isolation: no Jenkins client by default).
	for _, imp := range imports[adapterPkg] {
		if strings.HasSuffix(imp, "/internal/jenkins") ||
			strings.HasSuffix(imp, "/internal/keyring") ||
			strings.HasSuffix(imp, "/internal/tools") {
			t.Errorf("adapter imports forbidden package %s (auth isolation)", imp)
		}
	}
}
