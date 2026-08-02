package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/update"
)

func TestParseGoModRequire(t *testing.T) {
	t.Parallel()
	block := `module example.com/x

go 1.25.0

require (
	github.com/modelcontextprotocol/go-sdk v1.1.0
	github.com/other/dep v0.1.0
)
`
	v, ok := parseGoModRequire(block, mcpSDKModule)
	if !ok || v != "v1.1.0" {
		t.Fatalf("block form: got %q ok=%v", v, ok)
	}

	single := "require github.com/modelcontextprotocol/go-sdk v9.9.9 // comment\n"
	v, ok = parseGoModRequire(single, mcpSDKModule)
	if !ok || v != "v9.9.9" {
		t.Fatalf("single line: got %q ok=%v", v, ok)
	}

	if _, ok := parseGoModRequire("require other v1", mcpSDKModule); ok {
		t.Fatal("expected missing module")
	}
	if _, ok := parseGoModRequire("", mcpSDKModule); ok {
		t.Fatal("empty go.mod")
	}
}

func TestBuildReleaseEvidenceOfflineCore(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "3.1.4", "piecommit", "2026-08-01T00:00:00Z"
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()

	// Isolate LKG path (absent).
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv(update.EnvUpdateLKGPath, filepath.Join(t.TempDir(), "no-lkg.json"))

	goMod := `module github.com/hilather/go-jenkins-mcp

require (
	github.com/modelcontextprotocol/go-sdk v1.1.0
)
`
	ev, err := buildReleaseEvidence(context.Background(), releaseEvidenceOptions{
		Now:                func() time.Time { return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC) },
		GoModContent:       goMod,
		SkipGatewayQualify: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Schema != releaseEvidenceSchemaV2 {
		t.Fatalf("schema %s", ev.Schema)
	}
	if !ev.Offline {
		t.Fatal("expected offline")
	}
	if ev.Version.Version != "3.1.4" || ev.Version.Commit != "piecommit" {
		t.Fatalf("version %+v", ev.Version)
	}
	if ev.MCPSDK == nil || ev.MCPSDK.Version != "v1.1.0" || ev.MCPSDK.Source != "go.mod" {
		t.Fatalf("mcp sdk %+v", ev.MCPSDK)
	}
	if ev.UpdateLKG == nil || ev.UpdateLKG.Present {
		t.Fatalf("expected LKG absent: %+v", ev.UpdateLKG)
	}
	if ev.SecuritySelfCheck == nil || ev.SecuritySelfCheck.IndependentReviewRequired != true {
		t.Fatalf("security self-check snap: %+v", ev.SecuritySelfCheck)
	}
	if ev.GatewayQualify == nil || !ev.GatewayQualify.OK {
		t.Fatalf("gateway qualify: %+v", ev.GatewayQualify)
	}
	// REL residual lite: full gateway residual-status map embedded offline.
	if ev.GatewayResidualStatus == nil {
		t.Fatal("gateway_residual_status missing on offline release-evidence")
	}
	if ev.GatewayResidualStatus["residual_id"] != "oauth009_offline" {
		t.Fatalf("gateway_residual_status.residual_id=%v", ev.GatewayResidualStatus["residual_id"])
	}
	if ev.GatewayResidualStatus["ha_multi_replica"] != false {
		t.Fatal("gateway_residual_status ha_multi_replica must be false")
	}
	if ev.GatewayResidualStatus["gateway_ready"] != false {
		t.Fatal("gateway_ready must be false on residual-status embed (Ready only on serve /readyz)")
	}

	wantChecks := map[string]string{
		"version_metadata":        "pass",
		"version_commit":          "pass",
		"mcp_sdk_pin":             "pass",
		"policy_engine_self_test": "pass",
		"security_self_check":     "", // pass or warn ok
		"update_lkg":              "pass",
		"gateway_qualify_offline": "pass",
		"doctor_offline":          "skip",
		"cache_status":            "skip",
	}
	byID := map[string]releaseCheck{}
	for _, c := range ev.Checks {
		byID[c.ID] = c
	}
	for id, want := range wantChecks {
		c, ok := byID[id]
		if !ok {
			t.Fatalf("missing check %s in %+v", id, ev.Checks)
		}
		if want != "" && c.Status != want {
			t.Fatalf("check %s status=%s want=%s msg=%s", id, c.Status, want, c.Message)
		}
		if want == "" && c.Status != "pass" && c.Status != "warn" {
			t.Fatalf("check %s status=%s (want pass|warn)", id, c.Status)
		}
		if c.GateID == "" && !c.Optional {
			t.Fatalf("core check %s missing gate_id", id)
		}
	}

	// Structured residuals with known ids (include modes residual honesty).
	resIDs := map[string]bool{}
	for _, r := range ev.Residual {
		resIDs[r.ID] = true
		if strings.TrimSpace(r.Message) == "" {
			t.Fatalf("empty residual message for %s", r.ID)
		}
	}
	for _, id := range []string{
		"full_suite", "production_signoff", "live_entra", "gateway_modes_live",
		"multi_user_offline", "oauth009_offline", "oauth010_offline", "progressive_consent_offline",
		"host008_single_replica",
		"stdio_binary_smoke", "cursor_host_ci", "install_operator",
	} {
		if !resIDs[id] {
			t.Fatalf("missing residual %s in %+v", id, ev.Residual)
		}
	}
	// Honesty: stdio_binary_smoke is Done* (optional CI), cursor_host_ci remains open residual.
	// multi_user_offline / oauth009_offline / oauth010_offline / progressive_consent_offline mark Done* foundations;
	// host008 stays single-replica residual. Offline only — not live Entra / multi-user GO.
	var stdioMsg, cursorMsg, multiUserMsg, oauth009Msg, oauth010Msg, progressiveMsg, host008Msg string
	for _, r := range ev.Residual {
		switch r.ID {
		case "stdio_binary_smoke":
			stdioMsg = r.Message
		case "cursor_host_ci":
			cursorMsg = r.Message
		case "multi_user_offline":
			multiUserMsg = r.Message
		case "oauth009_offline":
			oauth009Msg = r.Message
		case "oauth010_offline":
			oauth010Msg = r.Message
		case "progressive_consent_offline":
			progressiveMsg = r.Message
		case "host008_single_replica":
			host008Msg = r.Message
		}
	}
	if !strings.Contains(strings.ToLower(stdioMsg), "done*") {
		t.Fatalf("stdio_binary_smoke should mark Done*: %q", stdioMsg)
	}
	if !strings.Contains(strings.ToLower(cursorMsg), "residual") {
		t.Fatalf("cursor_host_ci should remain residual: %q", cursorMsg)
	}
	if !strings.Contains(strings.ToLower(multiUserMsg), "done*") {
		t.Fatalf("multi_user_offline should mark Done* foundation: %q", multiUserMsg)
	}
	if !strings.Contains(strings.ToLower(multiUserMsg), "pilot") {
		t.Fatalf("multi_user_offline should point pilot checklist: %q", multiUserMsg)
	}
	if !strings.Contains(strings.ToLower(oauth009Msg), "done*") || !strings.Contains(oauth009Msg, "OAUTH-009") {
		t.Fatalf("oauth009_offline honesty: %q", oauth009Msg)
	}
	if !strings.Contains(strings.ToLower(oauth010Msg), "done*") || !strings.Contains(oauth010Msg, "OAUTH-010") {
		t.Fatalf("oauth010_offline honesty: %q", oauth010Msg)
	}
	if !strings.Contains(strings.ToLower(oauth010Msg), "offline") {
		t.Fatalf("oauth010_offline should stress offline-only: %q", oauth010Msg)
	}
	if !strings.Contains(strings.ToLower(progressiveMsg), "done*") || !strings.Contains(strings.ToLower(progressiveMsg), "browser") {
		t.Fatalf("progressive_consent_offline honesty: %q", progressiveMsg)
	}
	if !strings.Contains(strings.ToLower(host008Msg), "single-replica") && !strings.Contains(strings.ToLower(host008Msg), "single replica") {
		t.Fatalf("host008_single_replica honesty: %q", host008Msg)
	}

	// Lite overall: core passes → pass (optional doctor/cache skip does not incomplete).
	if ev.Overall != "pass" && ev.Overall != "warn" {
		t.Fatalf("overall %s (want pass|warn for offline core)", ev.Overall)
	}

	// Must never claim production sign-off in notes/residuals.
	blob, _ := json.Marshal(ev)
	if strings.Contains(strings.ToLower(string(blob)), "production go complete") {
		t.Fatal("must not claim production GO complete")
	}
}

// TestKnownReleaseResidualIDsStable is the pure unit contract for
// scripts/gateway-residual-smoke.sh (opt-in make residual-smoke).
// Asserts REL lite residual honesty ids stay present in knownReleaseResiduals().
// Offline only: these ids document Done* foundations + open live pins — not production GO.
func TestKnownReleaseResidualIDsStable(t *testing.T) {
	t.Parallel()
	// Keep in sync with scripts/gateway-residual-smoke.sh REQUIRED_RESIDUAL_IDS
	// and docs/pilot/checklist.md §0 / docs/release/gates.md residuals.
	required := []string{
		"multi_user_offline",
		"oauth009_offline",
		"oauth010_offline",
		"progressive_consent_offline",
		"host008_single_replica",
		"gateway_modes_live",
	}
	byID := map[string]releaseResidual{}
	for _, r := range knownReleaseResiduals() {
		if strings.TrimSpace(r.ID) == "" {
			t.Fatal("empty residual id in knownReleaseResiduals")
		}
		if strings.TrimSpace(r.Message) == "" {
			t.Fatalf("empty residual message for %s", r.ID)
		}
		if byID[r.ID].ID != "" {
			t.Fatalf("duplicate residual id %s", r.ID)
		}
		byID[r.ID] = r
	}
	for _, id := range required {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("missing residual id %s (smoke script / release gates contract)", id)
		}
		if len(r.GateIDs) == 0 {
			t.Fatalf("residual %s missing gate_ids", id)
		}
	}
	// Message honesty: Done* foundations must not claim live GO; Mode C residuals offline-only.
	assertDoneStarOffline := func(id, mustContain string) {
		t.Helper()
		msg := byID[id].Message
		low := strings.ToLower(msg)
		if !strings.Contains(low, "done*") {
			t.Fatalf("%s should mark Done* offline foundation: %q", id, msg)
		}
		if mustContain != "" && !strings.Contains(msg, mustContain) && !strings.Contains(low, strings.ToLower(mustContain)) {
			t.Fatalf("%s should reference %q: %q", id, mustContain, msg)
		}
	}
	assertDoneStarOffline("multi_user_offline", "multi-user")
	assertDoneStarOffline("oauth009_offline", "OAUTH-009")
	assertDoneStarOffline("oauth010_offline", "OAUTH-010")
	assertDoneStarOffline("progressive_consent_offline", "browser")
	hostMsg := strings.ToLower(byID["host008_single_replica"].Message)
	if !strings.Contains(hostMsg, "single-replica") && !strings.Contains(hostMsg, "single replica") {
		t.Fatalf("host008_single_replica should state single-replica honesty: %q", byID["host008_single_replica"].Message)
	}
	modesMsg := strings.ToLower(byID["gateway_modes_live"].Message)
	if !strings.Contains(modesMsg, "residual") && !strings.Contains(modesMsg, "live") {
		t.Fatalf("gateway_modes_live should mark live modes residual: %q", byID["gateway_modes_live"].Message)
	}
}

// TestParseReleaseEvidenceResidualJSON asserts residual[] ids can be recovered
// from a stable v2 JSON document (same shape as release-evidence --offline).
// Regression: residual honesty ids must remain machine-readable for opt-in smoke.
func TestParseReleaseEvidenceResidualJSON(t *testing.T) {
	t.Parallel()
	// Minimal fixture matching jenkins-mcp.release-evidence.v2 residual shape.
	const fixture = `{
  "schema": "jenkins-mcp.release-evidence.v2",
  "offline": true,
  "overall": "pass",
  "residual": [
    {"id": "multi_user_offline", "gate_ids": ["REL-002.compat.modes"], "message": "Done* foundation; not production multi-user GO"},
    {"id": "oauth009_offline", "gate_ids": ["REL-002.sec.oauth"], "message": "Done* OAUTH-009 offline matrix; live pin residual"},
    {"id": "oauth010_offline", "gate_ids": ["REL-002.sec.oauth"], "message": "Done* OAUTH-010 offline Mode C matrix; live Entra residual"},
    {"id": "progressive_consent_offline", "gate_ids": ["REL-002.compat.modes"], "message": "Done* progressive consent metadata; browser 3LO not automated"},
    {"id": "host008_single_replica", "gate_ids": ["REL-002.compat.gateway"], "message": "HOST-008 single-replica default; multi-replica residual"},
    {"id": "gateway_modes_live", "gate_ids": ["REL-002.compat.modes"], "message": "Live modes A/B/C residual unless pilot matrix records cohorts"}
  ]
}`
	var ev releaseEvidence
	if err := json.Unmarshal([]byte(fixture), &ev); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if ev.Schema != releaseEvidenceSchemaV2 {
		t.Fatalf("schema %q", ev.Schema)
	}
	if !ev.Offline {
		t.Fatal("offline")
	}
	got := map[string]string{}
	for _, r := range ev.Residual {
		got[r.ID] = r.Message
	}
	for _, id := range []string{
		"multi_user_offline", "oauth009_offline", "oauth010_offline", "progressive_consent_offline",
		"host008_single_replica", "gateway_modes_live",
	} {
		msg, ok := got[id]
		if !ok || strings.TrimSpace(msg) == "" {
			t.Fatalf("missing or empty residual %s in parsed fixture: %+v", id, got)
		}
	}
	// Round-trip residual slice from knownReleaseResiduals via JSON.
	raw, err := json.Marshal(struct {
		Residual []releaseResidual `json:"residual"`
	}{Residual: knownReleaseResiduals()})
	if err != nil {
		t.Fatal(err)
	}
	var wrap struct {
		Residual []releaseResidual `json:"residual"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range wrap.Residual {
		ids[r.ID] = true
	}
	for _, id := range []string{
		"multi_user_offline", "oauth009_offline", "oauth010_offline", "progressive_consent_offline",
		"host008_single_replica", "gateway_modes_live",
	} {
		if !ids[id] {
			t.Fatalf("round-trip missing residual %s", id)
		}
	}
}

func TestBuildReleaseEvidenceUnknownVersionWarn(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "unknown", "unknown", ""
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()
	t.Setenv(update.EnvUpdateLKGPath, filepath.Join(t.TempDir(), "absent.json"))

	ev, err := buildReleaseEvidence(context.Background(), releaseEvidenceOptions{
		GoModContent:       "require github.com/modelcontextprotocol/go-sdk v1.1.0\n",
		SkipGatewayQualify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Overall != "warn" {
		t.Fatalf("overall %s want warn", ev.Overall)
	}
	var verCheck, commitCheck releaseCheck
	for _, c := range ev.Checks {
		if c.ID == "version_metadata" {
			verCheck = c
		}
		if c.ID == "version_commit" {
			commitCheck = c
		}
	}
	if verCheck.Status != "warn" || commitCheck.Status != "warn" {
		t.Fatalf("version=%s commit=%s", verCheck.Status, commitCheck.Status)
	}
}

func TestBuildReleaseEvidenceLKGPresent(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "1.0.0", "abc", "t"
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()

	dir := t.TempDir()
	lkgPath := filepath.Join(dir, "last_known_good.json")
	rec := update.LKGRecord{
		SchemaVersion:  update.LKGSchemaVersion,
		Version:        "1.2.3",
		Channel:        "stable",
		ArtifactSHA256: strings.Repeat("ab", 32),
		PathBasename:   "jenkins-mcp",
		Timestamp:      "2026-08-01T00:00:00Z",
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lkgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(update.EnvUpdateLKGPath, lkgPath)

	ev, err := buildReleaseEvidence(context.Background(), releaseEvidenceOptions{
		GoModContent:       "require github.com/modelcontextprotocol/go-sdk v1.1.0\n",
		SkipGatewayQualify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.UpdateLKG == nil || !ev.UpdateLKG.Present || ev.UpdateLKG.Version != "1.2.3" {
		t.Fatalf("LKG snap %+v", ev.UpdateLKG)
	}
	found := false
	for _, c := range ev.Checks {
		if c.ID == "update_lkg" && c.Status == "pass" && strings.Contains(c.Message, "present") {
			found = true
		}
	}
	if !found {
		t.Fatalf("update_lkg check: %+v", ev.Checks)
	}
}

func TestReleaseEvidenceOfflineCLI(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "3.1.4", "pie", "t"
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()
	t.Setenv(update.EnvUpdateLKGPath, filepath.Join(t.TempDir(), "no-lkg.json"))

	out := captureStdout(t, func() {
		if err := runReleaseEvidence([]string{"--offline"}); err != nil {
			t.Fatal(err)
		}
	})
	var ev releaseEvidence
	if err := json.Unmarshal([]byte(out), &ev); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if ev.Schema != releaseEvidenceSchemaV2 {
		t.Fatalf("schema %s", ev.Schema)
	}
	if ev.Version.Version != "3.1.4" {
		t.Fatalf("%+v", ev.Version)
	}
	// Secret canary on CLI output.
	if strings.Contains(strings.ToLower(out), "authorization: bearer") {
		t.Fatal("must not contain bearer material")
	}
	if strings.Contains(out, "BEGIN PRIVATE KEY") {
		t.Fatal("must not contain private key material")
	}
	// Structured residual about make test.
	found := false
	for _, r := range ev.Residual {
		if r.ID == "full_suite" && strings.Contains(r.Message, "make test") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected full_suite residual: %+v", ev.Residual)
	}
	// Policy + security checks present.
	ids := map[string]bool{}
	for _, c := range ev.Checks {
		ids[c.ID] = true
	}
	for _, id := range []string{"policy_engine_self_test", "security_self_check", "mcp_sdk_pin", "update_lkg"} {
		if !ids[id] {
			t.Fatalf("missing check %s", id)
		}
	}
}

func TestReleaseEvidenceOutputFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "release-evidence.json")
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "0.0.1", "x", "t"
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()
	t.Setenv(update.EnvUpdateLKGPath, filepath.Join(t.TempDir(), "no-lkg.json"))

	if err := runReleaseEvidence([]string{"--offline", "--output", path}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Mode is secret-free file (0600 recommended).
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("expected owner-only perms, got %o", st.Mode().Perm())
	}
	var ev releaseEvidence
	if err := json.Unmarshal(b, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Version.Version != "0.0.1" {
		t.Fatalf("%+v", ev.Version)
	}
	if ev.Schema != releaseEvidenceSchemaV2 {
		t.Fatalf("schema %s", ev.Schema)
	}
	if err := assertReleaseEvidenceSecretFree(b); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseEvidenceSecretCanaryRejectsPayload(t *testing.T) {
	t.Parallel()
	// Regression: secret canary must fail closed on authorization material.
	bad := []byte(`{"message":"Authorization: Bearer super-secret-token"}`)
	if err := assertReleaseEvidenceSecretFree(bad); err == nil {
		t.Fatal("expected secret canary failure")
	}
	ok := []byte(`{"message":"security self-check overall=ok"}`)
	if err := assertReleaseEvidenceSecretFree(ok); err != nil {
		t.Fatal(err)
	}
}

func TestAggregateReleaseOverallOptionalSkip(t *testing.T) {
	t.Parallel()
	checks := []releaseCheck{
		{ID: "version_metadata", Status: "pass"},
		{ID: "policy_engine_self_test", Status: "pass"},
		{ID: "doctor_offline", Status: "skip", Optional: true},
		{ID: "cache_status", Status: "skip", Optional: true},
	}
	if got := aggregateReleaseOverall(checks); got != "pass" {
		t.Fatalf("got %s want pass", got)
	}
	checks = append(checks, releaseCheck{ID: "security_self_check", Status: "fail"})
	if got := aggregateReleaseOverall(checks); got != "fail" {
		t.Fatalf("got %s want fail", got)
	}
	warnOnly := []releaseCheck{
		{ID: "version_metadata", Status: "warn"},
		{ID: "policy", Status: "pass"},
	}
	if got := aggregateReleaseOverall(warnOnly); got != "warn" {
		t.Fatalf("got %s want warn", got)
	}
}

func TestKnownReleaseResidualsHonesty(t *testing.T) {
	t.Parallel()
	rs := knownReleaseResiduals()
	if len(rs) < 4 {
		t.Fatalf("expected structured residuals, got %d", len(rs))
	}
	joined := ""
	for _, r := range rs {
		joined += r.Message + " "
		if len(r.GateIDs) == 0 {
			t.Fatalf("residual %s missing gate_ids", r.ID)
		}
	}
	// Honesty: not claiming full production.
	if !strings.Contains(joined, "not production sign-off") && !strings.Contains(joined, "go/no-go") {
		t.Fatalf("residuals should deny production sign-off claim: %s", joined)
	}
}

// TestBuildReleaseEvidence_GatewayResidualStatusEmbed asserts REL residual lite:
// release-evidence --offline embeds the same secret-free map as CLI
// `gateway residual-status` (diagnostics.BuildGatewayResidualStatus) under
// gateway_residual_status. Offline only — not live multi-user / Entra GO.
func TestBuildReleaseEvidence_GatewayResidualStatusEmbed(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "3.1.4", "piecommit", "2026-08-01T00:00:00Z"
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()

	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv(update.EnvUpdateLKGPath, filepath.Join(t.TempDir(), "no-lkg.json"))

	// Plant canaries that residual builder / scrub must never echo.
	const canary = "REL_EVIDENCE_RESIDUAL_CANARY_super-secret-token-xyz"
	t.Setenv("HOST_RELEASE_EVIDENCE_RESIDUAL_CANARY", canary)

	// Closed getenv: Mode B multi-user offline honesty without ambient process noise.
	getenv := func(k string) string {
		switch k {
		case "JENKINS_MCP_GATEWAY_MULTI_USER":
			return "1"
		case "JENKINS_MCP_GATEWAY_CREDENTIAL_MODE":
			return "jwt_rs_bearer"
		case "KUBERNETES_SERVICE_HOST", "JENKINS_MCP_GATEWAY_REPLICAS", "REPLICAS":
			return ""
		case "JENKINS_MCP_GATEWAY_VAULT_PATH", "JENKINS_MCP_GATEWAY_JWT_VAULT_PATH",
			"JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH", "JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH",
			"JENKINS_MCP_GATEWAY_JWKS_CACHE_PATH":
			return ""
		default:
			return ""
		}
	}

	goMod := `module github.com/hilather/go-jenkins-mcp

require (
	github.com/modelcontextprotocol/go-sdk v1.1.0
)
`
	ev, err := buildReleaseEvidence(context.Background(), releaseEvidenceOptions{
		Now:                func() time.Time { return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC) },
		GoModContent:       goMod,
		SkipGatewayQualify: true,
		Getenv:             getenv,
	})
	if err != nil {
		t.Fatal(err)
	}
	grs := ev.GatewayResidualStatus
	if grs == nil {
		t.Fatal("gateway_residual_status required on offline release-evidence")
	}
	if grs["residual_id"] != "oauth009_offline" {
		t.Fatalf("residual_id=%v", grs["residual_id"])
	}
	if grs["oauth009_offline"] != true {
		t.Fatalf("oauth009_offline=%v", grs["oauth009_offline"])
	}
	if grs["mode_b_enabled"] != true {
		t.Fatalf("mode_b_enabled=%v", grs["mode_b_enabled"])
	}
	if grs["multi_user_enabled"] != true {
		t.Fatalf("multi_user_enabled=%v", grs["multi_user_enabled"])
	}
	if grs["ha_multi_replica"] != false {
		t.Fatal("ha_multi_replica must be false")
	}
	if grs["gateway_ready"] != false {
		t.Fatal("gateway_ready must be false on residual embed")
	}
	if grs["mode_a_live_obtain_qualified"] != false ||
		grs["mode_b_live_rs_qualified"] != false ||
		grs["mode_c_live_agentcore_qualified"] != false {
		t.Fatalf("live mode pins must stay false: %+v", grs)
	}
	if grs["multi_pod_vault_residual"] != true {
		t.Fatal("multi_pod_vault_residual always true")
	}
	// residual_ids list honesty.
	idSet := map[string]bool{}
	switch v := grs["residual_ids"].(type) {
	case []string:
		for _, id := range v {
			idSet[id] = true
		}
	case []any:
		for _, id := range v {
			if s, ok := id.(string); ok {
				idSet[s] = true
			}
		}
	default:
		t.Fatalf("residual_ids type %T: %+v", grs["residual_ids"], grs["residual_ids"])
	}
	for _, want := range []string{
		"multi_user_offline", "oauth009_offline", "oauth010_offline",
		"progressive_consent_offline", "host008_single_replica", "gateway_modes_live",
	} {
		if !idSet[want] {
			t.Errorf("residual_ids missing %q: %+v", want, grs["residual_ids"])
		}
	}
	note, _ := grs["residual_note"].(string)
	doc, _ := grs["doc"].(string)
	if !strings.Contains(note, "live-pin-blockers") && !strings.Contains(doc, "live-pin-blockers") {
		t.Fatalf("want live-pin-blockers pointer: note=%q doc=%q", note, doc)
	}

	// Secret-free canaries on full document + residual map (JSON marshal path).
	scrubReleaseEvidence(ev)
	blob, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := assertReleaseEvidenceSecretFree(blob); err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	for _, bad := range []string{
		canary,
		"access_token=",
		"refresh_token=",
		"client_secret=",
		"Authorization: Bearer",
		"production go complete",
		"BEGIN PRIVATE KEY",
	} {
		if strings.Contains(strings.ToLower(s), strings.ToLower(bad)) {
			t.Fatalf("forbidden %q in release-evidence JSON (gateway_residual_status canary)", bad)
		}
	}
	// Nested key must appear in JSON.
	if !strings.Contains(s, `"gateway_residual_status"`) {
		t.Fatal("JSON must include gateway_residual_status key")
	}
	if !strings.Contains(s, `"oauth009_offline"`) {
		t.Fatal("JSON residual map must mention oauth009_offline")
	}
}

// TestReleaseEvidenceCLI_GatewayResidualStatusJSON asserts the CLI path emits
// gateway_residual_status under the offline evidence document (secret-free).
func TestReleaseEvidenceCLI_GatewayResidualStatusJSON(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	version, commit, buildTime = "3.1.4", "pie", "t"
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()
	t.Setenv(update.EnvUpdateLKGPath, filepath.Join(t.TempDir(), "no-lkg.json"))

	out := captureStdout(t, func() {
		if err := runReleaseEvidence([]string{"--offline"}); err != nil {
			t.Fatal(err)
		}
	})
	var ev releaseEvidence
	if err := json.Unmarshal([]byte(out), &ev); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if ev.GatewayResidualStatus == nil {
		t.Fatal("CLI release-evidence must embed gateway_residual_status")
	}
	if ev.GatewayResidualStatus["ha_multi_replica"] != false {
		t.Fatal("ha_multi_replica must be false")
	}
	if ev.GatewayResidualStatus["residual_id"] != "oauth009_offline" {
		t.Fatalf("residual_id=%v", ev.GatewayResidualStatus["residual_id"])
	}
	if strings.Contains(strings.ToLower(out), "authorization: bearer") {
		t.Fatal("must not contain bearer material")
	}
	if strings.Contains(out, "BEGIN PRIVATE KEY") {
		t.Fatal("must not contain private key material")
	}
	if strings.Contains(strings.ToLower(out), "production go complete") {
		t.Fatal("must not claim production GO complete")
	}
}

// TestScrubResidualStatusMapDropsSecretKeys is a Regression: planted secret-shaped
// keys and string canaries must not survive scrub before evidence write.
func TestScrubResidualStatusMapDropsSecretKeys(t *testing.T) {
	t.Parallel()
	// Regression: residual embed scrub must drop secret keys and redact values.
	// Wave 15: shared_token_cache_file residual honesty bool must survive scrub
	// (naive "token" substring must not drop it).
	in := map[string]any{
		"residual_id":                 "oauth009_offline",
		"ha_multi_replica":            false,
		"shared_token_cache_file":     true,
		"shared_api_token_vault_file": true,
		"shared_jwt_vault_file":       false,
		"shared_jwks_file":            false,
		"access_token":                "should-drop",
		"client_secret":               "should-drop",
		"authorization":               "Bearer drop-me",
		"token_cache_path":            "/secret/path/token.json",
		"residual_note":               "see docs/gateway/live-pin-blockers.md",
		"nested":                      map[string]any{"password": "nope", "ok": "live-pin-blockers"},
	}
	out := scrubResidualStatusMap(in)
	if _, ok := out["access_token"]; ok {
		t.Fatal("access_token must be dropped")
	}
	if _, ok := out["client_secret"]; ok {
		t.Fatal("client_secret must be dropped")
	}
	if _, ok := out["authorization"]; ok {
		t.Fatal("authorization must be dropped")
	}
	if _, ok := out["token_cache_path"]; ok {
		t.Fatal("token_cache_path must be dropped (path residual never dumped)")
	}
	if out["shared_token_cache_file"] != true {
		t.Fatalf("Regression: shared_token_cache_file residual honesty bool dropped by scrub: %+v", out["shared_token_cache_file"])
	}
	if out["shared_api_token_vault_file"] != true {
		t.Fatalf("Regression: shared_api_token_vault_file residual honesty bool dropped by scrub: %+v", out["shared_api_token_vault_file"])
	}
	if out["shared_jwt_vault_file"] != false {
		t.Fatalf("shared_jwt_vault_file: %+v", out["shared_jwt_vault_file"])
	}
	if out["shared_jwks_file"] != false {
		t.Fatalf("shared_jwks_file: %+v", out["shared_jwks_file"])
	}
	if out["residual_id"] != "oauth009_offline" {
		t.Fatalf("residual_id=%v", out["residual_id"])
	}
	nested, _ := out["nested"].(map[string]any)
	if nested == nil {
		t.Fatal("nested map missing")
	}
	if _, ok := nested["password"]; ok {
		t.Fatal("nested password must be dropped")
	}
	if nested["ok"] != "live-pin-blockers" {
		t.Fatalf("nested ok=%v", nested["ok"])
	}
}
