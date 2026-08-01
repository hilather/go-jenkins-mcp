package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/update"
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

	goMod := `module github.com/simonfxr/go-jenkins-mcp

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
		"multi_user_offline", "oauth009_offline", "host008_single_replica",
		"stdio_binary_smoke", "cursor_host_ci", "install_operator",
	} {
		if !resIDs[id] {
			t.Fatalf("missing residual %s in %+v", id, ev.Residual)
		}
	}
	// Honesty: stdio_binary_smoke is Done* (optional CI), cursor_host_ci remains open residual.
	// multi_user_offline / oauth009_offline mark Done* foundations; host008 stays single-replica residual.
	var stdioMsg, cursorMsg, multiUserMsg, oauth009Msg, host008Msg string
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
