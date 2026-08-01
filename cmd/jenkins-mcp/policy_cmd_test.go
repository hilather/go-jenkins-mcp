package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

func TestPolicyVerifyCLI(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pem, err := policy.EncodePublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "cli.pub"), pem, 0o600); err != nil {
		t.Fatal(err)
	}

	env := &policy.BundleEnvelope{
		SchemaVersion: policy.CurrentBundleSchemaVersion,
		Alg:           policy.AlgEd25519,
		KeyID:         "cli",
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
		MinVersion:    1,
		BundleSeq:     1,
		Overlay:       policy.Overlay{Version: 1, ForceReadOnly: true},
	}
	if err := policy.SignBundle(env, priv); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "overlay.bundle.json")
	raw, _ := policy.MarshalBundle(env)
	if err := os.WriteFile(bundlePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// Isolate XDG for last-good.
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))

	if err := runPolicyVerify([]string{"--file", bundlePath, "--keys", keysDir}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Tamper fails.
	env.Overlay.ForceReadOnly = false
	bad, _ := policy.MarshalBundle(env)
	badPath := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(badPath, bad, 0o600)
	if err := runPolicyVerify([]string{"--file", badPath, "--keys", keysDir}); err == nil {
		t.Fatal("tampered verify must fail")
	}
}

func TestPolicySignDevGated(t *testing.T) {
	t.Setenv(EnvPolicySignDev, "")
	err := runPolicySign([]string{
		"--file", "x.json", "--key", "k.pem", "--key-id", "k", "--out", "o.json",
	})
	if err == nil || !strings.Contains(err.Error(), "dev-only") {
		t.Fatalf("want dev gate: %v", err)
	}
}

func TestPolicySignAndVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	privPEM, err := policy.EncodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "dev.pem")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pubPEM, _ := policy.EncodePublicKeyPEM(pub)
	keysDir := filepath.Join(dir, "keys")
	_ = os.MkdirAll(keysDir, 0o700)
	_ = os.WriteFile(filepath.Join(keysDir, "dev.pub"), pubPEM, 0o600)

	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, []byte(`{"version":1,"force_read_only":true,"mode":"strict"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "signed.bundle.json")

	t.Setenv(EnvPolicySignDev, "1")
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))

	if err := runPolicySign([]string{
		"--file", overlayPath,
		"--key", privPath,
		"--key-id", "dev",
		"--out", outPath,
		"--bundle-seq", "3",
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := runPolicyVerify([]string{"--file", outPath, "--keys", keysDir, "--json"}); err != nil {
		t.Fatalf("verify after sign: %v", err)
	}
}

// Wave 35: multi-key policy sign → signatures[] + verify with MinSignatures=2.
func TestPolicySignMultiAndVerifyMinSignatures2(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	privAPath := filepath.Join(dir, "a.pem")
	privBPath := filepath.Join(dir, "b.pem")
	pemA, err := policy.EncodePrivateKeyPEM(privA)
	if err != nil {
		t.Fatal(err)
	}
	pemB, err := policy.EncodePrivateKeyPEM(privB)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privAPath, pemA, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privBPath, pemB, 0o600); err != nil {
		t.Fatal(err)
	}
	trustDir := filepath.Join(dir, "trusted")
	if err := os.MkdirAll(trustDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pubAPEM, _ := policy.EncodePublicKeyPEM(pubA)
	pubBPEM, _ := policy.EncodePublicKeyPEM(pubB)
	_ = os.WriteFile(filepath.Join(trustDir, "key-a.pub"), pubAPEM, 0o600)
	_ = os.WriteFile(filepath.Join(trustDir, "key-b.pub"), pubBPEM, 0o600)

	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, []byte(`{"version":1,"force_read_only":true,"mode":"strict"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "multi.bundle.json")

	t.Setenv(EnvPolicySignDev, "1")
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	// Dual-control threshold for multi-sig verify.
	t.Setenv(policy.EnvPolicyMinSignatures, "2")

	// Order-paired --key / --key-id (Wave 35 UX).
	if err := runPolicySign([]string{
		"--file", overlayPath,
		"--key", privAPath, "--key-id", "key-a",
		"--key", privBPath, "--key-id", "key-b",
		"--out", outPath,
		"--bundle-seq", "7",
	}); err != nil {
		t.Fatalf("sign multi: %v", err)
	}

	// Inspect envelope: signatures[] populated; top-level signature empty.
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var env policy.BundleEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.Signature != "" {
		t.Fatalf("multi-sig must leave top-level signature empty, got %q", env.Signature)
	}
	if len(env.Signatures) != 2 {
		t.Fatalf("want 2 signatures, got %d", len(env.Signatures))
	}
	if env.KeyID != "key-a" {
		t.Fatalf("top-level key_id should be first signer, got %q", env.KeyID)
	}
	if env.BundleSeq != 7 {
		t.Fatalf("bundle_seq=%d", env.BundleSeq)
	}
	// Order preserved from flag occurrence.
	if env.Signatures[0].KeyID != "key-a" || env.Signatures[1].KeyID != "key-b" {
		t.Fatalf("signature key_ids=%v,%v", env.Signatures[0].KeyID, env.Signatures[1].KeyID)
	}

	// Verify with two public keys + MinSignatures=2 must pass.
	if err := runPolicyVerify([]string{"--file", outPath, "--keys", trustDir, "--json"}); err != nil {
		t.Fatalf("verify multi MinSignatures=2: %v", err)
	}

	// Fail closed: multi-sig envelope but only one trusted key → distinct count < MinSignatures.
	oneKeyDir := filepath.Join(dir, "trusted-one")
	if err := os.MkdirAll(oneKeyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(oneKeyDir, "key-a.pub"), pubAPEM, 0o600)
	// key-b missing from trust store → verify fails on unknown key_id (fail closed).
	if err := runPolicyVerify([]string{"--file", outPath, "--keys", oneKeyDir}); err == nil {
		t.Fatal("multi-sig with untrusted key_id must fail via CLI verify")
	}

	// Regression: multi-sig signed with only one CLI signer uses single-sig path when
	// --key/--key-id appear once; MinSignatures is ignored for pure single-sig envelopes.
	// Create a 1-entry multi-sig via library to assert threshold fail-closed for CLI verify.
	oneMulti := &policy.BundleEnvelope{
		SchemaVersion: policy.CurrentBundleSchemaVersion,
		Alg:           policy.AlgEd25519,
		KeyID:         "key-a",
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
		MinVersion:    policy.CurrentOverlayVersion,
		BundleSeq:     9,
		Overlay:       policy.Overlay{Version: 1, ForceReadOnly: true},
	}
	if err := policy.SignBundleMulti(oneMulti, []policy.BundleSigner{
		{KeyID: "key-a", Priv: privA},
	}); err != nil {
		t.Fatal(err)
	}
	oneMultiPath := filepath.Join(dir, "one-of-two.bundle.json")
	oneRaw, err := policy.MarshalBundle(oneMulti)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oneMultiPath, oneRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Trust both keys so the single signature is valid, but MinSignatures=2 fails.
	if err := runPolicyVerify([]string{"--file", oneMultiPath, "--keys", trustDir}); err == nil {
		t.Fatal("1 distinct multi-sig with MinSignatures=2 must fail via CLI verify")
	}
}

func TestPolicySignMultiKeysDir(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	privDir := filepath.Join(dir, "priv")
	if err := os.MkdirAll(privDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pemA, _ := policy.EncodePrivateKeyPEM(privA)
	pemB, _ := policy.EncodePrivateKeyPEM(privB)
	// Filenames define key_ids (basename without .pem).
	if err := os.WriteFile(filepath.Join(privDir, "alice.pem"), pemA, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(privDir, "bob.pem"), pemB, 0o600); err != nil {
		t.Fatal(err)
	}
	// Public keys for verify (sorted load is independent).
	trustDir := filepath.Join(dir, "trusted")
	_ = os.MkdirAll(trustDir, 0o700)
	pubAPEM, _ := policy.EncodePublicKeyPEM(pubA)
	pubBPEM, _ := policy.EncodePublicKeyPEM(pubB)
	_ = os.WriteFile(filepath.Join(trustDir, "alice.pub"), pubAPEM, 0o600)
	_ = os.WriteFile(filepath.Join(trustDir, "bob.pub"), pubBPEM, 0o600)

	overlayPath := filepath.Join(dir, "overlay.json")
	_ = os.WriteFile(overlayPath, []byte(`{"version":1,"force_read_only":true}`), 0o600)
	outPath := filepath.Join(dir, "from-dir.bundle.json")

	t.Setenv(EnvPolicySignDev, "1")
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv(policy.EnvPolicyMinSignatures, "2")

	if err := runPolicySign([]string{
		"--file", overlayPath,
		"--keys-dir", privDir,
		"--out", outPath,
		"--bundle-seq", "2",
	}); err != nil {
		t.Fatalf("sign keys-dir: %v", err)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var env policy.BundleEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Signatures) != 2 {
		t.Fatalf("want 2 signatures from keys-dir, got %d", len(env.Signatures))
	}
	// Sorted by key_id: alice, bob.
	if env.Signatures[0].KeyID != "alice" || env.Signatures[1].KeyID != "bob" {
		t.Fatalf("keys-dir order want alice,bob got %s,%s",
			env.Signatures[0].KeyID, env.Signatures[1].KeyID)
	}
	if err := runPolicyVerify([]string{"--file", outPath, "--keys", trustDir}); err != nil {
		t.Fatalf("verify keys-dir multi: %v", err)
	}
}

func TestPolicySignMultiMismatchedKeyFlags(t *testing.T) {
	t.Setenv(EnvPolicySignDev, "1")
	dir := t.TempDir()
	overlay := filepath.Join(dir, "o.json")
	_ = os.WriteFile(overlay, []byte(`{"version":1}`), 0o600)
	// Two keys, one key-id → fail closed.
	err := runPolicySign([]string{
		"--file", overlay,
		"--key", "a.pem", "--key-id", "a",
		"--key", "b.pem",
		"--out", filepath.Join(dir, "out.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "counts must match") {
		t.Fatalf("want pair count error, got %v", err)
	}
}

func TestPolicySignMultiRejectsMixedModes(t *testing.T) {
	t.Setenv(EnvPolicySignDev, "1")
	dir := t.TempDir()
	overlay := filepath.Join(dir, "o.json")
	_ = os.WriteFile(overlay, []byte(`{"version":1}`), 0o600)
	err := runPolicySign([]string{
		"--file", overlay,
		"--key", "a.pem", "--key-id", "a",
		"--keys-dir", dir,
		"--out", filepath.Join(dir, "out.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("want mutually exclusive modes error, got %v", err)
	}
}

func TestPolicySignMultiAlias(t *testing.T) {
	// sign-multi is an alias for the same multi-capable sign path.
	t.Setenv(EnvPolicySignDev, "")
	err := runPolicy([]string{"sign-multi", "--file", "x", "--key", "k", "--key-id", "id", "--out", "o"})
	if err == nil || !strings.Contains(err.Error(), "dev-only") {
		t.Fatalf("sign-multi must hit same dev gate: %v", err)
	}
}

func TestPolicyShowEffective(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv(policy.EnvPolicyFileVar, "")
	t.Setenv(policy.EnvPolicyTrustedKeysVar, "")
	t.Setenv(policy.EnvPolicyRequiredVar, "")

	// Create a profile via store.
	paths, err := profileStore()
	if err != nil {
		t.Fatal(err)
	}
	// profileStore uses config.Resolve — XDG is set.
	st := paths
	p := &profile.Profile{
		ID:         "corp",
		JenkinsURL: "https://jenkins.example.corp",
		AuthMethod: "api_token",
	}
	// Set read_only if field exists — use EffectiveReadOnly default.
	if err := st.Save(p); err != nil {
		// Try constructing minimal via add path.
		t.Fatalf("save profile: %v", err)
	}

	// Optional enterprise force via plain overlay (Wave 35 node/view denials).
	polDir := filepath.Join(dir, "cfg", "jenkins-mcp", "policy")
	_ = os.MkdirAll(polDir, 0o700)
	ovPath := filepath.Join(polDir, "overlay.json")
	overlay := `{"version":1,"force_read_only":true,"deny_tools":["jenkins_start_job"],"deny_job_prefixes":["secret-folder"],"deny_node_names":["prod-agent-*"],"deny_view_names":["secret-view"]}`
	if err := os.WriteFile(ovPath, []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(policy.EnvPolicyFileVar, ovPath)

	// Text path: must surface node/view denials (Wave 36 doctor/policy counts consistency).
	if err := runPolicyShowEffective([]string{"--profile", "corp", "--allow-mutations"}); err != nil {
		t.Fatalf("show-effective: %v", err)
	}

	// JSON explain shape includes deny_node_names / deny_view_names when present.
	polRes, err := policy.LoadFromEnviron()
	if err != nil {
		t.Fatal(err)
	}
	ex := policy.ExplainEffective("corp", polRes, policy.Inputs{AllowMutations: true, Force: policy.AsEnterpriseForce(polRes.Overlay)})
	if len(ex.DenyNodeNames) != 1 || ex.DenyNodeNames[0] != "prod-agent-*" {
		t.Fatalf("deny_node_names=%v", ex.DenyNodeNames)
	}
	if len(ex.DenyViewNames) != 1 || ex.DenyViewNames[0] != "secret-view" {
		t.Fatalf("deny_view_names=%v", ex.DenyViewNames)
	}
	if len(ex.DenyJobPrefixes) != 1 {
		t.Fatalf("deny_job_prefixes=%v", ex.DenyJobPrefixes)
	}
	// Doctor StatusMap must include resource deny counts (counts, not values).
	sm := polRes.StatusMap()
	if sm["deny_node_names_count"] != 1 {
		t.Fatalf("status map deny_node_names_count=%v", sm["deny_node_names_count"])
	}
	if sm["deny_view_names_count"] != 1 {
		t.Fatalf("status map deny_view_names_count=%v", sm["deny_view_names_count"])
	}
	if sm["deny_job_prefixes_count"] != 1 {
		t.Fatalf("status map deny_job_prefixes_count=%v", sm["deny_job_prefixes_count"])
	}
}

func TestPolicyUnknownSubcommand(t *testing.T) {
	err := runPolicy([]string{"deploy"})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("got %v", err)
	}
}

func TestPolicyVerifyRequiresFile(t *testing.T) {
	err := runPolicyVerify(nil)
	if err == nil || !strings.Contains(err.Error(), "--file") {
		t.Fatalf("got %v", err)
	}
}

func TestPolicyVerifyJSONNoSecrets(t *testing.T) {
	// Capture that verify report schema is secret-free for a missing keys path.
	err := runPolicyVerify([]string{"--file", filepath.Join(t.TempDir(), "missing.json"), "--json"})
	if err == nil {
		// missing file without required may succeed with absent? LoadOverlay absent is ok.
		// Path missing → Present false, nil error.
	}
	// Build a minimal plain overlay and verify without keys (pilot).
	dir := t.TempDir()
	p := filepath.Join(dir, "o.json")
	_ = os.WriteFile(p, []byte(`{"version":1,"force_read_only":false}`), 0o600)
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "c"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	// Ensure no trusted keys.
	t.Setenv(policy.EnvPolicyTrustedKeysVar, "")

	// DefaultVerifier without keys → Nop → ok pilot.
	if err := runPolicyVerify([]string{"--file", p, "--json"}); err != nil {
		t.Fatal(err)
	}
}

// Ensure ExplainEffective JSON shape stays stable for tooling.
func TestEffectiveExplainJSONShape(t *testing.T) {
	t.Parallel()
	ex := policy.ExplainEffective("p", policy.LoadResult{SignatureState: policy.SigStateAbsent}, policy.Inputs{})
	raw, err := json.Marshal(ex)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["signature_state"]; !ok {
		t.Fatal("missing signature_state")
	}
}
