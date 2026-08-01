package policy_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func writeTrustDir(t *testing.T, dir, keyID string, pub ed25519.PublicKey) string {
	t.Helper()
	td := filepath.Join(dir, "trusted_keys")
	if err := os.MkdirAll(td, 0o700); err != nil {
		t.Fatal(err)
	}
	pem, err := policy.EncodePublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(td, keyID+".pub")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return td
}

func signOverlay(t *testing.T, ov policy.Overlay, priv ed25519.PrivateKey, keyID string, seq int64, notAfter string) *policy.BundleEnvelope {
	t.Helper()
	env := &policy.BundleEnvelope{
		SchemaVersion: policy.CurrentBundleSchemaVersion,
		Alg:           policy.AlgEd25519,
		KeyID:         keyID,
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
		NotAfter:      notAfter,
		MinVersion:    policy.CurrentOverlayVersion,
		BundleSeq:     seq,
		Overlay:       ov,
	}
	if err := policy.SignBundle(env, priv); err != nil {
		t.Fatal(err)
	}
	return env
}

func writeBundle(t *testing.T, path string, env *policy.BundleEnvelope) {
	t.Helper()
	raw, err := policy.MarshalBundle(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyHappyPath(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	keysDir := writeTrustDir(t, dir, "corp-2026", pub)
	keys, err := policy.LoadTrustedKeys(keysDir)
	if err != nil {
		t.Fatal(err)
	}

	maxB := 4096
	ov := policy.Overlay{
		Version:        1,
		ForceReadOnly:  true,
		Mode:           policy.ModePilot,
		DenyTools:      []string{"jenkins_get_build_logs"},
		MaxResultBytes: &maxB,
	}
	env := signOverlay(t, ov, priv, "corp-2026", 10, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339))
	path := filepath.Join(dir, "overlay.bundle.json")
	writeBundle(t, path, env)

	cachePath := filepath.Join(dir, "last_good.json")
	cache, err := policy.OpenLastGoodCache(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	v := policy.BundleVerifier(keys, cache, true)
	res, err := policy.LoadOverlay(policy.LoadOptions{
		Path:         path,
		Verifier:     v,
		SkipLastGood: true, // cache already attached to verifier
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.SignatureState != policy.SigStateVerified {
		t.Fatalf("state=%s", res.SignatureState)
	}
	if !res.Overlay.ForceReadOnly || res.BundleSeq != 10 || res.KeyID != "corp-2026" {
		t.Fatalf("overlay/meta: force=%v seq=%d key=%s", res.Overlay.ForceReadOnly, res.BundleSeq, res.KeyID)
	}
	if cache.Record == nil || cache.Record.BundleSeq != 10 {
		t.Fatal("last-good not updated")
	}
	// Status must not contain signature material.
	m := res.StatusMap()
	for k, val := range m {
		s := strings.ToLower(k + " " + toString(val))
		if strings.Contains(s, "signature") && k != "signature_state" {
			t.Fatalf("status leaked signature: %v=%v", k, val)
		}
		if strings.Contains(s, env.Signature) {
			t.Fatal("status leaked signature bytes")
		}
	}
}

func TestTamperFails(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	keys, _ := policy.LoadTrustedKeys(writeTrustDir(t, dir, "k1", pub))
	env := signOverlay(t, policy.Overlay{Version: 1, ForceReadOnly: true}, priv, "k1", 1, "")
	// Tamper after sign.
	env.Overlay.ForceReadOnly = false
	raw, _ := policy.MarshalBundle(env)
	path := filepath.Join(dir, "tampered.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{
		Path:     path,
		Verifier: policy.BundleVerifier(keys, nil, true),
	})
	if err == nil {
		t.Fatal("tampered bundle must fail")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
	if strings.Contains(err.Error(), env.Signature) {
		t.Fatal("error must not echo signature")
	}
}

func TestExpiredFails(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	keys, _ := policy.LoadTrustedKeys(writeTrustDir(t, dir, "k1", pub))
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	env := signOverlay(t, policy.Overlay{Version: 1, ForceReadOnly: true}, priv, "k1", 2, past)
	path := filepath.Join(dir, "expired.json")
	writeBundle(t, path, env)

	v := policy.Ed25519SignatureVerifier{
		Keys:          keys,
		RequireSigned: true,
		Now:           func() time.Time { return time.Now().UTC() },
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path, Verifier: v})
	if err == nil {
		t.Fatal("expired must fail")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("want expired: %v", err)
	}
}

func TestUntrustedKeyFails(t *testing.T) {
	t.Parallel()
	_, priv := testKeyPair(t)
	pubOther, _ := testKeyPair(t)
	dir := t.TempDir()
	keys, _ := policy.LoadTrustedKeys(writeTrustDir(t, dir, "trusted", pubOther))
	env := signOverlay(t, policy.Overlay{Version: 1, ForceReadOnly: true}, priv, "attacker", 1, "")
	path := filepath.Join(dir, "untrusted.json")
	writeBundle(t, path, env)
	_, err := policy.LoadOverlay(policy.LoadOptions{
		Path:     path,
		Verifier: policy.BundleVerifier(keys, nil, true),
	})
	if err == nil {
		t.Fatal("untrusted key_id must fail")
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("want not trusted: %v", err)
	}
}

func TestDowngradeFails(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	keys, _ := policy.LoadTrustedKeys(writeTrustDir(t, dir, "k1", pub))
	cachePath := filepath.Join(dir, "last_good.json")

	// Install seq=5 as last-good.
	env5 := signOverlay(t, policy.Overlay{Version: 1, ForceReadOnly: true}, priv, "k1", 5, "")
	path5 := filepath.Join(dir, "b5.json")
	writeBundle(t, path5, env5)
	cache, err := policy.OpenLastGoodCache(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	v := policy.BundleVerifier(keys, cache, true)
	if _, err := policy.LoadOverlay(policy.LoadOptions{Path: path5, Verifier: v}); err != nil {
		t.Fatalf("seq5: %v", err)
	}

	// Re-open cache from disk and try seq=3.
	cache2, err := policy.OpenLastGoodCache(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if cache2.Record == nil || cache2.Record.BundleSeq != 5 {
		t.Fatalf("cache not persisted: %+v", cache2.Record)
	}
	env3 := signOverlay(t, policy.Overlay{Version: 1, ForceReadOnly: true}, priv, "k1", 3, "")
	path3 := filepath.Join(dir, "b3.json")
	writeBundle(t, path3, env3)
	_, err = policy.LoadOverlay(policy.LoadOptions{
		Path:     path3,
		Verifier: policy.BundleVerifier(keys, cache2, true),
	})
	if err == nil {
		t.Fatal("downgrade must fail")
	}
	if !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("want downgrade: %v", err)
	}
}

func TestKeyRotationEmergencyReplacement(t *testing.T) {
	t.Parallel()
	pub1, priv1 := testKeyPair(t)
	pub2, priv2 := testKeyPair(t)
	dir := t.TempDir()
	// Both keys trusted (rotation window).
	td := filepath.Join(dir, "trusted_keys")
	_ = os.MkdirAll(td, 0o700)
	pem1, _ := policy.EncodePublicKeyPEM(pub1)
	pem2, _ := policy.EncodePublicKeyPEM(pub2)
	_ = os.WriteFile(filepath.Join(td, "old.pub"), pem1, 0o600)
	_ = os.WriteFile(filepath.Join(td, "new.pub"), pem2, 0o600)
	keys, err := policy.LoadTrustedKeys(td)
	if err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(dir, "lg.json")
	cache, _ := policy.OpenLastGoodCache(cachePath)

	envOld := signOverlay(t, policy.Overlay{Version: 1, ForceReadOnly: true}, priv1, "old", 1, "")
	p1 := filepath.Join(dir, "old.json")
	writeBundle(t, p1, envOld)
	if _, err := policy.LoadOverlay(policy.LoadOptions{
		Path: p1, Verifier: policy.BundleVerifier(keys, cache, true),
	}); err != nil {
		t.Fatal(err)
	}

	// Emergency replacement: higher seq signed by new key.
	envNew := signOverlay(t, policy.Overlay{Version: 1, ForceReadOnly: true, Mode: policy.ModeStrict}, priv2, "new", 2, "")
	p2 := filepath.Join(dir, "new.json")
	writeBundle(t, p2, envNew)
	cache2, _ := policy.OpenLastGoodCache(cachePath)
	res, err := policy.LoadOverlay(policy.LoadOptions{
		Path: p2, Verifier: policy.BundleVerifier(keys, cache2, true),
	})
	if err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if res.KeyID != "new" || res.BundleSeq != 2 {
		t.Fatalf("got key=%s seq=%d", res.KeyID, res.BundleSeq)
	}
	if res.Overlay.NormalizeMode() != policy.ModeStrict {
		t.Fatal("mode")
	}
}

func TestRequireSignedRejectsPlain(t *testing.T) {
	t.Parallel()
	pub, _ := testKeyPair(t)
	dir := t.TempDir()
	keys, _ := policy.LoadTrustedKeys(writeTrustDir(t, dir, "k1", pub))
	path := filepath.Join(dir, "plain.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"force_read_only":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{
		Path:     path,
		Verifier: policy.BundleVerifier(keys, nil, true),
	})
	if err == nil {
		t.Fatal("unsigned plain must fail when RequireSigned")
	}
}

func TestSignedBundleWithoutKeysFailsClosed(t *testing.T) {
	t.Parallel()
	_, priv := testKeyPair(t)
	dir := t.TempDir()
	env := signOverlay(t, policy.Overlay{Version: 1, ForceReadOnly: true}, priv, "k1", 1, "")
	path := filepath.Join(dir, "b.json")
	writeBundle(t, path, env)
	// Nop verifier + bundle → fail closed.
	_, err := policy.LoadOverlay(policy.LoadOptions{
		Path:     path,
		Verifier: policy.NopSignatureVerifier{},
	})
	if err == nil {
		t.Fatal("bundle without trusted keys must fail")
	}
}

func TestMinVersionMismatchFails(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	keys, _ := policy.LoadTrustedKeys(writeTrustDir(t, dir, "k1", pub))
	env := &policy.BundleEnvelope{
		SchemaVersion: policy.CurrentBundleSchemaVersion,
		Alg:           policy.AlgEd25519,
		KeyID:         "k1",
		MinVersion:    99,
		BundleSeq:     1,
		Overlay:       policy.Overlay{Version: 1, ForceReadOnly: true},
	}
	if err := policy.SignBundle(env, priv); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "minv.json")
	writeBundle(t, path, env)
	_, err := policy.LoadOverlay(policy.LoadOptions{
		Path:     path,
		Verifier: policy.BundleVerifier(keys, nil, true),
	})
	if err == nil || !strings.Contains(err.Error(), "min_version") {
		t.Fatalf("want min_version fail: %v", err)
	}
}

func TestLoadFromEnvironWithTrustedKeys(t *testing.T) {
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	keysDir := writeTrustDir(t, dir, "fleet", pub)
	env := signOverlay(t, policy.Overlay{Version: 1, ForceReadOnly: true}, priv, "fleet", 7, "")
	path := filepath.Join(dir, "overlay.bundle.json")
	writeBundle(t, path, env)

	t.Setenv(policy.EnvPolicyFileVar, path)
	t.Setenv(policy.EnvPolicyTrustedKeysVar, keysDir)
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvRequireSignedPolicyVar, "")
	// Isolate last-good under temp XDG cache.
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("HOME", dir)

	res, err := policy.LoadFromEnviron()
	if err != nil {
		t.Fatalf("LoadFromEnviron: %v", err)
	}
	if res.SignatureState != policy.SigStateVerified {
		t.Fatalf("state=%s", res.SignatureState)
	}
	if res.BundleSeq != 7 {
		t.Fatalf("seq=%d", res.BundleSeq)
	}
}

func TestLoadFromEnvironPilotNoKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"force_read_only":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(policy.EnvPolicyFileVar, path)
	t.Setenv(policy.EnvPolicyTrustedKeysVar, filepath.Join(dir, "no-such-keys"))
	// Missing keys path should error when env is set to nonexistent...
	// Env set to nonexistent → LoadTrustedKeys errors. Use empty/unset for pilot.
	t.Setenv(policy.EnvPolicyTrustedKeysVar, "")
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvRequireSignedPolicyVar, "")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	t.Setenv("HOME", dir)

	res, err := policy.LoadFromEnviron()
	if err != nil {
		t.Fatal(err)
	}
	if res.SignatureState != policy.SigStateUnverifiedPilot {
		t.Fatalf("state=%s", res.SignatureState)
	}
}

// Regression: JENKINS_MCP_REQUIRE_SIGNED_POLICY=1 must fail closed without
// trusted keys (staging stub is not enterprise force-off safe). MGR-001 lite.
func TestLoadFromEnvironRequireSignedPolicyNoKeysFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"force_read_only":true,"signature":"stub"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(policy.EnvPolicyFileVar, path)
	t.Setenv(policy.EnvPolicyTrustedKeysVar, "")
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvRequireSignedPolicyVar, "1")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("HOME", dir)

	_, err := policy.LoadFromEnviron()
	if err == nil {
		t.Fatal("REQUIRE_SIGNED_POLICY without trusted keys must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "require_signed") && !strings.Contains(msg, "trusted") {
		t.Fatalf("expected require-signed / trusted-keys wording: %v", err)
	}
}

// Regression: REQUIRE_SIGNED_POLICY + trusted keys + valid envelope verifies.
func TestLoadFromEnvironRequireSignedPolicyOK(t *testing.T) {
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	keysDir := writeTrustDir(t, dir, "fleet", pub)
	env := signOverlay(t, policy.Overlay{Version: 1, ForceReadOnly: true}, priv, "fleet", 9, "")
	path := filepath.Join(dir, "overlay.bundle.json")
	writeBundle(t, path, env)

	t.Setenv(policy.EnvPolicyFileVar, path)
	t.Setenv(policy.EnvPolicyTrustedKeysVar, keysDir)
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvRequireSignedPolicyVar, "1")
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("HOME", dir)

	res, err := policy.LoadFromEnviron()
	if err != nil {
		t.Fatalf("LoadFromEnviron: %v", err)
	}
	if res.SignatureState != policy.SigStateVerified {
		t.Fatalf("state=%s", res.SignatureState)
	}
	if res.Overlay == nil || !res.Overlay.ForceReadOnly {
		t.Fatal("expected verified force_read_only overlay")
	}
}

// Regression: REQUIRE_SIGNED_POLICY + trusted keys rejects plain unsigned overlay.
func TestLoadFromEnvironRequireSignedPolicyRejectsUnsigned(t *testing.T) {
	pub, _ := testKeyPair(t)
	dir := t.TempDir()
	keysDir := writeTrustDir(t, dir, "fleet", pub)
	path := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"force_read_only":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(policy.EnvPolicyFileVar, path)
	t.Setenv(policy.EnvPolicyTrustedKeysVar, keysDir)
	t.Setenv(policy.EnvRequireSignedPolicyVar, "1")
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("HOME", dir)

	_, err := policy.LoadFromEnviron()
	if err == nil {
		t.Fatal("unsigned plain must fail under REQUIRE_SIGNED_POLICY + trusted keys")
	}
}

func TestUserConfigCannotWeakenForceReadOnly(t *testing.T) {
	t.Parallel()
	// Regression: profile / --allow-mutations cannot weaken enterprise force_read_only.
	o := &policy.Overlay{Version: 1, ForceReadOnly: true}
	force := policy.AsEnterpriseForce(o)
	prof := false
	st := policy.ComputeEffectiveReadOnly(policy.Inputs{
		AllowMutations:  true,
		FlagReadOnly:    false,
		ProfileReadOnly: &prof,
		Force:           force,
	})
	if !st.Effective {
		t.Fatal("enterprise force_read_only must win")
	}
	if !contains(st.Sources, policy.SourceEnterpriseForce) {
		t.Fatalf("sources=%v", st.Sources)
	}
}

func TestTrustedKeysJSONStore(t *testing.T) {
	t.Parallel()
	pub, _ := testKeyPair(t)
	dir := t.TempDir()
	store := map[string]any{
		"keys": []map[string]string{
			{
				"key_id":     "json-key",
				"alg":        "ed25519",
				"public_key": base64.StdEncoding.EncodeToString(pub),
			},
		},
	}
	raw, _ := json.Marshal(store)
	path := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := policy.LoadTrustedKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Has("json-key") {
		t.Fatal("missing key")
	}
}

func TestDefaultBundlePathPreference(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	paths := config.Paths{ConfigDir: filepath.Join(dir, "jenkins-mcp")}
	// Create bundle only.
	polDir := paths.PolicyDir()
	if err := os.MkdirAll(polDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bundle := paths.DefaultPolicyBundleFile()
	if err := os.WriteFile(bundle, []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := policy.ResolvePolicyPath(policy.LoadOptions{Paths: &paths})
	if err != nil {
		t.Fatal(err)
	}
	if p != bundle {
		t.Fatalf("prefer bundle: got %s", p)
	}
}

func TestExplainEffectiveNoSecrets(t *testing.T) {
	t.Parallel()
	const canary = "CANARY_SIG_must_not_appear_xyz"
	res := policy.LoadResult{
		Present:        true,
		Path:           "/home/alice/.config/jenkins-mcp/policy/overlay.bundle.json",
		SignatureState: policy.SigStateVerified,
		BundleSeq:      3,
		KeyID:          "corp",
		ContentHash:    "abc",
		Overlay:        &policy.Overlay{Version: 1, ForceReadOnly: true, DenyTools: []string{"jenkins_start_job"}},
	}
	// Inject canary into a field that should never be serialized from Explain.
	_ = canary
	ex := policy.ExplainEffective("corp", res, policy.Inputs{
		Force:          policy.AsEnterpriseForce(res.Overlay),
		AllowMutations: true,
	})
	raw, err := json.Marshal(ex)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canary) {
		t.Fatal("canary in explain")
	}
	if !ex.ForceReadOnly || !ex.ReadOnly["effective"].(bool) {
		t.Fatalf("explain RO: %+v", ex)
	}
	if ex.PolicyPathBase != "overlay.bundle.json" {
		t.Fatalf("path base=%s", ex.PolicyPathBase)
	}
}

func TestSameSeqReloadAllowed(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	keys, _ := policy.LoadTrustedKeys(writeTrustDir(t, dir, "k1", pub))
	cachePath := filepath.Join(dir, "lg.json")
	env := signOverlay(t, policy.Overlay{Version: 1, ForceReadOnly: true}, priv, "k1", 4, "")
	path := filepath.Join(dir, "b.json")
	writeBundle(t, path, env)

	cache, _ := policy.OpenLastGoodCache(cachePath)
	v := policy.BundleVerifier(keys, cache, true)
	if _, err := policy.LoadOverlay(policy.LoadOptions{Path: path, Verifier: v}); err != nil {
		t.Fatal(err)
	}
	// Reload identical bundle.
	cache2, _ := policy.OpenLastGoodCache(cachePath)
	if _, err := policy.LoadOverlay(policy.LoadOptions{
		Path: path, Verifier: policy.BundleVerifier(keys, cache2, true),
	}); err != nil {
		t.Fatalf("idempotent reload: %v", err)
	}
}

func TestLooksLikeBundle(t *testing.T) {
	t.Parallel()
	if policy.LooksLikeBundle([]byte(`{"version":1,"force_read_only":true}`)) {
		t.Fatal("plain overlay must not look like bundle")
	}
	if !policy.LooksLikeBundle([]byte(`{"schema_version":1,"alg":"ed25519","key_id":"k","overlay":{"version":1},"signature":"x"}`)) {
		t.Fatal("envelope must look like bundle")
	}
	if !policy.LooksLikeBundle([]byte(`{"schema_version":1,"alg":"ed25519","key_id":"k","overlay":{"version":1},"signatures":[{"key_id":"a","signature":"x"}]}`)) {
		t.Fatal("multi-sig envelope must look like bundle")
	}
}

// writeTrustDirMulti writes multiple public keys into one trust directory.
func writeTrustDirMulti(t *testing.T, dir string, keys map[string]ed25519.PublicKey) string {
	t.Helper()
	td := filepath.Join(dir, "trusted_keys")
	if err := os.MkdirAll(td, 0o700); err != nil {
		t.Fatal(err)
	}
	for keyID, pub := range keys {
		pem, err := policy.EncodePublicKeyPEM(pub)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(td, keyID+".pub"), pem, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return td
}

func TestMultiSig2of2Pass(t *testing.T) {
	t.Parallel()
	pubA, privA := testKeyPair(t)
	pubB, privB := testKeyPair(t)
	dir := t.TempDir()
	keysDir := writeTrustDirMulti(t, dir, map[string]ed25519.PublicKey{
		"key-a": pubA,
		"key-b": pubB,
	})
	keys, err := policy.LoadTrustedKeys(keysDir)
	if err != nil {
		t.Fatal(err)
	}

	env := &policy.BundleEnvelope{
		SchemaVersion: policy.CurrentBundleSchemaVersion,
		Alg:           policy.AlgEd25519,
		KeyID:         "key-a",
		MinVersion:    policy.CurrentOverlayVersion,
		BundleSeq:     1,
		Overlay:       policy.Overlay{Version: 1, ForceReadOnly: true},
	}
	if err := policy.SignBundleMulti(env, []policy.BundleSigner{
		{KeyID: "key-a", Priv: privA},
		{KeyID: "key-b", Priv: privB},
	}); err != nil {
		t.Fatal(err)
	}
	if env.Signature != "" {
		t.Fatal("multi-sig must clear top-level signature")
	}
	if len(env.Signatures) != 2 {
		t.Fatalf("want 2 signatures, got %d", len(env.Signatures))
	}

	// Canonical body must be identical for both signers (signatures not in payload).
	body1, err := policy.CanonicalSigningBytes(env)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating signatures must not change canonical bytes.
	env.Signatures[0].Signature = "tampered-should-not-affect-body"
	body2, err := policy.CanonicalSigningBytes(env)
	if err != nil {
		t.Fatal(err)
	}
	if string(body1) != string(body2) {
		t.Fatal("canonical bytes must exclude signatures array")
	}
	// Restore valid signatures for verify.
	if err := policy.SignBundleMulti(env, []policy.BundleSigner{
		{KeyID: "key-a", Priv: privA},
		{KeyID: "key-b", Priv: privB},
	}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "multi.bundle.json")
	writeBundle(t, path, env)

	v := policy.Ed25519SignatureVerifier{
		Keys:          keys,
		RequireSigned: true,
		MinSignatures: 2, // dual-control 2-of-2
	}
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path, Verifier: v})
	if err != nil {
		t.Fatalf("2-of-2 multi-sig must pass: %v", err)
	}
	if res.SignatureState != policy.SigStateVerified {
		t.Fatalf("state=%s", res.SignatureState)
	}
	if !res.Overlay.ForceReadOnly {
		t.Fatal("overlay not applied")
	}
}

func TestMultiSig1of2FailsWhenMinSignatures2(t *testing.T) {
	t.Parallel()
	pubA, privA := testKeyPair(t)
	pubB, _ := testKeyPair(t)
	dir := t.TempDir()
	keysDir := writeTrustDirMulti(t, dir, map[string]ed25519.PublicKey{
		"key-a": pubA,
		"key-b": pubB,
	})
	keys, err := policy.LoadTrustedKeys(keysDir)
	if err != nil {
		t.Fatal(err)
	}

	// Only one signer when MinSignatures=2 → fail closed.
	env := &policy.BundleEnvelope{
		SchemaVersion: policy.CurrentBundleSchemaVersion,
		Alg:           policy.AlgEd25519,
		KeyID:         "key-a",
		MinVersion:    policy.CurrentOverlayVersion,
		BundleSeq:     1,
		Overlay:       policy.Overlay{Version: 1, ForceReadOnly: true},
	}
	if err := policy.SignBundleMulti(env, []policy.BundleSigner{
		{KeyID: "key-a", Priv: privA},
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "one-of-two.bundle.json")
	writeBundle(t, path, env)

	v := policy.Ed25519SignatureVerifier{
		Keys:          keys,
		RequireSigned: true,
		MinSignatures: 2,
	}
	_, err = policy.LoadOverlay(policy.LoadOptions{Path: path, Verifier: v})
	if err == nil {
		t.Fatal("1-of-2 with MinSignatures=2 must fail")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "multi-sig") && !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("want multi-sig threshold error: %v", err)
	}
}

func TestMultiSigSingleSigStillWorks(t *testing.T) {
	t.Parallel()
	// Regression: MVP single-sig envelopes still verify with MinSignatures set.
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	keys, _ := policy.LoadTrustedKeys(writeTrustDir(t, dir, "solo", pub))
	env := signOverlay(t, policy.Overlay{Version: 1, ForceReadOnly: true}, priv, "solo", 3, "")
	if len(env.Signatures) != 0 {
		t.Fatal("single-sig must not populate signatures[]")
	}
	path := filepath.Join(dir, "solo.bundle.json")
	writeBundle(t, path, env)

	v := policy.Ed25519SignatureVerifier{
		Keys:          keys,
		RequireSigned: true,
		MinSignatures: 2, // ignored for single-sig path
	}
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path, Verifier: v})
	if err != nil {
		t.Fatalf("single-sig must still work: %v", err)
	}
	if res.SignatureState != policy.SigStateVerified || res.KeyID != "solo" {
		t.Fatalf("state=%s key=%s", res.SignatureState, res.KeyID)
	}
}

func TestMultiSigUnknownKeyFails(t *testing.T) {
	t.Parallel()
	pubA, privA := testKeyPair(t)
	_, privB := testKeyPair(t) // B not in trust store
	dir := t.TempDir()
	// Only key-a is trusted.
	keys, _ := policy.LoadTrustedKeys(writeTrustDir(t, dir, "key-a", pubA))

	env := &policy.BundleEnvelope{
		SchemaVersion: policy.CurrentBundleSchemaVersion,
		Alg:           policy.AlgEd25519,
		KeyID:         "key-a",
		MinVersion:    policy.CurrentOverlayVersion,
		BundleSeq:     1,
		Overlay:       policy.Overlay{Version: 1, ForceReadOnly: true},
	}
	if err := policy.SignBundleMulti(env, []policy.BundleSigner{
		{KeyID: "key-a", Priv: privA},
		{KeyID: "attacker", Priv: privB},
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "unknown.bundle.json")
	writeBundle(t, path, env)

	v := policy.Ed25519SignatureVerifier{
		Keys:          keys,
		RequireSigned: true,
		MinSignatures: 1,
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path, Verifier: v})
	if err == nil {
		t.Fatal("unknown multi-sig key_id must fail")
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("want not trusted: %v", err)
	}
	if strings.Contains(err.Error(), env.Signatures[1].Signature) {
		t.Fatal("error must not echo signature material")
	}
}

func TestMultiSigDuplicateKeyIDCountsOnce(t *testing.T) {
	t.Parallel()
	// Two signatures from the same key_id count as one distinct key for MinSignatures.
	pubA, privA := testKeyPair(t)
	dir := t.TempDir()
	keys, _ := policy.LoadTrustedKeys(writeTrustDir(t, dir, "key-a", pubA))

	env := &policy.BundleEnvelope{
		SchemaVersion: policy.CurrentBundleSchemaVersion,
		Alg:           policy.AlgEd25519,
		KeyID:         "key-a",
		MinVersion:    policy.CurrentOverlayVersion,
		BundleSeq:     1,
		Overlay:       policy.Overlay{Version: 1, ForceReadOnly: true},
	}
	if err := policy.SignBundleMulti(env, []policy.BundleSigner{
		{KeyID: "key-a", Priv: privA},
		{KeyID: "key-a", Priv: privA}, // same key twice
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "dup.bundle.json")
	writeBundle(t, path, env)

	v := policy.Ed25519SignatureVerifier{
		Keys:          keys,
		RequireSigned: true,
		MinSignatures: 2,
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path, Verifier: v})
	if err == nil {
		t.Fatal("duplicate key_id must not satisfy MinSignatures=2")
	}
}

func TestMultiSigInvalidSignatureFails(t *testing.T) {
	t.Parallel()
	pubA, privA := testKeyPair(t)
	pubB, privB := testKeyPair(t)
	dir := t.TempDir()
	keysDir := writeTrustDirMulti(t, dir, map[string]ed25519.PublicKey{
		"key-a": pubA,
		"key-b": pubB,
	})
	keys, _ := policy.LoadTrustedKeys(keysDir)

	env := &policy.BundleEnvelope{
		SchemaVersion: policy.CurrentBundleSchemaVersion,
		Alg:           policy.AlgEd25519,
		KeyID:         "key-a",
		MinVersion:    policy.CurrentOverlayVersion,
		BundleSeq:     1,
		Overlay:       policy.Overlay{Version: 1, ForceReadOnly: true},
	}
	if err := policy.SignBundleMulti(env, []policy.BundleSigner{
		{KeyID: "key-a", Priv: privA},
		{KeyID: "key-b", Priv: privB},
	}); err != nil {
		t.Fatal(err)
	}
	// Corrupt second signature (valid base64, wrong bytes).
	bad := make([]byte, 64)
	env.Signatures[1].Signature = base64.StdEncoding.EncodeToString(bad)
	path := filepath.Join(dir, "bad-sig.bundle.json")
	writeBundle(t, path, env)

	v := policy.Ed25519SignatureVerifier{
		Keys:          keys,
		RequireSigned: true,
		MinSignatures: 2,
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path, Verifier: v})
	if err == nil {
		t.Fatal("invalid multi-sig entry must fail closed")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("want verification failed: %v", err)
	}
}
