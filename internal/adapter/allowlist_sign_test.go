package adapter_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/adapter"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

func testAllowlistKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func writeAllowlistTrustedJSON(t *testing.T, dir, keyID string, pub ed25519.PublicKey) string {
	t.Helper()
	path := filepath.Join(dir, "keys.json")
	store := map[string]any{
		"keys": []map[string]string{
			{
				"key_id":     keyID,
				"public_key": base64.StdEncoding.EncodeToString(pub),
			},
		},
	}
	raw, err := json.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAllowlist_SignVerifyHappyPath(t *testing.T) {
	t.Parallel()
	pub, priv := testAllowlistKeyPair(t)
	const keyID = "adapter-ops-1"
	raw, err := adapter.SignAllowlist(1, []string{"Noop", "CLOCK"}, priv, keyID)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	keys := adapter.AllowlistTrustedKeySet{keyID: pub}
	al, err := adapter.LoadAllowlistFileWithKeys(path, keys, true)
	if err != nil {
		t.Fatal(err)
	}
	if !al.Contains(adapter.IDNoop) || !al.Contains(adapter.IDClock) {
		t.Fatalf("approved IDs missing: noop=%v clock=%v", al.Contains(adapter.IDNoop), al.Contains(adapter.IDClock))
	}
}

func TestLoadAllowlist_WrongSignatureFails(t *testing.T) {
	t.Parallel()
	pub, _ := testAllowlistKeyPair(t)
	_, otherPriv := testAllowlistKeyPair(t)
	const keyID = "k1"
	// Sign with wrong private key but claim key_id k1.
	raw, err := adapter.SignAllowlist(1, []string{"noop"}, otherPriv, keyID)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	keys := adapter.AllowlistTrustedKeySet{keyID: pub}
	_, err = adapter.LoadAllowlistFileWithKeys(path, keys, true)
	if err == nil {
		t.Fatal("expected wrong signature to fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code=%s want policy_denial", apperr.CodeOf(err))
	}
	// Canary: error must not echo signature material.
	assertSecretFreeError(t, err, string(raw))
}

func TestLoadAllowlist_UnknownKeyIDFails(t *testing.T) {
	t.Parallel()
	pub, priv := testAllowlistKeyPair(t)
	raw, err := adapter.SignAllowlist(1, []string{"noop"}, priv, "not-in-trust-store")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	keys := adapter.AllowlistTrustedKeySet{"trusted-only": pub}
	_, err = adapter.LoadAllowlistFileWithKeys(path, keys, true)
	if err == nil {
		t.Fatal("expected unknown key_id to fail closed")
	}
	msg := apperr.ModelMessage(err)
	if !strings.Contains(msg, "not trusted") {
		t.Fatalf("want not trusted guidance: %s", msg)
	}
	// Never leak signature base64 from the file.
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	if sig, ok := doc["signature"].(string); ok && sig != "" && strings.Contains(msg, sig) {
		t.Fatal("error echoed signature material")
	}
}

func TestLoadAllowlist_UnsignedWithKeysRequireSignedFails(t *testing.T) {
	t.Parallel()
	pub, _ := testAllowlistKeyPair(t)
	path := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"approved":["noop"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := adapter.AllowlistTrustedKeySet{"k1": pub}
	_, err := adapter.LoadAllowlistFileWithKeys(path, keys, true)
	if err == nil {
		t.Fatal("expected unsigned+keys+requireSigned to fail closed")
	}
	if !strings.Contains(strings.ToLower(apperr.ModelMessage(err)), "unsigned") {
		t.Fatalf("msg=%s", apperr.ModelMessage(err))
	}
}

func TestLoadAllowlist_SignedWithNoKeysFailsClosed(t *testing.T) {
	t.Parallel()
	_, priv := testAllowlistKeyPair(t)
	raw, err := adapter.SignAllowlist(1, []string{"noop"}, priv, "k1")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = adapter.LoadAllowlistFileWithKeys(path, nil, false)
	if err == nil {
		t.Fatal("expected signed+no keys to fail closed")
	}
	msg := strings.ToLower(apperr.ModelMessage(err))
	if !strings.Contains(msg, "no trusted keys") {
		t.Fatalf("want no trusted keys message: %s", apperr.ModelMessage(err))
	}
	assertSecretFreeError(t, err, string(raw))
}

func TestLoadAllowlist_PilotUnsignedNoKeysOK(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"approved":["noop","CLOCK"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	al, err := adapter.LoadAllowlistFileWithKeys(path, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !al.Contains("noop") || !al.Contains("clock") {
		t.Fatalf("normalization: %+v", al.IDs)
	}
	// Pilot LoadAllowlistFile remains unchanged.
	al2, err := adapter.LoadAllowlistFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !al2.Contains("noop") {
		t.Fatal("LoadAllowlistFile pilot path")
	}
}

func TestLoadAllowlist_EmptyPathWithKeys(t *testing.T) {
	t.Parallel()
	pub, _ := testAllowlistKeyPair(t)
	keys := adapter.AllowlistTrustedKeySet{"k": pub}
	al, err := adapter.LoadAllowlistFileWithKeys("", keys, true)
	if err != nil {
		t.Fatal(err)
	}
	if al.Contains(adapter.IDNoop) {
		t.Fatal("empty path must deny")
	}
}

func TestLoadAllowlist_InvalidJSONFailsClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(path, []byte(`{not-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := adapter.LoadAllowlistFileWithKeys(path, nil, false)
	if err == nil {
		t.Fatal("expected invalid JSON error")
	}
}

func TestLoadAllowlist_ApprovedIDNormalization(t *testing.T) {
	t.Parallel()
	pub, priv := testAllowlistKeyPair(t)
	const keyID = "ops"
	// Sign with mixed case; verification uses same normalization.
	raw, err := adapter.SignAllowlist(1, []string{"  NoOp  ", "Clock"}, priv, keyID)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	al, err := adapter.LoadAllowlistFileWithKeys(path, adapter.AllowlistTrustedKeySet{keyID: pub}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !al.Contains("NOOP") || !al.Contains("clock") {
		t.Fatalf("IDs=%v", al.IDs)
	}
}

func TestLoadAllowlist_MultiSigHappyAndUnknownFails(t *testing.T) {
	t.Parallel()
	pubA, privA := testAllowlistKeyPair(t)
	pubB, privB := testAllowlistKeyPair(t)
	raw, err := adapter.SignAllowlistMulti(1, []string{"noop"}, []struct {
		KeyID string
		Priv  ed25519.PrivateKey
	}{
		{KeyID: "a", Priv: privA},
		{KeyID: "b", Priv: privB},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	keys := adapter.AllowlistTrustedKeySet{"a": pubA, "b": pubB}
	al, err := adapter.LoadAllowlistFileWithKeys(path, keys, true)
	if err != nil {
		t.Fatal(err)
	}
	if !al.Contains("noop") {
		t.Fatal("multi-sig should approve noop")
	}
	// Only one key trusted → second entry unknown key_id fails closed.
	_, err = adapter.LoadAllowlistFileWithKeys(path, adapter.AllowlistTrustedKeySet{"a": pubA}, true)
	if err == nil {
		t.Fatal("expected unknown multi-sig key_id fail")
	}
}

// Wave 45 / INT-001: multi-sig MinSignatures dual-control lite floor.
func TestLoadAllowlist_MinSignatures2of2OK(t *testing.T) {
	t.Parallel()
	pubA, privA := testAllowlistKeyPair(t)
	pubB, privB := testAllowlistKeyPair(t)
	raw, err := adapter.SignAllowlistMulti(1, []string{"noop", "clock"}, []struct {
		KeyID string
		Priv  ed25519.PrivateKey
	}{
		{KeyID: "a", Priv: privA},
		{KeyID: "b", Priv: privB},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	keys := adapter.AllowlistTrustedKeySet{"a": pubA, "b": pubB}
	al, err := adapter.LoadAllowlistFileOpts(adapter.LoadAllowlistOptions{
		Path:          path,
		Keys:          keys,
		RequireSigned: true,
		MinSignatures: 2,
	})
	if err != nil {
		t.Fatalf("2-of-2 MinSignatures=2 must succeed: %v", err)
	}
	if !al.Contains("noop") || !al.Contains("clock") {
		t.Fatalf("approved: %+v", al.IDs)
	}
}

func TestLoadAllowlist_MinSignatures2_1of2Fails(t *testing.T) {
	t.Parallel()
	pubA, privA := testAllowlistKeyPair(t)
	pubB, _ := testAllowlistKeyPair(t)
	// Only one signature entry; MinSignatures=2 must fail closed (strip residual).
	raw, err := adapter.SignAllowlistMulti(1, []string{"noop"}, []struct {
		KeyID string
		Priv  ed25519.PrivateKey
	}{
		{KeyID: "a", Priv: privA},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	keys := adapter.AllowlistTrustedKeySet{"a": pubA, "b": pubB}
	_, err = adapter.LoadAllowlistFileOpts(adapter.LoadAllowlistOptions{
		Path:          path,
		Keys:          keys,
		RequireSigned: true,
		MinSignatures: 2,
	})
	if err == nil {
		t.Fatal("1-of-2 with MinSignatures=2 must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code=%s want policy_denial", apperr.CodeOf(err))
	}
	msg := strings.ToLower(apperr.ModelMessage(err))
	if !strings.Contains(msg, "multi-sig") && !strings.Contains(msg, "distinct") {
		t.Fatalf("want multi-sig/distinct guidance: %s", apperr.ModelMessage(err))
	}
	assertSecretFreeError(t, err, string(raw))
}

func TestLoadAllowlist_MinSignatures1_1of2OK(t *testing.T) {
	t.Parallel()
	pubA, privA := testAllowlistKeyPair(t)
	pubB, _ := testAllowlistKeyPair(t)
	raw, err := adapter.SignAllowlistMulti(1, []string{"noop"}, []struct {
		KeyID string
		Priv  ed25519.PrivateKey
	}{
		{KeyID: "a", Priv: privA},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Default MinSignatures=1 via LoadAllowlistFileWithKeys: 1 distinct ok.
	al, err := adapter.LoadAllowlistFileWithKeys(path, adapter.AllowlistTrustedKeySet{"a": pubA, "b": pubB}, true)
	if err != nil {
		t.Fatalf("min=1 with 1-of-2 must accept: %v", err)
	}
	if !al.Contains("noop") {
		t.Fatal("approved missing")
	}
	// Explicit MinSignatures=1 via opts.
	al2, err := adapter.LoadAllowlistFileOpts(adapter.LoadAllowlistOptions{
		Path:          path,
		Keys:          adapter.AllowlistTrustedKeySet{"a": pubA, "b": pubB},
		RequireSigned: true,
		MinSignatures: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !al2.Contains("noop") {
		t.Fatal("opts min=1 missing id")
	}
	// 0 / negative MinSignatures treated as 1.
	al3, err := adapter.LoadAllowlistFileOpts(adapter.LoadAllowlistOptions{
		Path:          path,
		Keys:          adapter.AllowlistTrustedKeySet{"a": pubA},
		RequireSigned: true,
		MinSignatures: 0,
	})
	if err != nil {
		t.Fatalf("MinSignatures=0 must default to 1: %v", err)
	}
	if !al3.Contains("noop") {
		t.Fatal("zero min missing id")
	}
}

func TestLoadAllowlist_MinSignatures_SingleSigIgnoresFloor(t *testing.T) {
	t.Parallel()
	pub, priv := testAllowlistKeyPair(t)
	const keyID = "solo"
	raw, err := adapter.SignAllowlist(1, []string{"noop"}, priv, keyID)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Single-sig path ignores MinSignatures (even when set to 2).
	al, err := adapter.LoadAllowlistFileOpts(adapter.LoadAllowlistOptions{
		Path:          path,
		Keys:          adapter.AllowlistTrustedKeySet{keyID: pub},
		RequireSigned: true,
		MinSignatures: 2,
	})
	if err != nil {
		t.Fatalf("single-sig must ignore MinSignatures=2: %v", err)
	}
	if !al.Contains("noop") {
		t.Fatal("single-sig approved missing")
	}
}

func TestResolveAllowlistMinSignatures_PrecedenceAndDefaults(t *testing.T) {
	t.Parallel()
	n, err := adapter.ResolveAllowlistMinSignatures("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != adapter.DefaultAllowlistMinSignatures {
		t.Fatalf("default: got %d want %d", n, adapter.DefaultAllowlistMinSignatures)
	}
	n, err = adapter.ResolveAllowlistMinSignatures("", "2")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("env: got %d", n)
	}
	n, err = adapter.ResolveAllowlistMinSignatures("3", "2")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("flag wins: got %d", n)
	}
	// empty / whitespace / 0 → default 1
	for _, tc := range []struct{ flag, env string }{
		{"0", "2"}, // explicit flag 0 means default (not keep env)
		{"", "0"},
		{"  ", "  "},
		{"0", ""},
	} {
		n, err = adapter.ResolveAllowlistMinSignatures(tc.flag, tc.env)
		if err != nil {
			t.Fatalf("flag=%q env=%q: %v", tc.flag, tc.env, err)
		}
		if n != adapter.DefaultAllowlistMinSignatures {
			t.Fatalf("flag=%q env=%q: got %d want default", tc.flag, tc.env, n)
		}
	}
}

func TestResolveAllowlistMinSignatures_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-number"},
		{"bad flag", "2x", ""},
		{"negative env", "", "-1"},
		{"negative flag", "-2", "1"},
		{"float", "", "1.5"},
		{"over max flag", "17", ""},
		{"over max env", "", "100"},
		{"absurd", "9999", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := adapter.ResolveAllowlistMinSignatures(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected fail closed")
			}
			msg := strings.ToLower(apperr.ModelMessage(err))
			if !strings.Contains(msg, "min-signatures") && !strings.Contains(msg, "fail closed") {
				t.Fatalf("unexpected error: %v", err)
			}
			// No secret-like material.
			if strings.Contains(msg, "BEGIN") || strings.Contains(msg, "private") {
				t.Fatalf("error looks like key material: %s", msg)
			}
		})
	}
	// At absolute max is ok.
	n, err := adapter.ResolveAllowlistMinSignatures("16", "")
	if err != nil || n != adapter.AbsoluteMaxAllowlistMinSignatures {
		t.Fatalf("at max: n=%d err=%v", n, err)
	}
}

func TestResolveAllowlistMinSignatures_EnvName(t *testing.T) {
	t.Parallel()
	if adapter.EnvAdapterAllowlistMinSignatures != "JENKINS_MCP_ADAPTER_ALLOWLIST_MIN_SIGNATURES" {
		t.Fatalf("env name drift: %q", adapter.EnvAdapterAllowlistMinSignatures)
	}
	if adapter.AbsoluteMaxAllowlistMinSignatures != 16 {
		t.Fatalf("absolute max drift: %d", adapter.AbsoluteMaxAllowlistMinSignatures)
	}
	if adapter.DefaultAllowlistMinSignatures != 1 {
		t.Fatalf("default drift: %d", adapter.DefaultAllowlistMinSignatures)
	}
}

// Regression: MinSignatures=2 blocks stripping multi-sig down to one trusted entry.
func TestLoadAllowlist_MinSignatures_StripOneFails(t *testing.T) {
	t.Parallel()
	pubA, privA := testAllowlistKeyPair(t)
	pubB, privB := testAllowlistKeyPair(t)
	// Full 2-of-2 document, then strip to one signature (editor with one key).
	rawFull, err := adapter.SignAllowlistMulti(1, []string{"noop"}, []struct {
		KeyID string
		Priv  ed25519.PrivateKey
	}{
		{KeyID: "a", Priv: privA},
		{KeyID: "b", Priv: privB},
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(rawFull, &doc); err != nil {
		t.Fatal(err)
	}
	sigs, ok := doc["signatures"].([]any)
	if !ok || len(sigs) < 2 {
		t.Fatalf("expected 2 signatures in doc: %+v", doc)
	}
	doc["signatures"] = []any{sigs[0]} // keep only first
	stripped, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "stripped.json")
	if err := os.WriteFile(path, stripped, 0o600); err != nil {
		t.Fatal(err)
	}
	keys := adapter.AllowlistTrustedKeySet{"a": pubA, "b": pubB}
	// With MinSignatures=1, stripped file still verifies (residual when floor=1).
	al, err := adapter.LoadAllowlistFileOpts(adapter.LoadAllowlistOptions{
		Path: path, Keys: keys, RequireSigned: true, MinSignatures: 1,
	})
	if err != nil || !al.Contains("noop") {
		t.Fatalf("min=1 stripped must still verify: al=%+v err=%v", al, err)
	}
	// MinSignatures=2 fail-closes the strip attack.
	_, err = adapter.LoadAllowlistFileOpts(adapter.LoadAllowlistOptions{
		Path: path, Keys: keys, RequireSigned: true, MinSignatures: 2,
	})
	if err == nil {
		t.Fatal("Regression: stripped multi-sig must fail when MinSignatures=2")
	}
	assertSecretFreeError(t, err, string(stripped))
}

func TestLoadAllowlistTrustedKeys_JSONAndDir(t *testing.T) {
	t.Parallel()
	pub, _ := testAllowlistKeyPair(t)
	dir := t.TempDir()
	jsonPath := writeAllowlistTrustedJSON(t, dir, "from-json", pub)
	set, err := adapter.LoadAllowlistTrustedKeys(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 1 || !set.Has("from-json") {
		t.Fatalf("json store: %+v", set.KeyIDs())
	}

	// Directory of key_id.pub base64 files.
	keyDir := filepath.Join(dir, "keys")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "dir-key.pub"),
		[]byte(base64.StdEncoding.EncodeToString(pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	set2, err := adapter.LoadAllowlistTrustedKeys(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if !set2.Has("dir-key") {
		t.Fatalf("dir keys: %v", set2.KeyIDs())
	}
}

func TestLoadAllowlistTrustedKeysFromEnviron(t *testing.T) {
	// Cannot t.Parallel: mutates env.
	pub, _ := testAllowlistKeyPair(t)
	path := writeAllowlistTrustedJSON(t, t.TempDir(), "env-key", pub)
	t.Setenv(adapter.EnvAdapterAllowlistTrustedKeys, path)
	set, err := adapter.LoadAllowlistTrustedKeysFromEnviron()
	if err != nil {
		t.Fatal(err)
	}
	if !set.Has("env-key") {
		t.Fatalf("env load: %v", set.KeyIDs())
	}
	t.Setenv(adapter.EnvAdapterAllowlistTrustedKeys, "")
	set2, err := adapter.LoadAllowlistTrustedKeysFromEnviron()
	if err != nil {
		t.Fatal(err)
	}
	if set2.Len() != 0 {
		t.Fatal("empty env must yield empty set")
	}
}

func TestLoadAllowlist_SecretsNeverInErrors(t *testing.T) {
	t.Parallel()
	pub, priv := testAllowlistKeyPair(t)
	// Plant distinctive material in a wrong signature.
	canarySig := base64.StdEncoding.EncodeToString(bytesOf(64, 0xAB))
	canaryPub := base64.StdEncoding.EncodeToString(pub)
	doc := map[string]any{
		"version":   1,
		"approved":  []string{"noop"},
		"key_id":    "k1",
		"signature": canarySig,
	}
	// Also sign correctly then flip — use wrong sig explicitly.
	_ = priv
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	keys := adapter.AllowlistTrustedKeySet{"k1": pub}
	_, err = adapter.LoadAllowlistFileWithKeys(path, keys, true)
	if err == nil {
		t.Fatal("expected fail")
	}
	msg := apperr.ModelMessage(err)
	for _, bad := range []string{canarySig, canaryPub, string(pub), string(priv)} {
		if bad != "" && strings.Contains(msg, bad) {
			t.Fatalf("error leaked material: msg=%q bad_len=%d", msg, len(bad))
		}
	}
	// Base64 prefix of planted sig should not appear.
	if strings.Contains(msg, canarySig[:16]) {
		t.Fatalf("error leaked sig prefix: %s", msg)
	}
}

func TestCanonicalAllowlistSigningBytes_DeterministicSorted(t *testing.T) {
	t.Parallel()
	a, err := adapter.CanonicalAllowlistSigningBytes(1, []string{"clock", "noop"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := adapter.CanonicalAllowlistSigningBytes(1, []string{"NOOP", "Clock", "noop"})
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical not stable:\n%s\n%s", a, b)
	}
	// Must not include signature fields even if we only pass version+approved.
	if strings.Contains(string(a), "signature") || strings.Contains(string(a), "key_id") {
		t.Fatalf("payload must exclude signature fields: %s", a)
	}
}

func bytesOf(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func assertSecretFreeError(t *testing.T, err error, rawDoc string) {
	t.Helper()
	msg := apperr.ModelMessage(err)
	var doc map[string]any
	if json.Unmarshal([]byte(rawDoc), &doc) == nil {
		if sig, ok := doc["signature"].(string); ok && sig != "" && strings.Contains(msg, sig) {
			t.Fatalf("error echoed signature: %s", msg)
		}
	}
	for _, bad := range []string{"BEGIN PRIVATE", "BEGIN PUBLIC", string([]byte{0})} {
		if bad != "" && strings.Contains(msg, bad) {
			t.Fatalf("error looks like key material: %s", msg)
		}
	}
}

// Regression: configured trusted-keys directory with zero usable keys must fail
// closed (not silently return empty set → pilot unsigned).
func TestLoadAllowlistTrustedKeys_EmptyDirFailClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Empty dir
	_, err := adapter.LoadAllowlistTrustedKeys(dir)
	if err == nil {
		t.Fatal("empty trusted-keys dir must fail closed")
	}
	if !strings.Contains(err.Error(), "zero keys") {
		t.Fatalf("err should note zero keys: %v", err)
	}
	// Dir with only ignored README.md
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# keys"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = adapter.LoadAllowlistTrustedKeys(dir)
	if err == nil {
		t.Fatal("dir with only .md must fail closed")
	}
}

// Raw 32-byte public key file with trailing newline must parse (common .pub shape).
func TestParseAllowlistPublicKey_RawWithTrailingNewline(t *testing.T) {
	t.Parallel()
	pub, _ := testAllowlistKeyPair(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "ops1.pub")
	// Raw bytes + trailing newline (33 bytes on disk).
	if err := os.WriteFile(path, append(append([]byte{}, pub...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := adapter.LoadAllowlistTrustedKeys(path)
	if err != nil {
		t.Fatalf("raw+newline: %v", err)
	}
	if set.Len() != 1 || !set.Has("ops1") {
		t.Fatalf("keys: %+v", set.KeyIDs())
	}
}
