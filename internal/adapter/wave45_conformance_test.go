package adapter_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/adapter"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Wave 45 / INT-001 conformance:
//   - Hard-assert Wave 44 Done* sign/verify still works
//   - Hard-assert Wave 45 Track A MinSignatures dual-control lite

// TestWave45_AllowlistSignVerify_Hard hard-asserts Wave 44 Done*:
// SignAllowlist + LoadAllowlistFileWithKeys happy path, bad sig fail-closed,
// signed-without-keys fail-closed, multi-sig all-entries verify path.
func TestWave45_AllowlistSignVerify_Hard(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "wave45-adapter-ops"
	raw, err := adapter.SignAllowlist(1, []string{adapter.IDNoop, adapter.IDClock}, priv, keyID)
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
		t.Fatalf("approved IDs missing: noop=%v clock=%v",
			al.Contains(adapter.IDNoop), al.Contains(adapter.IDClock))
	}

	// Bad signature fail-closed.
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badRaw, err := adapter.SignAllowlist(1, []string{adapter.IDNoop}, wrongPriv, keyID)
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, badRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, errBad := adapter.LoadAllowlistFileWithKeys(badPath, keys, true)
	if errBad == nil {
		t.Fatal("wrong signature must fail closed")
	}
	if apperr.CodeOf(errBad) != apperr.CodePolicyDenial {
		t.Fatalf("code=%s want policy_denial", apperr.CodeOf(errBad))
	}
	msg := apperr.ModelMessage(errBad)
	if strings.Contains(msg, string(raw)) || strings.Contains(msg, string(badRaw)) {
		t.Fatal("error must not echo allowlist/signature material")
	}

	// Signed without keys fail-closed.
	if _, err := adapter.LoadAllowlistFileWithKeys(path, nil, false); err == nil {
		t.Fatal("signed allowlist without trusted keys must fail closed")
	}

	// Multi-sig all-entries path (default MinSignatures=1).
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID2 = "wave45-adapter-ops-2"
	multiRaw, err := adapter.SignAllowlistMulti(1, []string{adapter.IDNoop}, []struct {
		KeyID string
		Priv  ed25519.PrivateKey
	}{
		{KeyID: keyID, Priv: priv},
		{KeyID: keyID2, Priv: priv2},
	})
	if err != nil {
		t.Fatal(err)
	}
	multiPath := filepath.Join(dir, "multi.json")
	if err := os.WriteFile(multiPath, multiRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	keysMulti := adapter.AllowlistTrustedKeySet{keyID: pub, keyID2: pub2}
	alMulti, err := adapter.LoadAllowlistFileWithKeys(multiPath, keysMulti, true)
	if err != nil {
		t.Fatal(err)
	}
	if !alMulti.Contains(adapter.IDNoop) {
		t.Fatal("multi-sig verified allowlist missing noop")
	}

	// Env contract name still public (Wave 44).
	if adapter.EnvAdapterAllowlistTrustedKeys != "JENKINS_MCP_ADAPTER_ALLOWLIST_TRUSTED_KEYS" {
		t.Fatalf("env name drift: %q", adapter.EnvAdapterAllowlistTrustedKeys)
	}
}

// TestWave45_MinSignaturesDualControl_Hard hard-asserts Wave 45 Track A:
// MinSignatures=2 accepts 2-of-2 multi-sig and fails closed on 1-of-2.
// Default MinSignatures=1 still accepts a single multi-sig entry.
func TestWave45_MinSignaturesDualControl_Hard(t *testing.T) {
	t.Parallel()

	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID1 = "wave45-ms-k1"
	const keyID2 = "wave45-ms-k2"
	dir := t.TempDir()

	// 2-of-2 with MinSignatures=2 must succeed.
	raw2, err := adapter.SignAllowlistMulti(1, []string{adapter.IDNoop}, []struct {
		KeyID string
		Priv  ed25519.PrivateKey
	}{
		{KeyID: keyID1, Priv: priv1},
		{KeyID: keyID2, Priv: priv2},
	})
	if err != nil {
		t.Fatal(err)
	}
	path2 := filepath.Join(dir, "two.json")
	if err := os.WriteFile(path2, raw2, 0o600); err != nil {
		t.Fatal(err)
	}
	keys2 := adapter.AllowlistTrustedKeySet{keyID1: pub1, keyID2: pub2}
	al, err := adapter.LoadAllowlistFileOpts(adapter.LoadAllowlistOptions{
		Path: path2, Keys: keys2, RequireSigned: true, MinSignatures: 2,
	})
	if err != nil {
		t.Fatalf("2-of-2 MinSignatures=2 must verify: %v", err)
	}
	if !al.Contains(adapter.IDNoop) {
		t.Fatal("2-of-2 missing noop")
	}

	// 1-of-2 with MinSignatures=2 must fail closed.
	raw1, err := adapter.SignAllowlistMulti(1, []string{adapter.IDNoop}, []struct {
		KeyID string
		Priv  ed25519.PrivateKey
	}{
		{KeyID: keyID1, Priv: priv1},
	})
	if err != nil {
		t.Fatal(err)
	}
	path1 := filepath.Join(dir, "one.json")
	if err := os.WriteFile(path1, raw1, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = adapter.LoadAllowlistFileOpts(adapter.LoadAllowlistOptions{
		Path: path1, Keys: keys2, RequireSigned: true, MinSignatures: 2,
	})
	if err == nil {
		t.Fatal("1-of-2 with MinSignatures=2 must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code=%s want policy_denial", apperr.CodeOf(err))
	}
	msg := strings.ToLower(apperr.ModelMessage(err))
	if !strings.Contains(msg, "multi") && !strings.Contains(msg, "distinct") && !strings.Contains(msg, "min") {
		t.Fatalf("fail message should mention multi-sig/distinct/min: %s", msg)
	}

	// Default MinSignatures=1 still accepts single multi-sig entry (back-compat).
	al1, err := adapter.LoadAllowlistFileWithKeys(path1, adapter.AllowlistTrustedKeySet{keyID1: pub1}, true)
	if err != nil {
		t.Fatalf("default MinSignatures=1 should accept 1 multi-sig entry: %v", err)
	}
	if !al1.Contains(adapter.IDNoop) {
		t.Fatal("default min=1 missing noop")
	}

	if adapter.EnvAdapterAllowlistMinSignatures != "JENKINS_MCP_ADAPTER_ALLOWLIST_MIN_SIGNATURES" {
		t.Fatalf("env name drift: %q", adapter.EnvAdapterAllowlistMinSignatures)
	}
	n, err := adapter.ResolveAllowlistMinSignatures("", "")
	if err != nil || n != 1 {
		t.Fatalf("default resolve: n=%d err=%v", n, err)
	}
	if _, err := adapter.ResolveAllowlistMinSignatures("17", ""); err == nil {
		t.Fatal("above absolute max 16 must fail closed")
	}
}
