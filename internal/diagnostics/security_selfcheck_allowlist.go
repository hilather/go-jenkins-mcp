package diagnostics

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/adapter"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// checkAdapterAllowlistProvenanceLite is Wave 44–45 / INT-001 residual honesty:
// proves offline that optional Ed25519 allowlist signature verification works
// (sign temp allowlist, verify with trusted keys, bad signature fails closed)
// and dual-control MinSignatures lite (2-of-2 ok, 1-of-2 fails closed), while
// documenting that cosign/SBOM/HSM/true multi-party threshold provenance are residual.
//
// Pure offline: ephemeral keys only (never written to report). No network.
// Status OK when lite path works; Details residual_cosign/hsm/sbom false.
func checkAdapterAllowlistProvenanceLite() SelfCheckItem {
	const (
		name    = "adapter_allowlist_provenance_lite"
		control = "INT-001"
	)
	fail := func(msg string) SelfCheckItem {
		return SelfCheckItem{
			Name:    name,
			Status:  SelfCheckFail,
			Message: msg,
			Control: control,
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail("ephemeral ed25519 key generation failed")
	}
	const keyID = "selfcheck-adapter-ops"
	// Synthetic only — never put priv/pub/sig bytes in Message/Details.
	raw, err := adapter.SignAllowlist(1, []string{adapter.IDNoop, adapter.IDClock}, priv, keyID)
	if err != nil {
		return fail("SignAllowlist failed (allowlist sign path broken)")
	}

	dir, err := os.MkdirTemp("", "adapter-allowlist-selfcheck-*")
	if err != nil {
		return fail("temp dir for allowlist canary failed")
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "allowlist.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fail("write signed allowlist canary failed")
	}

	keys := adapter.AllowlistTrustedKeySet{keyID: pub}
	al, err := adapter.LoadAllowlistFileWithKeys(path, keys, true)
	if err != nil {
		return fail("signed allowlist verify must succeed: " + apperr.ModelMessage(err))
	}
	if !al.Contains(adapter.IDNoop) || !al.Contains(adapter.IDClock) {
		return fail("verified allowlist missing approved ids")
	}

	// Bad signature must fail closed (flip last byte of signature field via re-sign wrong key).
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail("ephemeral wrong-key generation failed")
	}
	badRaw, err := adapter.SignAllowlist(1, []string{adapter.IDNoop}, wrongPriv, keyID)
	if err != nil {
		return fail("SignAllowlist wrong-key path failed")
	}
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, badRaw, 0o600); err != nil {
		return fail("write bad allowlist canary failed")
	}
	_, errBad := adapter.LoadAllowlistFileWithKeys(badPath, keys, true)
	if errBad == nil {
		return fail("wrong signature must fail closed")
	}
	if apperr.CodeOf(errBad) != apperr.CodePolicyDenial {
		return fail("wrong signature fail must be policy denial")
	}
	// Defense: never echo signature material from canary files.
	errMsg := apperr.ModelMessage(errBad)
	if strings.Contains(errMsg, string(raw)) || strings.Contains(errMsg, string(badRaw)) {
		return fail("allowlist error echoed file material")
	}

	// Signed without keys must fail closed (false sense of security).
	_, errNoKeys := adapter.LoadAllowlistFileWithKeys(path, nil, false)
	if errNoKeys == nil {
		return fail("signed allowlist without trusted keys must fail closed")
	}

	// Unsigned + keys + requireSigned must fail closed.
	unsignedPath := filepath.Join(dir, "unsigned.json")
	if err := os.WriteFile(unsignedPath, []byte(`{"version":1,"approved":["noop"]}`), 0o600); err != nil {
		return fail("write unsigned allowlist canary failed")
	}
	_, errUnsigned := adapter.LoadAllowlistFileWithKeys(unsignedPath, keys, true)
	if errUnsigned == nil {
		return fail("unsigned allowlist with trusted keys must fail closed when requireSigned")
	}

	// Pilot unsigned + no keys still works.
	alPilot, err := adapter.LoadAllowlistFileWithKeys(unsignedPath, nil, false)
	if err != nil || !alPilot.Contains(adapter.IDNoop) {
		return fail("pilot unsigned allowlist without keys must accept approved ids")
	}

	// --- Wave 45 dual-control MinSignatures lite ---
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail("ephemeral multi-sig key A generation failed")
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail("ephemeral multi-sig key B generation failed")
	}
	const keyIDA = "selfcheck-adapter-a"
	const keyIDB = "selfcheck-adapter-b"
	multiKeys := adapter.AllowlistTrustedKeySet{keyIDA: pubA, keyIDB: pubB}

	raw2, err := adapter.SignAllowlistMulti(1, []string{adapter.IDNoop}, []struct {
		KeyID string
		Priv  ed25519.PrivateKey
	}{
		{KeyID: keyIDA, Priv: privA},
		{KeyID: keyIDB, Priv: privB},
	})
	if err != nil {
		return fail("SignAllowlistMulti 2-of-2 failed (multi-sig lite sign path broken)")
	}
	path2 := filepath.Join(dir, "multi2.json")
	if err := os.WriteFile(path2, raw2, 0o600); err != nil {
		return fail("write multi-sig 2-of-2 canary failed")
	}
	al2, err := adapter.LoadAllowlistFileOpts(adapter.LoadAllowlistOptions{
		Path:          path2,
		Keys:          multiKeys,
		RequireSigned: true,
		MinSignatures: 2,
	})
	if err != nil {
		return fail("2-of-2 multi-sig with MinSignatures=2 must verify: " + apperr.ModelMessage(err))
	}
	if !al2.Contains(adapter.IDNoop) {
		return fail("2-of-2 verified allowlist missing approved ids")
	}

	// 1-of-2 must fail closed when MinSignatures=2.
	raw1, err := adapter.SignAllowlistMulti(1, []string{adapter.IDNoop}, []struct {
		KeyID string
		Priv  ed25519.PrivateKey
	}{
		{KeyID: keyIDA, Priv: privA},
	})
	if err != nil {
		return fail("SignAllowlistMulti 1-signer failed")
	}
	path1 := filepath.Join(dir, "multi1.json")
	if err := os.WriteFile(path1, raw1, 0o600); err != nil {
		return fail("write multi-sig 1-of-2 canary failed")
	}
	_, err1 := adapter.LoadAllowlistFileOpts(adapter.LoadAllowlistOptions{
		Path:          path1,
		Keys:          multiKeys, // both keys trusted; only one signature present
		RequireSigned: true,
		MinSignatures: 2,
	})
	if err1 == nil {
		return fail("1-of-2 multi-sig with MinSignatures=2 must fail closed")
	}
	if apperr.CodeOf(err1) != apperr.CodePolicyDenial {
		return fail("1-of-2 threshold fail must be policy denial")
	}
	err1Msg := strings.ToLower(apperr.ModelMessage(err1))
	if !strings.Contains(err1Msg, "multi-sig") && !strings.Contains(err1Msg, "distinct") {
		return fail("1-of-2 fail missing multi-sig / distinct threshold guidance")
	}
	// Defense: never echo signature material.
	if strings.Contains(apperr.ModelMessage(err1), string(raw1)) {
		return fail("allowlist multi-sig error echoed file material")
	}

	// Ephemeral private keys are stack-local only; never reported.
	return SelfCheckItem{
		Name:    name,
		Status:  SelfCheckOK,
		Message: "allowlist Ed25519 lite + dual-control MinSignatures lite works (2-of-2 ok, 1-of-2 fails closed); cosign/SBOM/HSM/true multi-party threshold residual",
		Control: control,
		Details: map[string]any{
			"allowlist_ed25519_lite":          true,
			"allowlist_min_signatures_lite":   true,
			"sign_verify_ok":                  true,
			"bad_sig_fail_closed":             true,
			"signed_without_keys_fail_closed": true,
			"unsigned_require_signed_fail":    true,
			"pilot_unsigned_ok":               true,
			"min_signatures_2of2_verified":    true,
			"min_signatures_1of2_fail_closed": true,
			"residual_cosign":                 false,
			"residual_sbom":                   false,
			"residual_hsm":                    false,
			"residual_multi_party_provenance": false,
			"residual_true_threshold":         false,
			"residual_note":                   "cosign_sbom_hsm_true_threshold_multi_party_not_implemented",
		},
	}
}
