package diagnostics

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// checkPolicyMultisigLiteResidual is Wave 42 / MGR-001 residual honesty:
// proves multi-sig lite MinSignatures (distinct trusted Ed25519 keys) works
// offline via exported policy APIs, and documents that true t-of-n threshold
// crypto and HSM-backed signing are not implemented.
//
// Canary (ephemeral keys only; never written to disk or report):
//   - 2-of-2 dual-sig envelope verifies with MinSignatures=2
//   - 1-of-2 dual-sig envelope fails closed when MinSignatures=2
//
// Status OK when lite path works; Details residual_true_threshold=false,
// residual_hsm=false, multi_sig_lite=true. No private keys, signatures, or
// PEM material in Message/Details.
func checkPolicyMultisigLiteResidual() SelfCheckItem {
	const (
		name    = "policy_multisig_lite_residual"
		control = "MGR-001"
	)
	fail := func(msg string) SelfCheckItem {
		return SelfCheckItem{
			Name:    name,
			Status:  SelfCheckFail,
			Message: msg,
			Control: control,
		}
	}

	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail("ephemeral ed25519 key A generation failed")
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail("ephemeral ed25519 key B generation failed")
	}
	// Synthetic key_ids only (non-secret). Never put priv/pub/sig bytes in report.
	const keyIDA = "selfcheck-a"
	const keyIDB = "selfcheck-b"
	keys := policy.TrustedKeySet{
		keyIDA: pubA,
		keyIDB: pubB,
	}

	// --- 2-of-2 multi-sig must verify when MinSignatures=2 ---
	env2 := &policy.BundleEnvelope{
		SchemaVersion: policy.CurrentBundleSchemaVersion,
		Alg:           policy.AlgEd25519,
		KeyID:         keyIDA,
		MinVersion:    policy.CurrentOverlayVersion,
		BundleSeq:     1,
		Overlay: policy.Overlay{
			Version:       policy.CurrentOverlayVersion,
			ForceReadOnly: true,
			Mode:          policy.ModePilot,
		},
	}
	if err := policy.SignBundleMulti(env2, []policy.BundleSigner{
		{KeyID: keyIDA, Priv: privA},
		{KeyID: keyIDB, Priv: privB},
	}); err != nil {
		return fail("SignBundleMulti 2-of-2 failed (multi-sig lite sign path broken)")
	}
	if !env2.HasMultiSignatures() || len(env2.Signatures) != 2 {
		return fail("SignBundleMulti did not populate signatures[] for dual-control")
	}
	if strings.TrimSpace(env2.Signature) != "" {
		return fail("multi-sig envelope must leave top-level signature empty")
	}
	raw2, err := policy.MarshalBundle(env2)
	if err != nil {
		return fail("MarshalBundle 2-of-2 failed")
	}
	v2 := policy.Ed25519SignatureVerifier{
		Keys:          keys,
		RequireSigned: true,
		MinSignatures: 2,
	}
	// Verify uses exported SignatureVerifier path; overlay non-nil is required.
	ov := env2.Overlay
	if err := v2.Verify(&ov, raw2); err != nil {
		// ModelMessage is secret-free by policy package contract.
		return fail("2-of-2 multi-sig with MinSignatures=2 must verify: " + apperr.ModelMessage(err))
	}

	// --- 1-of-2 must fail closed when MinSignatures=2 ---
	env1 := &policy.BundleEnvelope{
		SchemaVersion: policy.CurrentBundleSchemaVersion,
		Alg:           policy.AlgEd25519,
		KeyID:         keyIDA,
		MinVersion:    policy.CurrentOverlayVersion,
		BundleSeq:     2,
		Overlay: policy.Overlay{
			Version:       policy.CurrentOverlayVersion,
			ForceReadOnly: true,
			Mode:          policy.ModePilot,
		},
	}
	if err := policy.SignBundleMulti(env1, []policy.BundleSigner{
		{KeyID: keyIDA, Priv: privA},
	}); err != nil {
		return fail("SignBundleMulti 1-signer failed")
	}
	raw1, err := policy.MarshalBundle(env1)
	if err != nil {
		return fail("MarshalBundle 1-of-2 failed")
	}
	v1 := policy.Ed25519SignatureVerifier{
		Keys:          keys, // both keys trusted; only one signature present
		RequireSigned: true,
		MinSignatures: 2,
	}
	ov1 := env1.Overlay
	err1 := v1.Verify(&ov1, raw1)
	if err1 == nil {
		return fail("1-of-2 multi-sig with MinSignatures=2 must fail closed")
	}
	if apperr.CodeOf(err1) != apperr.CodePolicyDenial {
		return fail("1-of-2 threshold fail must be policy denial")
	}
	errMsg := strings.ToLower(apperr.ModelMessage(err1))
	if !strings.Contains(errMsg, "multi-sig") && !strings.Contains(errMsg, "distinct") {
		return fail("1-of-2 fail missing multi-sig / distinct threshold guidance")
	}
	// Defense: never echo signature material (base64 raw Ed25519 is long).
	for _, sig := range env1.Signatures {
		if sig.Signature != "" && strings.Contains(apperr.ModelMessage(err1), sig.Signature) {
			return fail("policy multi-sig error echoed signature material")
		}
	}

	// Ephemeral private keys are stack-local only; never reported.
	return SelfCheckItem{
		Name:    name,
		Status:  SelfCheckOK,
		Message: "multi-sig lite MinSignatures works (2-of-2 ok, 1-of-2 fails closed); true t-of-n threshold crypto and HSM not implemented",
		Control: control,
		Details: map[string]any{
			"multi_sig_lite":                  true,
			"min_signatures_2of2_verified":    true,
			"min_signatures_1of2_fail_closed": true,
			"residual_true_threshold":         false,
			"residual_hsm":                    false,
			"ed25519_distinct_trusted_keys":   true,
			// Residual honesty (documented, not a fail): full threshold / HSM out of scope.
			"residual_note": "true_threshold_crypto_and_hsm_not_implemented",
		},
	}
}
