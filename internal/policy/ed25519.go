package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Ed25519SignatureVerifier verifies signed policy bundle envelopes (MGR-001).
//
// Fail-closed rules:
//   - Unknown key_id
//   - Invalid / wrong signature
//   - Multi-sig: fewer than MinSignatures valid distinct key_ids
//   - Expired not_after
//   - min_version > CurrentOverlayVersion (client too old for this bundle)
//   - bundle_seq downgrade vs last-good cache
//   - RequireSigned: plain/unsigned overlays rejected
//
// Keys and signature bytes never appear in returned error strings.
type Ed25519SignatureVerifier struct {
	// Keys maps key_id → public key. Required (empty set rejects all signed bundles).
	Keys TrustedKeySet
	// Cache is optional last-good store for rollback detection.
	Cache *LastGoodCache
	// RequireSigned rejects plain Overlay documents (no envelope).
	// When trusted keys are configured, LoadFromEnviron sets this true.
	RequireSigned bool
	// MinSignatures is the multi-sig lite threshold: when the envelope has a
	// non-empty signatures[] array, at least this many distinct trusted key_ids
	// must present a valid signature. 0 or negative ⇒ 1 (single valid multi-sig
	// entry is enough). Set to 2 for dual-control (2-of-N distinct keys).
	// Ignored for MVP single-sig envelopes that only set top-level signature.
	MinSignatures int
	// Now overrides time.Now for expiry tests. Nil ⇒ time.Now().UTC.
	Now func() time.Time
	// AppOverlayVersion is the client overlay schema; 0 ⇒ CurrentOverlayVersion.
	AppOverlayVersion int
	// OnVerified is optional hook after successful verify (tests).
	OnVerified func(env *BundleEnvelope)
}

// Verify implements SignatureVerifier.
//
// raw must be the exact file bytes. When raw looks like a BundleEnvelope, full
// cryptographic verification runs. When raw is a plain Overlay:
//   - RequireSigned → error
//   - else → accept (pilot Nop-compatible path; caller sets signature_state)
func (v Ed25519SignatureVerifier) Verify(overlay *Overlay, raw []byte) error {
	if overlay == nil {
		return apperr.New(apperr.CodePolicyDenial, "policy overlay is nil")
	}
	if LooksLikeBundle(raw) {
		return v.verifyBundle(raw)
	}
	// Plain overlay document.
	if v.RequireSigned {
		return apperr.New(apperr.CodePolicyDenial,
			"unsigned policy overlay rejected (signed bundle required when trusted keys are configured or policy is required)")
	}
	return nil
}

func (v Ed25519SignatureVerifier) verifyBundle(raw []byte) error {
	var env BundleEnvelope
	if err := strictUnmarshalBundle(raw, &env); err != nil {
		return err
	}
	if err := env.ValidateStructure(); err != nil {
		return err
	}

	appVer := v.AppOverlayVersion
	if appVer == 0 {
		appVer = CurrentOverlayVersion
	}
	if env.MinVersion > appVer {
		return apperr.New(apperr.CodePolicyDenial,
			fmt.Sprintf("policy bundle min_version %d exceeds client overlay version %d (fail closed)",
				env.MinVersion, appVer))
	}

	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	if exp, ok, err := env.ParseNotAfter(); err != nil {
		return apperr.Wrap(apperr.CodePolicyDenial, "policy bundle not_after invalid (fail closed)", err)
	} else if ok && now.After(exp) {
		// Inclusive not_after: valid while now <= not_after.
		return apperr.New(apperr.CodePolicyDenial,
			fmt.Sprintf("policy bundle expired at %s (fail closed)", exp.UTC().Format(time.RFC3339)))
	}

	payload, err := CanonicalSigningBytes(&env)
	if err != nil {
		return apperr.Wrap(apperr.CodePolicyDenial, "policy bundle canonicalization failed", err)
	}

	// Multi-sig lite: when signatures[] is present and non-empty, verify each
	// entry and require MinSignatures valid distinct trusted key_ids.
	if env.HasMultiSignatures() {
		if err := v.verifyMultiSignatures(&env, payload); err != nil {
			return err
		}
	} else {
		// MVP single-sig path (top-level signature + key_id).
		keyID := strings.TrimSpace(env.KeyID)
		pub, ok := v.Keys.Get(keyID)
		if !ok {
			return apperr.New(apperr.CodePolicyDenial,
				fmt.Sprintf("policy bundle key_id %q is not trusted (fail closed)", keyID))
		}
		sig, err := DecodeSignature(env.Signature)
		if err != nil {
			return err
		}
		if !verifyEd25519(pub, payload, sig) {
			return apperr.New(apperr.CodePolicyDenial,
				"policy bundle signature verification failed (fail closed)")
		}
	}

	hash, err := ContentHash(&env)
	if err != nil {
		return err
	}
	if v.Cache != nil {
		if err := v.Cache.CheckDowngrade(env.BundleSeq, hash); err != nil {
			return err
		}
	}

	// Success path: update last-good (best-effort write; verification already succeeded).
	if v.Cache != nil {
		if err := v.Cache.Store(&env, hash, now); err != nil {
			// Fail closed on cache write errors so rollback detection cannot be bypassed
			// by a full disk after first accept without persistence.
			return apperr.Wrap(apperr.CodePolicyDenial, "policy last-good cache update failed (fail closed)", err)
		}
	}
	if v.OnVerified != nil {
		v.OnVerified(&env)
	}
	return nil
}

// verifyMultiSignatures verifies every signatures[] entry against the trusted
// key set. Fail-closed on unknown key_id or invalid signature. Requires at
// least MinSignatures (default 1) valid distinct key_ids.
func (v Ed25519SignatureVerifier) verifyMultiSignatures(env *BundleEnvelope, payload []byte) error {
	minSigs := v.MinSignatures
	if minSigs <= 0 {
		minSigs = 1
	}
	valid := make(map[string]struct{}, len(env.Signatures))
	for i, entry := range env.Signatures {
		keyID := strings.TrimSpace(entry.KeyID)
		if keyID == "" {
			return apperr.New(apperr.CodePolicyDenial,
				fmt.Sprintf("policy bundle signatures[%d].key_id is empty (fail closed)", i))
		}
		pub, ok := v.Keys.Get(keyID)
		if !ok {
			return apperr.New(apperr.CodePolicyDenial,
				fmt.Sprintf("policy bundle key_id %q is not trusted (fail closed)", keyID))
		}
		sig, err := DecodeSignature(entry.Signature)
		if err != nil {
			return err
		}
		if !verifyEd25519(pub, payload, sig) {
			return apperr.New(apperr.CodePolicyDenial,
				"policy bundle signature verification failed (fail closed)")
		}
		valid[keyID] = struct{}{}
	}
	if len(valid) < minSigs {
		return apperr.New(apperr.CodePolicyDenial,
			fmt.Sprintf("policy bundle multi-sig requires %d distinct trusted signatures, got %d (fail closed)",
				minSigs, len(valid)))
	}
	return nil
}

// EnvPolicyMinSignatures is the optional dual-control threshold for multi-sig
// bundles (Wave 34). When set to an integer ≥1, multi-sig envelopes must present
// at least that many distinct trusted signatures. Unset/invalid ⇒ 1.
const EnvPolicyMinSignatures = "JENKINS_MCP_POLICY_MIN_SIGNATURES"

// BundleVerifier is a convenience constructor. MinSignatures is taken from
// EnvPolicyMinSignatures when set, else defaults to 1 (single-sig friendly).
func BundleVerifier(keys TrustedKeySet, cache *LastGoodCache, requireSigned bool) Ed25519SignatureVerifier {
	return Ed25519SignatureVerifier{
		Keys:          keys,
		Cache:         cache,
		RequireSigned: requireSigned,
		MinSignatures: minSignaturesFromEnv(),
	}
}

// minSignaturesFromEnv parses EnvPolicyMinSignatures (default 1).
func minSignaturesFromEnv() int {
	raw := strings.TrimSpace(os.Getenv(EnvPolicyMinSignatures))
	if raw == "" {
		return 1
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 1
	}
	// Cap for fail-closed sanity (not a full t-of-n crypto threshold).
	if n > 16 {
		return 16
	}
	return n
}

func strictUnmarshalBundle(raw []byte, env *BundleEnvelope) error {
	if err := json.Unmarshal(raw, env); err != nil {
		return apperr.Wrap(apperr.CodePolicyDenial,
			"enterprise policy bundle is invalid JSON (fail closed)", err)
	}
	return nil
}
