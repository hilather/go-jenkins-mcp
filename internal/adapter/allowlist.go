package adapter

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// EnvAdapterAllowlistMinSignatures is the dual-control lite threshold for
// multi-sig adapter allowlists (Wave 45 / INT-001). When signatures[] is
// non-empty, at least this many distinct trusted key_ids must present a valid
// signature. Unset/empty/0 → 1. Invalid or > AbsoluteMaxAllowlistMinSignatures
// fails closed at resolve. Single-sig top-level key_id+signature ignores this.
const EnvAdapterAllowlistMinSignatures = "JENKINS_MCP_ADAPTER_ALLOWLIST_MIN_SIGNATURES"

// DefaultAllowlistMinSignatures is the multi-sig floor when unset/0/negative.
const DefaultAllowlistMinSignatures = 1

// AbsoluteMaxAllowlistMinSignatures is the process fail-closed ceiling for
// MinSignatures (absurd multi-sig counts are rejected, not clamped).
const AbsoluteMaxAllowlistMinSignatures = 16

// Allowlist is the set of adapter IDs approved for enablement.
// Deny by default: empty allowlist means no adapters may be registered unless they
// are built-in test factories and AllowBuiltins is true on the Registry.
type Allowlist struct {
	// IDs is the approved adapter identifier set (lowercase).
	IDs map[string]struct{}
}

// EmptyAllowlist returns a deny-all allowlist.
func EmptyAllowlist() Allowlist {
	return Allowlist{IDs: map[string]struct{}{}}
}

// AllowlistFromIDs builds an allowlist from explicit IDs (tests / CLI).
func AllowlistFromIDs(ids ...string) Allowlist {
	a := EmptyAllowlist()
	for _, id := range ids {
		id = normalizeID(id)
		if id == "" {
			continue
		}
		a.IDs[id] = struct{}{}
	}
	return a
}

// Contains reports whether id is approved.
func (a Allowlist) Contains(id string) bool {
	if a.IDs == nil {
		return false
	}
	_, ok := a.IDs[normalizeID(id)]
	return ok
}

// allowlistSignatureEntry is one optional multi-sig entry (provenance lite).
type allowlistSignatureEntry struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"` // base64 raw 64-byte Ed25519 signature
}

// allowlistFile is the on-disk JSON shape for --adapter-allowlist.
//
// Pilot (unsigned):
//
//	{"version": 1, "approved": ["clock", "noop"]}
//
// Signed (Ed25519 provenance lite):
//
//	{"version": 1, "approved": ["clock", "noop"], "key_id": "adapter-ops-1", "signature": "<base64>"}
//
// Optional multi-sig array (same canonical body):
//
//	{"version": 1, "approved": [...], "signatures": [{"key_id":"...","signature":"..."}]}
//
// Canonical signing payload is deterministic JSON of only {version, approved}
// (approved normalized lower-case and sorted). Signature fields are never signed.
type allowlistFile struct {
	Approved   []string                  `json:"approved"`
	Version    int                       `json:"version,omitempty"`
	KeyID      string                    `json:"key_id,omitempty"`
	Signature  string                    `json:"signature,omitempty"`
	Signatures []allowlistSignatureEntry `json:"signatures,omitempty"`
}

// allowlistSigningBody is the only material covered by Ed25519 signatures.
type allowlistSigningBody struct {
	Version  int      `json:"version"`
	Approved []string `json:"approved"`
}

// LoadAllowlistFile reads an approved-adapter list from path (pilot / unsigned path).
// Missing path returns EmptyAllowlist without error only when path is empty;
// a non-empty path that cannot be read fails closed.
//
// Signature fields, when present, are ignored here — use LoadAllowlistFileWithKeys
// for fail-closed provenance (signature present without keys, require-signed, verify).
func LoadAllowlistFile(path string) (Allowlist, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return EmptyAllowlist(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return EmptyAllowlist(), apperr.Wrap(apperr.CodeInvalidArgument,
			fmt.Sprintf("adapter allowlist %s", sanitizePathBase(path)), err)
	}
	var f allowlistFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return EmptyAllowlist(), apperr.Wrap(apperr.CodeInvalidArgument,
			"adapter allowlist JSON", err)
	}
	return AllowlistFromIDs(f.Approved...), nil
}

// LoadAllowlistOptions configures LoadAllowlistFileOpts (Wave 45 MinSignatures).
// Prefer this over LoadAllowlistFileWithKeys when dual-control multi-sig floor
// is required.
type LoadAllowlistOptions struct {
	Path          string
	Keys          AllowlistTrustedKeySet
	RequireSigned bool
	// MinSignatures is the multi-sig lite threshold: when signatures[] is
	// non-empty, at least this many distinct trusted key_ids must verify.
	// 0 or negative ⇒ DefaultAllowlistMinSignatures (1). Ignored for the
	// single-sig top-level key_id+signature path.
	MinSignatures int
}

// LoadAllowlistFileWithKeys loads an allowlist with optional Ed25519 verification.
// MinSignatures defaults to 1 (back-compat wrapper around LoadAllowlistFileOpts).
//
// Rules (fail closed; never put keys/signatures in errors):
//   - Empty path → EmptyAllowlist, nil error.
//   - Unreadable path / bad JSON → error.
//   - keys empty && file unsigned → accept approved IDs (pilot).
//   - keys empty && file has signature fields → fail closed
//     ("signature present but no trusted keys configured").
//   - keys non-empty && file unsigned && requireSigned → fail closed.
//   - keys non-empty && signed → verify Ed25519 (unknown key_id / bad sig → fail).
//   - multi-sig: all entries verify + distinct trusted key_ids ≥ MinSignatures.
//   - keys non-empty && file unsigned && !requireSigned → accept (tests only;
//     serve sets requireSigned when keys are non-empty).
func LoadAllowlistFileWithKeys(path string, keys AllowlistTrustedKeySet, requireSigned bool) (Allowlist, error) {
	return LoadAllowlistFileOpts(LoadAllowlistOptions{
		Path:          path,
		Keys:          keys,
		RequireSigned: requireSigned,
		MinSignatures: DefaultAllowlistMinSignatures,
	})
}

// LoadAllowlistFileOpts loads an allowlist with optional Ed25519 verification and
// multi-sig MinSignatures dual-control lite floor (Wave 45 / INT-001).
func LoadAllowlistFileOpts(opts LoadAllowlistOptions) (Allowlist, error) {
	path := strings.TrimSpace(opts.Path)
	if path == "" {
		return EmptyAllowlist(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return EmptyAllowlist(), apperr.Wrap(apperr.CodeInvalidArgument,
			fmt.Sprintf("adapter allowlist %s", sanitizePathBase(path)), err)
	}
	var f allowlistFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return EmptyAllowlist(), apperr.Wrap(apperr.CodeInvalidArgument,
			"adapter allowlist JSON", err)
	}

	hasSig := f.hasSignatureMaterial()
	keys := opts.Keys
	keysLen := keys.Len()

	if hasSig && keysLen == 0 {
		return EmptyAllowlist(), apperr.New(apperr.CodePolicyDenial,
			"adapter allowlist signature present but no trusted keys configured (fail closed)")
	}
	if !hasSig {
		if opts.RequireSigned && keysLen > 0 {
			return EmptyAllowlist(), apperr.New(apperr.CodePolicyDenial,
				"adapter allowlist is unsigned but trusted keys require a signature (fail closed)")
		}
		return AllowlistFromIDs(f.Approved...), nil
	}

	// Signed path: verify before accepting approved IDs.
	if err := verifyAllowlistSignatures(&f, keys, opts.MinSignatures); err != nil {
		return EmptyAllowlist(), err
	}
	return AllowlistFromIDs(f.Approved...), nil
}

// ResolveAllowlistMinSignatures resolves the multi-sig dual-control lite floor.
//
// Precedence (later wins): DefaultAllowlistMinSignatures → envVal → flagVal.
// Empty or explicit "0" at the winning layer means DefaultAllowlistMinSignatures (1).
// Invalid integers, negatives, and values above AbsoluteMaxAllowlistMinSignatures
// fail closed (no clamp). Never logs secrets.
func ResolveAllowlistMinSignatures(flagVal, envVal string) (int, error) {
	n := DefaultAllowlistMinSignatures
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseAllowlistMinSignaturesValue(raw, "env "+EnvAdapterAllowlistMinSignatures)
		if err != nil {
			return 0, err
		}
		n = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseAllowlistMinSignaturesValue(raw, "flag --adapter-allowlist-min-signatures")
		if err != nil {
			return 0, err
		}
		n = v
	}
	if n > AbsoluteMaxAllowlistMinSignatures {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("adapter allowlist min-signatures exceeds absolute max %d (fail closed)",
				AbsoluteMaxAllowlistMinSignatures))
	}
	return n, nil
}

func parseAllowlistMinSignaturesValue(raw, source string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("adapter allowlist min-signatures %s is not a valid integer (fail closed)", source))
	}
	if n < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("adapter allowlist min-signatures %s must not be negative (fail closed)", source))
	}
	if n == 0 {
		return DefaultAllowlistMinSignatures, nil
	}
	if n > AbsoluteMaxAllowlistMinSignatures {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("adapter allowlist min-signatures %s exceeds absolute max %d (fail closed)",
				source, AbsoluteMaxAllowlistMinSignatures))
	}
	return n, nil
}

func (f *allowlistFile) hasSignatureMaterial() bool {
	if f == nil {
		return false
	}
	if strings.TrimSpace(f.KeyID) != "" || strings.TrimSpace(f.Signature) != "" {
		return true
	}
	if len(f.Signatures) > 0 {
		return true
	}
	return false
}

func (f *allowlistFile) hasMultiSignatures() bool {
	return f != nil && len(f.Signatures) > 0
}

// CanonicalAllowlistSigningBytes returns deterministic JSON for {version, approved}
// with approved IDs normalized (lower/trim) and sorted. Signature fields excluded.
func CanonicalAllowlistSigningBytes(version int, approved []string) ([]byte, error) {
	norm := normalizeApprovedForSigning(approved)
	body := allowlistSigningBody{
		Version:  version,
		Approved: norm,
	}
	return json.Marshal(body)
}

func normalizeApprovedForSigning(approved []string) []string {
	out := make([]string, 0, len(approved))
	seen := make(map[string]struct{}, len(approved))
	for _, id := range approved {
		id = normalizeID(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func verifyAllowlistSignatures(f *allowlistFile, keys AllowlistTrustedKeySet, minSignatures int) error {
	payload, err := CanonicalAllowlistSigningBytes(f.Version, f.Approved)
	if err != nil {
		return apperr.Wrap(apperr.CodePolicyDenial,
			"adapter allowlist canonicalization failed", err)
	}

	if f.hasMultiSignatures() {
		// Multi-sig dual-control lite (Wave 45): every listed entry must verify
		// against trusted keys, and distinct trusted key_ids ≥ minSignatures.
		// True t-of-n threshold crypto / HSM remain residual.
		minSigs := minSignatures
		if minSigs <= 0 {
			minSigs = DefaultAllowlistMinSignatures
		}
		valid := make(map[string]struct{}, len(f.Signatures))
		for i, entry := range f.Signatures {
			keyID := strings.TrimSpace(entry.KeyID)
			if keyID == "" {
				return apperr.New(apperr.CodePolicyDenial,
					fmt.Sprintf("adapter allowlist signatures[%d].key_id is empty (fail closed)", i))
			}
			pub, ok := keys.Get(keyID)
			if !ok {
				return apperr.New(apperr.CodePolicyDenial,
					fmt.Sprintf("adapter allowlist key_id %q is not trusted (fail closed)", keyID))
			}
			sig, err := decodeAllowlistSignature(entry.Signature)
			if err != nil {
				return err
			}
			if !ed25519.Verify(pub, payload, sig) {
				return apperr.New(apperr.CodePolicyDenial,
					"adapter allowlist signature verification failed (fail closed)")
			}
			valid[keyID] = struct{}{}
		}
		if len(valid) < minSigs {
			return apperr.New(apperr.CodePolicyDenial,
				fmt.Sprintf("adapter allowlist multi-sig requires %d distinct trusted signatures, got %d (fail closed)",
					minSigs, len(valid)))
		}
		return nil
	}

	// Single-sig path (top-level key_id + signature). MinSignatures does not apply.
	keyID := strings.TrimSpace(f.KeyID)
	if keyID == "" {
		return apperr.New(apperr.CodePolicyDenial,
			"adapter allowlist key_id is missing (fail closed)")
	}
	pub, ok := keys.Get(keyID)
	if !ok {
		return apperr.New(apperr.CodePolicyDenial,
			fmt.Sprintf("adapter allowlist key_id %q is not trusted (fail closed)", keyID))
	}
	sig, err := decodeAllowlistSignature(f.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return apperr.New(apperr.CodePolicyDenial,
			"adapter allowlist signature verification failed (fail closed)")
	}
	return nil
}

func decodeAllowlistSignature(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return nil, apperr.New(apperr.CodePolicyDenial,
			"adapter allowlist signature is empty (fail closed)")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, apperr.New(apperr.CodePolicyDenial,
				"adapter allowlist signature is not valid base64 (fail closed)")
		}
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, apperr.New(apperr.CodePolicyDenial,
			fmt.Sprintf("adapter allowlist signature has wrong length %d (fail closed)", len(raw)))
	}
	return raw, nil
}

// SignAllowlist builds a signed allowlist document (single-sig path).
// Dev/tests/self-check only — never ship private keys in the product tree.
// Errors never include key or signature material.
func SignAllowlist(version int, approved []string, priv ed25519.PrivateKey, keyID string) ([]byte, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "adapter allowlist key_id is required")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, apperr.New(apperr.CodeInvalidArgument, "ed25519 private key has wrong size")
	}
	norm := normalizeApprovedForSigning(approved)
	payload, err := CanonicalAllowlistSigningBytes(version, norm)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "adapter allowlist canonicalization failed", err)
	}
	sig := ed25519.Sign(priv, payload)
	doc := allowlistFile{
		Version:   version,
		Approved:  norm,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	return json.MarshalIndent(doc, "", "  ")
}

// SignAllowlistMulti builds a multi-sig allowlist document (signatures[] path).
// Dev/tests only. Top-level key_id/signature are left empty.
func SignAllowlistMulti(version int, approved []string, signers []struct {
	KeyID string
	Priv  ed25519.PrivateKey
}) ([]byte, error) {
	if len(signers) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "at least one signer is required")
	}
	norm := normalizeApprovedForSigning(approved)
	payload, err := CanonicalAllowlistSigningBytes(version, norm)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "adapter allowlist canonicalization failed", err)
	}
	entries := make([]allowlistSignatureEntry, 0, len(signers))
	for i, s := range signers {
		id := strings.TrimSpace(s.KeyID)
		if id == "" {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("signer[%d].key_id is required", i))
		}
		if len(s.Priv) != ed25519.PrivateKeySize {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("signer[%d] ed25519 private key has wrong size", i))
		}
		sig := ed25519.Sign(s.Priv, payload)
		entries = append(entries, allowlistSignatureEntry{
			KeyID:     id,
			Signature: base64.StdEncoding.EncodeToString(sig),
		})
	}
	doc := allowlistFile{
		Version:    version,
		Approved:   norm,
		Signatures: entries,
	}
	return json.MarshalIndent(doc, "", "  ")
}

func normalizeID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}
