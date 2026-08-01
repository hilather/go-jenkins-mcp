package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// verifyEd25519 is a thin wrapper so ed25519.Verify is not re-imported in every file.
func verifyEd25519(publicKey ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(publicKey, message, sig)
}

// Bundle envelope schema (MGR-001).
const (
	// CurrentBundleSchemaVersion is the signed envelope schema version.
	CurrentBundleSchemaVersion = 1

	// AlgEd25519 is the only supported signature algorithm for MVP.
	AlgEd25519 = "ed25519"
)

// Signature state tokens (non-secret; status/doctor/CLI).
const (
	SigStateAbsent           = "absent"
	SigStateUnverifiedPilot  = "unverified_pilot"
	SigStatePresentField     = "present_field" // legacy stub field only
	SigStateVerified         = "verified"
	SigStateUnsignedRejected = "unsigned_rejected"
)

// BundleSignature is one Ed25519 signature entry in a multi-sig envelope (MGR-001 lite).
// Signature is base64 of the raw 64-byte Ed25519 signature over CanonicalSigningBytes.
type BundleSignature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"` // base64 raw Ed25519 signature (64 bytes)
}

// BundleEnvelope is a versioned signed enterprise policy bundle (MGR-001).
// Secret-free: no credentials. Signature material is base64 of the raw Ed25519
// signature over CanonicalSigningBytes (JSON of all fields except signature and
// signatures — multi-sig does not include signature fields in the signed payload).
//
// MVP single-sig (backward compatible):
//
//	{
//	  "schema_version": 1,
//	  "alg": "ed25519",
//	  "key_id": "corp-policy-2026",
//	  "issued_at": "2026-08-01T00:00:00Z",
//	  "not_after": "2027-08-01T00:00:00Z",
//	  "min_version": 1,
//	  "bundle_seq": 42,
//	  "overlay": { "version": 1, "force_read_only": true, "mode": "pilot" },
//	  "signature": "<base64>"
//	}
//
// Multi-sig lite (optional dual-control; same canonical body):
//
//	{
//	  "schema_version": 1,
//	  "alg": "ed25519",
//	  "key_id": "corp-policy-a",
//	  "min_version": 1,
//	  "bundle_seq": 42,
//	  "overlay": { "version": 1, "force_read_only": true },
//	  "signatures": [
//	    {"key_id":"corp-policy-a","signature":"<base64>"},
//	    {"key_id":"corp-policy-b","signature":"<base64>"}
//	  ]
//	}
type BundleEnvelope struct {
	SchemaVersion int     `json:"schema_version"`
	Alg           string  `json:"alg"`
	KeyID         string  `json:"key_id"`
	IssuedAt      string  `json:"issued_at,omitempty"` // RFC3339
	NotAfter      string  `json:"not_after,omitempty"` // RFC3339; empty = no expiry
	MinVersion    int     `json:"min_version"`         // min overlay schema the client must support
	BundleSeq     int64   `json:"bundle_seq"`          // monotonic; used for rollback detection
	Overlay       Overlay `json:"overlay"`
	// Signature is the MVP single-sig field (base64 raw Ed25519). Kept for
	// backward compatibility; used when Signatures is empty/absent.
	Signature string `json:"signature,omitempty"`
	// Signatures is optional multi-sig lite. When non-empty, verification uses
	// this array (MinSignatures distinct trusted key_ids) instead of Signature.
	Signatures []BundleSignature `json:"signatures,omitempty"`
}

// signingBody is the deterministic JSON payload that is signed/verified.
// Field order is fixed by the Go struct layout (encoding/json).
// Neither Signature nor Signatures are included.
type signingBody struct {
	SchemaVersion int     `json:"schema_version"`
	Alg           string  `json:"alg"`
	KeyID         string  `json:"key_id"`
	IssuedAt      string  `json:"issued_at,omitempty"`
	NotAfter      string  `json:"not_after,omitempty"`
	MinVersion    int     `json:"min_version"`
	BundleSeq     int64   `json:"bundle_seq"`
	Overlay       Overlay `json:"overlay"`
}

// LooksLikeBundle reports whether raw JSON is a signed envelope (has overlay object
// plus alg/key_id/signature envelope fields) rather than a plain Overlay document.
func LooksLikeBundle(raw []byte) bool {
	var probe struct {
		Overlay    json.RawMessage   `json:"overlay"`
		Signature  string            `json:"signature"`
		Signatures []BundleSignature `json:"signatures"`
		Alg        string            `json:"alg"`
		KeyID      string            `json:"key_id"`
		// Plain Overlay also has "version" at top level; envelopes use schema_version.
		SchemaVersion int `json:"schema_version"`
		Version       int `json:"version"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	if len(probe.Overlay) == 0 || probe.Overlay[0] != '{' {
		return false
	}
	// Envelope: schema_version present, or alg/key_id with nested overlay.
	if probe.SchemaVersion > 0 {
		return true
	}
	if strings.TrimSpace(probe.Alg) != "" && strings.TrimSpace(probe.KeyID) != "" {
		return true
	}
	// Nested overlay + signature(s) + no top-level overlay version field → envelope.
	if strings.TrimSpace(probe.Signature) != "" && probe.Version == 0 {
		return true
	}
	if len(probe.Signatures) > 0 && probe.Version == 0 {
		return true
	}
	return false
}

// HasMultiSignatures reports whether the envelope carries a non-empty multi-sig array.
func (env *BundleEnvelope) HasMultiSignatures() bool {
	if env == nil {
		return false
	}
	return len(env.Signatures) > 0
}

// CanonicalSigningBytes returns the exact bytes that must be signed/verified.
// Signature and Signatures are excluded from the payload (multi-sig signs the same body).
// Overlay.Signature is cleared so the nested document cannot smuggle a stub field.
func CanonicalSigningBytes(env *BundleEnvelope) ([]byte, error) {
	if env == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "policy bundle is nil")
	}
	ov := env.Overlay
	ov.Signature = "" // never part of signed overlay body
	body := signingBody{
		SchemaVersion: env.SchemaVersion,
		Alg:           env.Alg,
		KeyID:         env.KeyID,
		IssuedAt:      env.IssuedAt,
		NotAfter:      env.NotAfter,
		MinVersion:    env.MinVersion,
		BundleSeq:     env.BundleSeq,
		Overlay:       ov,
	}
	return json.Marshal(body)
}

// ContentHash returns a non-secret sha256 hex of the signing payload (for last-good cache).
func ContentHash(env *BundleEnvelope) (string, error) {
	b, err := CanonicalSigningBytes(env)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ValidateStructure checks envelope fields (no crypto).
func (env *BundleEnvelope) ValidateStructure() error {
	if env == nil {
		return apperr.New(apperr.CodeInvalidArgument, "policy bundle is nil")
	}
	if env.SchemaVersion != CurrentBundleSchemaVersion {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported policy bundle schema_version %d (want %d)",
				env.SchemaVersion, CurrentBundleSchemaVersion))
	}
	if strings.ToLower(strings.TrimSpace(env.Alg)) != AlgEd25519 {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported policy bundle alg %q (want %s)", env.Alg, AlgEd25519))
	}
	if strings.TrimSpace(env.KeyID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "policy bundle key_id is required")
	}
	if env.BundleSeq < 1 {
		return apperr.New(apperr.CodeInvalidArgument, "policy bundle bundle_seq must be >= 1")
	}
	if env.MinVersion < 1 {
		return apperr.New(apperr.CodeInvalidArgument, "policy bundle min_version must be >= 1")
	}
	// Clear any nested stub signature before overlay validation.
	env.Overlay.Signature = ""
	if err := env.Overlay.Validate(); err != nil {
		return apperr.Wrap(apperr.CodeInvalidArgument, "policy bundle overlay invalid", err)
	}
	// Multi-sig path: non-empty signatures[] is sufficient (top-level signature optional).
	if env.HasMultiSignatures() {
		for i, s := range env.Signatures {
			if strings.TrimSpace(s.KeyID) == "" {
				return apperr.New(apperr.CodeInvalidArgument,
					fmt.Sprintf("policy bundle signatures[%d].key_id is required", i))
			}
			if strings.TrimSpace(s.Signature) == "" {
				return apperr.New(apperr.CodePolicyDenial,
					fmt.Sprintf("policy bundle signatures[%d].signature is missing", i))
			}
		}
		return nil
	}
	// Single-sig MVP path.
	if strings.TrimSpace(env.Signature) == "" {
		return apperr.New(apperr.CodePolicyDenial, "policy bundle signature is missing")
	}
	return nil
}

// ParseNotAfter parses not_after when set. ok=false means no expiry constraint.
func (env *BundleEnvelope) ParseNotAfter() (t time.Time, ok bool, err error) {
	s := strings.TrimSpace(env.NotAfter)
	if s == "" {
		return time.Time{}, false, nil
	}
	t, err = time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false, apperr.Wrap(apperr.CodeInvalidArgument,
			"policy bundle not_after must be RFC3339", err)
	}
	return t, true, nil
}

// BundleSigner is one private key + key_id used by SignBundleMulti (tests / dual-control).
// Dev/admin only — never ship private keys in the product tree.
type BundleSigner struct {
	KeyID string
	Priv  ed25519.PrivateKey
}

// SignBundle creates a signature for env using the private key and sets env.Signature
// (MVP single-sig path). Clears Signatures so the envelope stays single-sig.
// Dev/admin only — never ship private keys in the product tree.
func SignBundle(env *BundleEnvelope, priv ed25519.PrivateKey) error {
	if err := prepareBundleForSigning(env); err != nil {
		return err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return apperr.New(apperr.CodeInvalidArgument, "ed25519 private key has wrong size")
	}
	if strings.TrimSpace(env.KeyID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "policy bundle key_id is required")
	}
	payload, err := CanonicalSigningBytes(env)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, payload)
	env.Signature = base64.StdEncoding.EncodeToString(sig)
	env.Signatures = nil // single-sig path
	return nil
}

// SignBundleMulti signs the same canonical body with each signer and sets env.Signatures.
// Top-level Signature is cleared. If env.KeyID is empty, it is set from the first signer
// (KeyID remains part of the signed body for all signers).
// Dev/admin and tests only — never ship private keys in the product tree.
func SignBundleMulti(env *BundleEnvelope, signers []BundleSigner) error {
	if err := prepareBundleForSigning(env); err != nil {
		return err
	}
	if len(signers) == 0 {
		return apperr.New(apperr.CodeInvalidArgument, "at least one signer is required")
	}
	if strings.TrimSpace(env.KeyID) == "" {
		env.KeyID = strings.TrimSpace(signers[0].KeyID)
	}
	if strings.TrimSpace(env.KeyID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "policy bundle key_id is required")
	}
	// Validate all signers before signing so we never leave a partial signatures array.
	for i, s := range signers {
		if strings.TrimSpace(s.KeyID) == "" {
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("signer[%d].key_id is required", i))
		}
		if len(s.Priv) != ed25519.PrivateKeySize {
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("signer[%d] ed25519 private key has wrong size", i))
		}
	}
	payload, err := CanonicalSigningBytes(env)
	if err != nil {
		return err
	}
	out := make([]BundleSignature, 0, len(signers))
	for _, s := range signers {
		sig := ed25519.Sign(s.Priv, payload)
		out = append(out, BundleSignature{
			KeyID:     strings.TrimSpace(s.KeyID),
			Signature: base64.StdEncoding.EncodeToString(sig),
		})
	}
	env.Signatures = out
	env.Signature = "" // multi-sig path uses signatures[] only
	return nil
}

// prepareBundleForSigning fills defaults and validates non-crypto structure for signing.
func prepareBundleForSigning(env *BundleEnvelope) error {
	if env == nil {
		return apperr.New(apperr.CodeInvalidArgument, "policy bundle is nil")
	}
	if env.SchemaVersion == 0 {
		env.SchemaVersion = CurrentBundleSchemaVersion
	}
	if env.Alg == "" {
		env.Alg = AlgEd25519
	}
	env.Overlay.Signature = ""
	if env.SchemaVersion != CurrentBundleSchemaVersion {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported policy bundle schema_version %d (want %d)",
				env.SchemaVersion, CurrentBundleSchemaVersion))
	}
	if strings.ToLower(strings.TrimSpace(env.Alg)) != AlgEd25519 {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported policy bundle alg %q (want %s)", env.Alg, AlgEd25519))
	}
	if env.BundleSeq < 1 {
		return apperr.New(apperr.CodeInvalidArgument, "policy bundle bundle_seq must be >= 1")
	}
	if env.MinVersion < 1 {
		return apperr.New(apperr.CodeInvalidArgument, "policy bundle min_version must be >= 1")
	}
	if err := env.Overlay.Validate(); err != nil {
		return apperr.Wrap(apperr.CodeInvalidArgument, "policy bundle overlay invalid", err)
	}
	// Optional not_after must parse if set.
	if _, _, err := env.ParseNotAfter(); err != nil {
		return err
	}
	return nil
}

// DecodeSignature returns the raw Ed25519 signature bytes.
func DecodeSignature(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return nil, apperr.New(apperr.CodePolicyDenial, "policy bundle signature is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Try raw URL encoding as a convenience; still fail closed on garbage.
		raw, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, apperr.New(apperr.CodePolicyDenial, "policy bundle signature is not valid base64")
		}
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, apperr.New(apperr.CodePolicyDenial,
			fmt.Sprintf("policy bundle signature has wrong length %d", len(raw)))
	}
	return raw, nil
}

// MarshalBundle returns pretty-printed JSON for writing a bundle file (secret-free).
func MarshalBundle(env *BundleEnvelope) ([]byte, error) {
	if env == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "policy bundle is nil")
	}
	return json.MarshalIndent(env, "", "  ")
}
