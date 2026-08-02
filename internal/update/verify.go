package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// VerifyOptions controls fail-closed verification of an update manifest.
type VerifyOptions struct {
	// Keys are trusted Ed25519 public keys. When non-empty, a valid signature is required.
	Keys TrustedKeySet
	// AllowUnsigned permits unsigned manifests only when Keys is empty (pilot residual).
	// When Keys is non-empty, this flag is ignored and signatures are always required.
	AllowUnsigned bool
	// Channel when non-empty must match manifest.Channel (case-insensitive).
	Channel string
	// AppVersion is the running binary version for min_app_version checks.
	AppVersion string
	// ClientSchema is the client's max supported schema; 0 ⇒ CurrentSchemaVersion.
	ClientSchema int
	// Now overrides time.Now for expiry tests. Nil ⇒ time.Now().UTC.
	Now func() time.Time
}

// VerifyResult is a secret-free outcome of manifest verification.
type VerifyResult struct {
	Manifest       *Manifest `json:"-"`
	SignatureState string    `json:"signature_state"`
	KeyID          string    `json:"key_id,omitempty"`
	Channel        string    `json:"channel,omitempty"`
	Version        string    `json:"version,omitempty"`
	SchemaVersion  int       `json:"schema_version,omitempty"`
	Message        string    `json:"message,omitempty"`
}

// VerifyManifest parses and verifies raw manifest bytes under opts (fail closed).
//
// Rules:
//   - Structure / channel / min_schema / min_app_version / not_after always checked.
//   - Keys present → require ≥1 valid Ed25519 signature from a trusted key_id.
//   - Keys empty + AllowUnsigned → accept with signature_state=unverified_pilot
//     (unsigned or present-but-untrusted signatures still require AllowUnsigned when
//     no trusted key can verify; signed with unknown keys is rejected).
//   - Keys empty + !AllowUnsigned → reject.
//   - Signature material never appears in returned errors.
func VerifyManifest(raw []byte, opts VerifyOptions) (*VerifyResult, error) {
	m, err := ParseManifest(raw)
	if err != nil {
		return &VerifyResult{SignatureState: SigStateRejected}, err
	}
	if err := m.ValidateStructure(); err != nil {
		return &VerifyResult{SignatureState: SigStateRejected, SchemaVersion: m.SchemaVersion}, err
	}

	clientSchema := opts.ClientSchema
	if clientSchema == 0 {
		clientSchema = CurrentSchemaVersion
	}
	if m.MinSchema > 0 && m.MinSchema > clientSchema {
		return &VerifyResult{SignatureState: SigStateRejected, SchemaVersion: m.SchemaVersion},
			apperr.New(apperr.CodePolicyDenial,
				fmt.Sprintf("update manifest min_schema %d exceeds client schema %d (fail closed)",
					m.MinSchema, clientSchema))
	}

	if ch := strings.TrimSpace(opts.Channel); ch != "" {
		if m.Channel != "" && !strings.EqualFold(m.Channel, ch) {
			return &VerifyResult{SignatureState: SigStateRejected, SchemaVersion: m.SchemaVersion},
				apperr.New(apperr.CodeNotFound,
					fmt.Sprintf("manifest channel %q does not match requested %q", m.Channel, ch))
		}
	}

	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}
	if exp, ok, err := m.ParseNotAfter(); err != nil {
		return &VerifyResult{SignatureState: SigStateRejected, SchemaVersion: m.SchemaVersion}, err
	} else if ok && now.After(exp) {
		// Inclusive not_after: valid while now <= not_after.
		return &VerifyResult{SignatureState: SigStateRejected, SchemaVersion: m.SchemaVersion},
			apperr.New(apperr.CodePolicyDenial,
				fmt.Sprintf("update manifest expired at %s (fail closed)", exp.UTC().Format(time.RFC3339)))
	}

	if minApp := strings.TrimSpace(m.MinAppVersion); minApp != "" {
		app := strings.TrimSpace(opts.AppVersion)
		if app == "" {
			return &VerifyResult{SignatureState: SigStateRejected, SchemaVersion: m.SchemaVersion},
				apperr.New(apperr.CodePolicyDenial,
					"update manifest requires min_app_version but app version is unknown (fail closed)")
		}
		// App must be >= min_app_version.
		// CompareVersions(app, minApp)=="newer" means minApp > app ⇒ app too old.
		switch CompareVersions(app, minApp) {
		case "newer":
			return &VerifyResult{SignatureState: SigStateRejected, SchemaVersion: m.SchemaVersion},
				apperr.New(apperr.CodePolicyDenial,
					fmt.Sprintf("update manifest min_app_version %s exceeds app version %s (fail closed)",
						minApp, app))
		case "unknown":
			return &VerifyResult{SignatureState: SigStateRejected, SchemaVersion: m.SchemaVersion},
				apperr.New(apperr.CodePolicyDenial,
					fmt.Sprintf("cannot compare app version %q to min_app_version %q (fail closed)",
						app, minApp))
		}
	}

	res := &VerifyResult{
		Manifest:      m,
		Channel:       m.Channel,
		Version:       m.Version,
		SchemaVersion: m.SchemaVersion,
	}

	keysPresent := opts.Keys.Len() > 0
	if keysPresent {
		keyID, err := verifySignatures(m, opts.Keys)
		if err != nil {
			res.SignatureState = SigStateRejected
			return res, err
		}
		res.SignatureState = SigStateVerified
		res.KeyID = keyID
		res.Message = "manifest signature verified"
		return res, nil
	}

	// No trusted keys configured.
	if m.HasSignatures() {
		// Cannot verify; do not accept as pilot unsigned either — signatures present
		// without keys is ambiguous / fail closed unless operator configures keys.
		res.SignatureState = SigStateRejected
		return res, apperr.New(apperr.CodePolicyDenial,
			"update manifest is signed but no trusted update keys are configured (fail closed)")
	}
	if !opts.AllowUnsigned {
		res.SignatureState = SigStateRejected
		return res, apperr.New(apperr.CodePolicyDenial,
			"unsigned update manifest rejected (configure JENKINS_MCP_UPDATE_TRUSTED_KEYS or set JENKINS_MCP_UPDATE_ALLOW_UNSIGNED=1 for pilot)")
	}
	res.SignatureState = SigStateUnverifiedPilot
	res.Message = "unsigned update manifest accepted (unverified_pilot)"
	return res, nil
}

// verifySignatures returns the first trusted key_id that verifies the payload.
func verifySignatures(m *Manifest, keys TrustedKeySet) (keyID string, err error) {
	if !m.HasSignatures() {
		return "", apperr.New(apperr.CodePolicyDenial,
			"unsigned update manifest rejected (signed manifest required when trusted keys are configured)")
	}
	payload, err := CanonicalSigningBytes(m)
	if err != nil {
		return "", apperr.Wrap(apperr.CodePolicyDenial, "update manifest canonicalization failed", err)
	}
	var lastErr error
	for _, sig := range m.Signatures {
		alg := strings.ToLower(strings.TrimSpace(sig.Alg))
		if alg == "" {
			alg = AlgEd25519
		}
		if alg != AlgEd25519 {
			lastErr = apperr.New(apperr.CodePolicyDenial,
				fmt.Sprintf("update manifest signature alg %q unsupported (want %s)", sig.Alg, AlgEd25519))
			continue
		}
		id := strings.TrimSpace(sig.KeyID)
		if id == "" {
			lastErr = apperr.New(apperr.CodePolicyDenial, "update manifest signature key_id is empty")
			continue
		}
		pub, ok := keys.Get(id)
		if !ok {
			lastErr = apperr.New(apperr.CodePolicyDenial,
				fmt.Sprintf("update manifest key_id %q is not trusted (fail closed)", id))
			continue
		}
		rawSig, err := decodeSignature(sig.Signature)
		if err != nil {
			lastErr = err
			continue
		}
		if !ed25519.Verify(pub, payload, rawSig) {
			lastErr = apperr.New(apperr.CodePolicyDenial,
				"update manifest signature verification failed (fail closed)")
			continue
		}
		return id, nil
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", apperr.New(apperr.CodePolicyDenial,
		"update manifest signature verification failed (fail closed)")
}

// SignManifest appends an Ed25519 signature for m using priv and keyID (dev/admin).
// Never ship private keys in the product tree.
func SignManifest(m *Manifest, priv ed25519.PrivateKey, keyID string) error {
	if m == nil {
		return apperr.New(apperr.CodeInvalidArgument, "update manifest is nil")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return apperr.New(apperr.CodeInvalidArgument, "ed25519 private key has wrong size")
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "update manifest key_id is required")
	}
	if m.SchemaVersion == 0 {
		m.SchemaVersion = SchemaV2
	}
	if m.SchemaVersion != SchemaV2 {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("signing requires schema_version %d (got %d)", SchemaV2, m.SchemaVersion))
	}
	if err := m.ValidateStructure(); err != nil {
		return err
	}
	// Clear legacy nested field so publishers don't smuggle unsigned fields.
	m.Latest = nil
	payload, err := CanonicalSigningBytes(m)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, payload)
	// Replace any existing signature for the same key_id.
	out := make([]ManifestSignature, 0, len(m.Signatures)+1)
	for _, s := range m.Signatures {
		if strings.TrimSpace(s.KeyID) == keyID {
			continue
		}
		out = append(out, s)
	}
	out = append(out, ManifestSignature{
		Alg:       AlgEd25519,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
	m.Signatures = out
	return nil
}

func decodeSignature(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return nil, apperr.New(apperr.CodePolicyDenial, "update manifest signature is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, apperr.New(apperr.CodePolicyDenial, "update manifest signature is not valid base64")
		}
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, apperr.New(apperr.CodePolicyDenial,
			fmt.Sprintf("update manifest signature has wrong length %d", len(raw)))
	}
	return raw, nil
}
