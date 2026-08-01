package update

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
)

// EnvUpdateTrustedKeysVar points at a file or directory of trusted update public keys.
// Empty → $XDG_CONFIG_HOME/jenkins-mcp/update/trusted_keys/ when that dir exists.
const EnvUpdateTrustedKeysVar = "JENKINS_MCP_UPDATE_TRUSTED_KEYS"

// EnvUpdateAllowUnsigned allows unsigned manifests when no trusted keys are configured.
// Must be exactly "1". Never elevates when keys are present (signed still required).
const EnvUpdateAllowUnsigned = "JENKINS_MCP_UPDATE_ALLOW_UNSIGNED"

// TrustedKeySet maps key_id → Ed25519 public key. Private keys never appear here.
type TrustedKeySet map[string]ed25519.PublicKey

// Has reports whether keyID is present.
func (s TrustedKeySet) Has(keyID string) bool {
	if s == nil {
		return false
	}
	_, ok := s[strings.TrimSpace(keyID)]
	return ok
}

// Get returns the public key for keyID.
func (s TrustedKeySet) Get(keyID string) (ed25519.PublicKey, bool) {
	if s == nil {
		return nil, false
	}
	pk, ok := s[strings.TrimSpace(keyID)]
	return pk, ok
}

// Len returns the number of trusted keys.
func (s TrustedKeySet) Len() int { return len(s) }

// KeyIDs returns sorted key ids (non-secret).
func (s TrustedKeySet) KeyIDs() []string {
	if len(s) == 0 {
		return nil
	}
	ids := make([]string, 0, len(s))
	for id := range s {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

type trustStoreFile struct {
	Keys []trustStoreKey `json:"keys"`
}

type trustStoreKey struct {
	KeyID     string `json:"key_id"`
	Alg       string `json:"alg,omitempty"`
	PublicKey string `json:"public_key"` // base64 raw 32-byte Ed25519 public key
}

// LoadTrustedKeys loads public keys from path (file or directory).
// Empty path returns (nil, nil) — no keys configured.
//
// Directory layout matches policy trusted keys: <key_id>.pub / .pem, or JSON trust store.
func LoadTrustedKeys(path string) (TrustedKeySet, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("update trusted keys path not found: %s", sanitizePath(path)))
		}
		return nil, apperr.Wrap(apperr.CodePolicyDenial,
			fmt.Sprintf("update trusted keys path unreadable: %s", sanitizePath(path)), err)
	}
	out := make(TrustedKeySet)
	if st.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodePolicyDenial,
				fmt.Sprintf("update trusted keys dir unreadable: %s", sanitizePath(path)), err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			lower := strings.ToLower(name)
			if strings.HasSuffix(lower, ".md") || strings.HasSuffix(lower, ".txt") {
				continue
			}
			keyID := keyIDFromFilename(name)
			if keyID == "" {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(path, name))
			if err != nil {
				return nil, apperr.Wrap(apperr.CodePolicyDenial,
					fmt.Sprintf("update trusted key file unreadable: %s", sanitizePath(name)), err)
			}
			if looksLikeJSONObject(raw) {
				set, err := parseTrustStoreJSON(raw)
				if err != nil {
					return nil, err
				}
				for id, pk := range set {
					if _, exists := out[id]; exists {
						return nil, apperr.New(apperr.CodeInvalidArgument,
							fmt.Sprintf("duplicate update trusted key_id %q", id))
					}
					out[id] = pk
				}
				continue
			}
			pk, err := ParsePublicKeyBytes(raw)
			if err != nil {
				return nil, apperr.Wrap(apperr.CodeInvalidArgument,
					fmt.Sprintf("update trusted key %q invalid", keyID), err)
			}
			if _, exists := out[keyID]; exists {
				return nil, apperr.New(apperr.CodeInvalidArgument,
					fmt.Sprintf("duplicate update trusted key_id %q", keyID))
			}
			out[keyID] = pk
		}
		return out, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodePolicyDenial,
			fmt.Sprintf("update trusted keys file unreadable: %s", sanitizePath(path)), err)
	}
	if looksLikeJSONObject(raw) {
		return parseTrustStoreJSON(raw)
	}
	pk, err := ParsePublicKeyBytes(raw)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInvalidArgument,
			fmt.Sprintf("update trusted key file invalid: %s", sanitizePath(path)), err)
	}
	keyID := keyIDFromFilename(filepath.Base(path))
	if keyID == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "update trusted key file basename yields empty key_id")
	}
	out[keyID] = pk
	return out, nil
}

// LoadTrustedKeysFromEnviron resolves trusted update keys from env or default XDG dir.
// Missing default directory is not an error (returns empty set).
func LoadTrustedKeysFromEnviron(paths *config.Paths) (TrustedKeySet, error) {
	if p := strings.TrimSpace(os.Getenv(EnvUpdateTrustedKeysVar)); p != "" {
		return LoadTrustedKeys(p)
	}
	var resolved config.Paths
	if paths != nil {
		resolved = *paths
	} else {
		r, err := config.Resolve()
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeInternal, "resolve config paths for update trusted keys", err)
		}
		resolved = r
	}
	dir := resolved.UpdateTrustedKeysDir()
	st, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, apperr.Wrap(apperr.CodePolicyDenial,
			fmt.Sprintf("update trusted keys dir unreadable: %s", sanitizePath(dir)), err)
	}
	if !st.IsDir() {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("update trusted keys path is not a directory: %s", sanitizePath(dir)))
	}
	return LoadTrustedKeys(dir)
}

// AllowUnsignedFromEnviron reports whether JENKINS_MCP_UPDATE_ALLOW_UNSIGNED=1.
func AllowUnsignedFromEnviron() bool {
	return strings.TrimSpace(os.Getenv(EnvUpdateAllowUnsigned)) == "1"
}

// ParsePublicKeyBytes parses PEM or base64/raw Ed25519 public key material.
// Errors never include key bytes.
func ParsePublicKeyBytes(raw []byte) (ed25519.PublicKey, error) {
	raw = bytesTrimSpace(raw)
	if len(raw) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "public key material is empty")
	}
	if bytesContains(raw, []byte("-----BEGIN")) {
		return parsePublicKeyPEM(raw)
	}
	if len(raw) == ed25519.PublicKeySize {
		pk := make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(pk, raw)
		return pk, nil
	}
	s := strings.TrimSpace(string(raw))
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		dec, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return nil, apperr.New(apperr.CodeInvalidArgument, "public key is not PEM, raw, or base64")
		}
	}
	if len(dec) != ed25519.PublicKeySize {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("ed25519 public key has wrong length %d", len(dec)))
	}
	return ed25519.PublicKey(dec), nil
}

func parsePublicKeyPEM(raw []byte) (ed25519.PublicKey, error) {
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, apperr.New(apperr.CodeInvalidArgument, "no PEM public key block found")
		}
		switch block.Type {
		case "PUBLIC KEY":
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, apperr.New(apperr.CodeInvalidArgument, "invalid PKIX public key PEM")
			}
			pk, ok := pub.(ed25519.PublicKey)
			if !ok {
				return nil, apperr.New(apperr.CodeInvalidArgument, "PEM public key is not ed25519")
			}
			return pk, nil
		case "ED25519 PUBLIC KEY":
			if len(block.Bytes) == ed25519.PublicKeySize {
				return ed25519.PublicKey(block.Bytes), nil
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, apperr.New(apperr.CodeInvalidArgument, "invalid ED25519 PUBLIC KEY PEM")
			}
			pk, ok := pub.(ed25519.PublicKey)
			if !ok {
				return nil, apperr.New(apperr.CodeInvalidArgument, "PEM public key is not ed25519")
			}
			return pk, nil
		default:
			if strings.Contains(strings.ToUpper(block.Type), "PRIVATE") {
				return nil, apperr.New(apperr.CodeInvalidArgument,
					"private key material is not accepted in trusted public key store")
			}
			continue
		}
	}
}

// EncodePublicKeyPEM returns PKIX PEM for an Ed25519 public key (safe to distribute).
func EncodePublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, apperr.New(apperr.CodeInvalidArgument, "ed25519 public key has wrong size")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "marshal ed25519 public key", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// EncodePrivateKeyPEM returns PKCS8 PEM for an Ed25519 private key (dev only).
func EncodePrivateKeyPEM(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, apperr.New(apperr.CodeInvalidArgument, "ed25519 private key has wrong size")
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "marshal ed25519 private key", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKeyBytes parses PEM PKCS8 Ed25519 private key (dev sign only).
func ParsePrivateKeyBytes(raw []byte) (ed25519.PrivateKey, error) {
	raw = bytesTrimSpace(raw)
	if len(raw) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "private key material is empty")
	}
	if !bytesContains(raw, []byte("-----BEGIN")) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "private key must be PEM-encoded")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "no PEM private key block found")
	}
	if strings.Contains(strings.ToUpper(block.Type), "PUBLIC") {
		return nil, apperr.New(apperr.CodeInvalidArgument, "expected private key PEM, got public")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		pk, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, apperr.New(apperr.CodeInvalidArgument, "PKCS8 key is not ed25519")
		}
		return pk, nil
	}
	if len(block.Bytes) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(block.Bytes), nil
	}
	if len(block.Bytes) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(block.Bytes), nil
	}
	return nil, apperr.New(apperr.CodeInvalidArgument, "unsupported private key PEM encoding")
}

func parseTrustStoreJSON(raw []byte) (TrustedKeySet, error) {
	var store trustStoreFile
	if err := json.Unmarshal(raw, &store); err != nil {
		return nil, apperr.Wrap(apperr.CodeInvalidArgument, "update trusted keys JSON invalid", err)
	}
	if len(store.Keys) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "update trusted keys JSON has no keys")
	}
	out := make(TrustedKeySet, len(store.Keys))
	for i, k := range store.Keys {
		id := strings.TrimSpace(k.KeyID)
		if id == "" {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("update trusted keys[%d].key_id is empty", i))
		}
		alg := strings.ToLower(strings.TrimSpace(k.Alg))
		if alg != "" && alg != AlgEd25519 {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("update trusted key %q has unsupported alg", id))
		}
		pk, err := ParsePublicKeyBytes([]byte(k.PublicKey))
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeInvalidArgument,
				fmt.Sprintf("update trusted key %q public_key invalid", id), err)
		}
		if _, exists := out[id]; exists {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("duplicate update trusted key_id %q", id))
		}
		out[id] = pk
	}
	return out, nil
}

func keyIDFromFilename(name string) string {
	base := filepath.Base(name)
	for _, ext := range []string{".pub", ".pem", ".json", ".key"} {
		if strings.HasSuffix(strings.ToLower(base), ext) {
			base = base[:len(base)-len(ext)]
			break
		}
	}
	return strings.TrimSpace(base)
}

func looksLikeJSONObject(raw []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(raw)), "{")
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func bytesContains(b, sub []byte) bool {
	return strings.Contains(string(b), string(sub))
}

// sanitizePath returns a basename-ish path for errors (avoid leaking home trees with secrets).
func sanitizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}
