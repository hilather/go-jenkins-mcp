package adapter

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// EnvAdapterAllowlistTrustedKeys points at a file or directory of trusted
// Ed25519 public keys used to verify optional adapter allowlist signatures
// (INT-001 / Wave 44 provenance lite).
//
// Empty → no keys configured (pilot: unsigned allowlist OK; signed file fails closed).
const EnvAdapterAllowlistTrustedKeys = "JENKINS_MCP_ADAPTER_ALLOWLIST_TRUSTED_KEYS"

// AllowlistTrustedKeySet maps key_id → Ed25519 public key.
// Private keys never appear here. Errors and logs must not dump key material.
type AllowlistTrustedKeySet map[string]ed25519.PublicKey

// Has reports whether keyID is present.
func (s AllowlistTrustedKeySet) Has(keyID string) bool {
	if s == nil {
		return false
	}
	_, ok := s[strings.TrimSpace(keyID)]
	return ok
}

// Get returns the public key for keyID.
func (s AllowlistTrustedKeySet) Get(keyID string) (ed25519.PublicKey, bool) {
	if s == nil {
		return nil, false
	}
	pk, ok := s[strings.TrimSpace(keyID)]
	return pk, ok
}

// Len returns the number of trusted keys.
func (s AllowlistTrustedKeySet) Len() int {
	return len(s)
}

// KeyIDs returns sorted key ids (non-secret).
func (s AllowlistTrustedKeySet) KeyIDs() []string {
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

// allowlistTrustStoreFile is the JSON format for a trusted-keys file.
//
//	{"keys":[{"key_id":"adapter-ops-1","public_key":"<base64 32>"}]}
type allowlistTrustStoreFile struct {
	Keys []allowlistTrustStoreKey `json:"keys"`
}

type allowlistTrustStoreKey struct {
	KeyID     string `json:"key_id"`
	Alg       string `json:"alg,omitempty"` // optional; only "ed25519" accepted when set
	PublicKey string `json:"public_key"`    // base64 raw 32-byte Ed25519 public key
}

// LoadAllowlistTrustedKeys loads public keys from path (file or directory).
// Empty path returns (nil, nil) — no keys configured.
//
// File: JSON trust store, or a single base64/raw 32-byte key (key_id = basename).
// Directory: each non-hidden file is either a JSON store (merge keys) or
// key_id.pub / key_id.json / key_id with base64/raw public key bytes.
func LoadAllowlistTrustedKeys(path string) (AllowlistTrustedKeySet, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("adapter allowlist trusted keys path not found: %s", sanitizePathBase(path)))
		}
		return nil, apperr.Wrap(apperr.CodePolicyDenial,
			fmt.Sprintf("adapter allowlist trusted keys path unreadable: %s", sanitizePathBase(path)), err)
	}
	out := make(AllowlistTrustedKeySet)
	if st.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodePolicyDenial,
				fmt.Sprintf("adapter allowlist trusted keys dir unreadable: %s", sanitizePathBase(path)), err)
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
			raw, err := os.ReadFile(filepath.Join(path, name))
			if err != nil {
				return nil, apperr.Wrap(apperr.CodePolicyDenial,
					fmt.Sprintf("adapter allowlist trusted key file unreadable: %s", sanitizePathBase(name)), err)
			}
			if looksLikeJSONObject(raw) {
				set, err := parseAllowlistTrustStoreJSON(raw)
				if err != nil {
					return nil, err
				}
				for id, pk := range set {
					if _, exists := out[id]; exists {
						return nil, apperr.New(apperr.CodeInvalidArgument,
							fmt.Sprintf("duplicate adapter allowlist trusted key_id %q", id))
					}
					out[id] = pk
				}
				continue
			}
			keyID := allowlistKeyIDFromFilename(name)
			if keyID == "" {
				continue
			}
			pk, err := parseAllowlistPublicKeyBytes(raw)
			if err != nil {
				return nil, apperr.Wrap(apperr.CodeInvalidArgument,
					fmt.Sprintf("adapter allowlist trusted key %q invalid", keyID), err)
			}
			if _, exists := out[keyID]; exists {
				return nil, apperr.New(apperr.CodeInvalidArgument,
					fmt.Sprintf("duplicate adapter allowlist trusted key_id %q", keyID))
			}
			out[keyID] = pk
		}
		// Configured path must yield ≥1 key — empty/placeholder dirs must not
		// silently disable require-signed (fail open into pilot unsigned).
		if len(out) == 0 {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("adapter allowlist trusted keys path resolved zero keys (fail closed): %s", sanitizePathBase(path)))
		}
		return out, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodePolicyDenial,
			fmt.Sprintf("adapter allowlist trusted keys file unreadable: %s", sanitizePathBase(path)), err)
	}
	if looksLikeJSONObject(raw) {
		return parseAllowlistTrustStoreJSON(raw)
	}
	pk, err := parseAllowlistPublicKeyBytes(raw)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInvalidArgument,
			fmt.Sprintf("adapter allowlist trusted key file invalid: %s", sanitizePathBase(path)), err)
	}
	keyID := allowlistKeyIDFromFilename(filepath.Base(path))
	if keyID == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"adapter allowlist trusted key file basename yields empty key_id")
	}
	out[keyID] = pk
	return out, nil
}

// LoadAllowlistTrustedKeysFromEnviron resolves trusted keys from
// JENKINS_MCP_ADAPTER_ALLOWLIST_TRUSTED_KEYS. Empty/unset env → (nil, nil).
func LoadAllowlistTrustedKeysFromEnviron() (AllowlistTrustedKeySet, error) {
	p := strings.TrimSpace(os.Getenv(EnvAdapterAllowlistTrustedKeys))
	if p == "" {
		return nil, nil
	}
	return LoadAllowlistTrustedKeys(p)
}

func parseAllowlistTrustStoreJSON(raw []byte) (AllowlistTrustedKeySet, error) {
	var store allowlistTrustStoreFile
	if err := json.Unmarshal(raw, &store); err != nil {
		return nil, apperr.Wrap(apperr.CodeInvalidArgument,
			"adapter allowlist trusted keys JSON invalid", err)
	}
	if len(store.Keys) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"adapter allowlist trusted keys JSON has no keys")
	}
	out := make(AllowlistTrustedKeySet, len(store.Keys))
	for i, k := range store.Keys {
		id := strings.TrimSpace(k.KeyID)
		if id == "" {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("adapter allowlist trusted keys[%d].key_id is empty", i))
		}
		alg := strings.ToLower(strings.TrimSpace(k.Alg))
		if alg != "" && alg != "ed25519" {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("adapter allowlist trusted key %q has unsupported alg", id))
		}
		pk, err := parseAllowlistPublicKeyBytes([]byte(k.PublicKey))
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeInvalidArgument,
				fmt.Sprintf("adapter allowlist trusted key %q public_key invalid", id), err)
		}
		if _, exists := out[id]; exists {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("duplicate adapter allowlist trusted key_id %q", id))
		}
		out[id] = pk
	}
	return out, nil
}

// parseAllowlistPublicKeyBytes parses raw 32-byte or std/raw base64 Ed25519 public key.
// Never returns private keys. Errors must not include key bytes.
func parseAllowlistPublicKeyBytes(raw []byte) (ed25519.PublicKey, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "public key material is empty")
	}
	// Reject PEM / private markers without echoing material.
	upper := strings.ToUpper(s)
	if strings.Contains(upper, "PRIVATE") {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"private key material is not accepted in adapter allowlist trusted public key store")
	}
	if strings.Contains(s, "-----BEGIN") {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"PEM public keys are not accepted for adapter allowlist keys (use base64 raw 32-byte)")
	}
	// Raw 32-byte key (optionally with trailing \n / \r only — common for .pub files).
	rawTrim := bytes.TrimRight(raw, "\r\n")
	if len(rawTrim) == ed25519.PublicKeySize {
		pk := make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(pk, rawTrim)
		return pk, nil
	}
	// Base64 (std or raw), strip internal whitespace.
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
			return nil, apperr.New(apperr.CodeInvalidArgument,
				"public key is not raw 32-byte or base64")
		}
	}
	if len(dec) != ed25519.PublicKeySize {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("ed25519 public key has wrong length %d", len(dec)))
	}
	return ed25519.PublicKey(dec), nil
}

func allowlistKeyIDFromFilename(name string) string {
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
	s := strings.TrimSpace(string(raw))
	return strings.HasPrefix(s, "{")
}

// sanitizePathBase returns a base-only path fragment for model-visible errors.
func sanitizePathBase(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}
