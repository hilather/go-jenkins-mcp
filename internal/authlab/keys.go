package authlab

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultKid is the lab key id embedded in JWTs and JWKS.
const DefaultKid = "oauth-lab-kid-1"

// DefaultAudience is the Jenkins API audience used by mode B/C lab tokens.
const DefaultAudience = "jenkins-api"

// DefaultTTL is the short-lived access-token lifetime for lab mints.
const DefaultTTL = 5 * time.Minute

// LabKey holds a disposable RSA signing key for the oauth lab.
// Material is lab-only; never use for production tenants.
type LabKey struct {
	Private *rsa.PrivateKey
	Kid     string
}

// GenerateLabKey creates a new 2048-bit RSA key for disposable labs.
func GenerateLabKey() (*LabKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("authlab: generate rsa: %w", err)
	}
	return &LabKey{Private: priv, Kid: DefaultKid}, nil
}

// LoadOrGenerateKey loads a PEM private key from dir/private.pem or generates
// one and writes private.pem + public.jwks.json for multi-service compose share.
func LoadOrGenerateKey(dir string) (*LabKey, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return GenerateLabKey()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("authlab: keys dir: %w", err)
	}
	privPath := filepath.Join(dir, "private.pem")
	jwksPath := filepath.Join(dir, "public.jwks.json")

	if b, err := os.ReadFile(privPath); err == nil {
		key, err := ParsePrivatePEM(b)
		if err != nil {
			return nil, err
		}
		// Ensure JWKS sidecar exists for other services / debugging.
		if _, err := os.Stat(jwksPath); err != nil {
			if werr := WriteJWKSFile(jwksPath, key); werr != nil {
				return nil, werr
			}
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("authlab: read private.pem: %w", err)
	}

	key, err := GenerateLabKey()
	if err != nil {
		return nil, err
	}
	if err := WritePrivatePEM(privPath, key); err != nil {
		return nil, err
	}
	if err := WriteJWKSFile(jwksPath, key); err != nil {
		return nil, err
	}
	return key, nil
}

// ParsePrivatePEM parses a PKCS#1 or PKCS#8 RSA private key PEM.
func ParsePrivatePEM(pemBytes []byte) (*LabKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("authlab: no PEM block in private key")
	}
	var priv *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("authlab: parse pkcs1: %w", err)
		}
		priv = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("authlab: parse pkcs8: %w", err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("authlab: pkcs8 key is not RSA")
		}
		priv = rk
	default:
		return nil, fmt.Errorf("authlab: unsupported PEM type %q", block.Type)
	}
	return &LabKey{Private: priv, Kid: DefaultKid}, nil
}

// WritePrivatePEM writes PKCS#1 RSA private key (lab-only; mode 0600).
func WritePrivatePEM(path string, key *LabKey) error {
	if key == nil || key.Private == nil {
		return errors.New("authlab: nil key")
	}
	der := x509.MarshalPKCS1PrivateKey(key.Private)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	// LAB ONLY — disposable key material for oauth-lab compose.
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

// WriteJWKSFile writes the public JWKS JSON for the lab key.
func WriteJWKSFile(path string, key *LabKey) error {
	doc, err := key.JWKS()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// JWKS returns a public-only JWKS document for this lab key.
func (k *LabKey) JWKS() (*JWKS, error) {
	if k == nil || k.Private == nil {
		return nil, errors.New("authlab: nil key")
	}
	kid := k.Kid
	if kid == "" {
		kid = DefaultKid
	}
	n := base64.RawURLEncoding.EncodeToString(k.Private.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.Private.E)).Bytes())
	return &JWKS{Keys: []JWK{{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   n,
		E:   e,
	}}}, nil
}

// JWKS is a minimal RFC 7517 key set (public RSA only).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is a public RSA JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// PublicKey returns the RSA public key for this JWK.
func (j JWK) PublicKey() (*rsa.PublicKey, error) {
	if !strings.EqualFold(j.Kty, "RSA") {
		return nil, fmt.Errorf("authlab: unsupported kty %q", j.Kty)
	}
	nb, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		nb, err = base64.URLEncoding.DecodeString(j.N)
		if err != nil {
			return nil, errors.New("authlab: invalid jwk n")
		}
	}
	eb, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		eb, err = base64.URLEncoding.DecodeString(j.E)
		if err != nil {
			return nil, errors.New("authlab: invalid jwk e")
		}
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: int(new(big.Int).SetBytes(eb).Int64()),
	}, nil
}

// KeyByID selects a verification key from the set.
func (s *JWKS) KeyByID(kid string) (*rsa.PublicKey, error) {
	if s == nil || len(s.Keys) == 0 {
		return nil, errors.New("authlab: empty jwks")
	}
	kid = strings.TrimSpace(kid)
	if kid == "" {
		if len(s.Keys) != 1 {
			return nil, errors.New("authlab: missing kid and multi-key jwks")
		}
		return s.Keys[0].PublicKey()
	}
	for _, k := range s.Keys {
		if k.Kid == kid {
			return k.PublicKey()
		}
	}
	return nil, errors.New("authlab: no jwks key matches kid")
}

// MintParams controls lab access-token claims.
type MintParams struct {
	Issuer   string
	Subject  string
	Audience string
	// TTL token lifetime; 0 → DefaultTTL. Negative values are used for expired tokens.
	TTL time.Duration
	// ExpOffset adds to time.Now for exp (e.g. -1h for expired). Overrides TTL when non-zero.
	ExpOffset time.Duration
	// NotBeforeOffset sets nbf relative to now (0 → now - 1m).
	NotBeforeOffset time.Duration
	// Extra claims merged into payload (non-secret lab claims only).
	Extra map[string]any
	// Now overrides clock for tests.
	Now func() time.Time
}

// MintAccessToken signs a compact RS256 JWT access token. Never logs the token.
func (k *LabKey) MintAccessToken(p MintParams) (string, error) {
	if k == nil || k.Private == nil {
		return "", errors.New("authlab: nil key")
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	t0 := now()

	iss := strings.TrimRight(strings.TrimSpace(p.Issuer), "/")
	if iss == "" {
		return "", errors.New("authlab: issuer required")
	}
	sub := strings.TrimSpace(p.Subject)
	if sub == "" {
		sub = "lab-user"
	}
	aud := strings.TrimSpace(p.Audience)
	if aud == "" {
		aud = DefaultAudience
	}

	ttl := p.TTL
	if ttl == 0 && p.ExpOffset == 0 {
		ttl = DefaultTTL
	}
	var exp time.Time
	if p.ExpOffset != 0 {
		exp = t0.Add(p.ExpOffset)
	} else {
		exp = t0.Add(ttl)
	}
	nbf := t0.Add(-time.Minute)
	if p.NotBeforeOffset != 0 {
		nbf = t0.Add(p.NotBeforeOffset)
	}

	claims := map[string]any{
		"iss":       iss,
		"sub":       sub,
		"aud":       aud,
		"exp":       exp.Unix(),
		"nbf":       nbf.Unix(),
		"iat":       t0.Unix(),
		"token_use": "access_token",
	}
	for k, v := range p.Extra {
		if strings.TrimSpace(k) == "" {
			continue
		}
		claims[k] = v
	}

	kid := k.Kid
	if kid == "" {
		kid = DefaultKid
	}
	return signRS256(k.Private, kid, claims)
}

func signRS256(priv *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	hdr, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	})
	if err != nil {
		return "", err
	}
	pl, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(hdr)
	p := base64.RawURLEncoding.EncodeToString(pl)
	input := h + "." + p
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("authlab: sign: %w", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// SharedKey is a process-wide lab key (optional) for multi-handler servers.
type SharedKey struct {
	mu  sync.RWMutex
	key *LabKey
}

// Set replaces the shared key.
func (s *SharedKey) Set(k *LabKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = k
}

// Get returns the current key.
func (s *SharedKey) Get() *LabKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key
}
