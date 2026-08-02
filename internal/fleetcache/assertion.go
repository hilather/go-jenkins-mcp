package fleetcache

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Assertion operations (low-cardinality; widen requires new MAC).
const (
	OpHead   = "head"
	OpRead   = "read"
	OpFrame  = "frame"
	OpImport = "import"
	OpRepair = "repair"
	// OpFill is fill-lease join/complete (FLC-040); peer wire residual until HTTP routes land.
	OpFill = "fill"
)

// DefaultAssertionTTL is the pilot default lifetime for scoped peer assertions.
const DefaultAssertionTTL = 30 * time.Second

// MinAssertionTTL / MaxAssertionTTL bound operator-chosen TTLs.
const (
	MinAssertionTTL = 5 * time.Second
	MaxAssertionTTL = 5 * time.Minute
)

// AssertionClaims is the secret-free scope of a peer cache request.
// Never includes Jenkins/OAuth credentials or raw subject strings.
type AssertionClaims struct {
	FleetID            string
	RequestingMemberID string
	LocatorHash        string // 64 hex
	ManifestDigest     string // optional 64 hex
	Operation          string
	// MaxDecodedBytes caps result size for OpRead (0 = op-default, still non-negative).
	MaxDecodedBytes int64
	// SubjectKeyHash is opaque (e.g. audit.HashOpaque); never raw subject.
	SubjectKeyHash string
	// PolicyEpoch binds the assertion to a policy generation (0 allowed for pilot).
	PolicyEpoch int64
	IssuedAt    time.Time
	ExpiresAt   time.Time
	Nonce       string // unique per issue; base64url
}

// Assertion is claims plus HMAC-SHA256 over the canonical claim bytes.
type Assertion struct {
	Claims AssertionClaims
	// MAC is lowercase hex HMAC-SHA256.
	MAC string
}

// Expected is what the verifier requires beyond signature validity.
type Expected struct {
	FleetID     string
	LocatorHash string // if non-empty, must match
	Operation   string // if non-empty, must match
	// MaxDecodedBytes if >0, claim must not exceed (cannot widen).
	MaxDecodedBytes int64
	// PolicyEpoch if >0, claim must match exactly.
	PolicyEpoch int64
}

// NonceStore records nonces for replay protection within a TTL window.
type NonceStore interface {
	// CheckAndRemember returns true if nonce was already seen (replay).
	// On first sight, records until expireAt.
	CheckAndRemember(nonce string, expireAt time.Time) (replay bool)
}

// MemoryNonceStore is a process-local nonce set with expiry cleanup.
type MemoryNonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewMemoryNonceStore creates an empty nonce store.
func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{seen: make(map[string]time.Time)}
}

// CheckAndRemember implements NonceStore.
func (s *MemoryNonceStore) CheckAndRemember(nonce string, expireAt time.Time) bool {
	if s == nil {
		return true // fail closed: no store ⇒ treat as replay/unavailable
	}
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return true
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	// Opportunistic purge.
	for n, exp := range s.seen {
		if !exp.After(now) {
			delete(s.seen, n)
		}
	}
	if exp, ok := s.seen[nonce]; ok && exp.After(now) {
		return true
	}
	s.seen[nonce] = expireAt.UTC()
	return false
}

// IssueAssertion builds a signed assertion. key is HMAC material (never log).
// If ExpiresAt is zero, IssuedAt+DefaultAssertionTTL is used. Nonce is filled if empty.
func IssueAssertion(key []byte, claims AssertionClaims) (Assertion, error) {
	if len(key) < 16 {
		return Assertion{}, apperr.New(apperr.CodeInvalidArgument, "assertion key too short")
	}
	if err := validateClaimsForIssue(&claims); err != nil {
		return Assertion{}, err
	}
	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = time.Now().UTC()
	} else {
		claims.IssuedAt = claims.IssuedAt.UTC()
	}
	if claims.ExpiresAt.IsZero() {
		claims.ExpiresAt = claims.IssuedAt.Add(DefaultAssertionTTL)
	} else {
		claims.ExpiresAt = claims.ExpiresAt.UTC()
	}
	ttl := claims.ExpiresAt.Sub(claims.IssuedAt)
	if ttl < MinAssertionTTL || ttl > MaxAssertionTTL {
		return Assertion{}, apperr.New(apperr.CodeInvalidArgument, "assertion ttl out of range")
	}
	if claims.Nonce == "" {
		n, err := randomNonce()
		if err != nil {
			return Assertion{}, err
		}
		claims.Nonce = n
	}
	mac, err := macClaims(key, claims)
	if err != nil {
		return Assertion{}, err
	}
	return Assertion{Claims: claims, MAC: mac}, nil
}

// VerifyAssertion checks MAC, time, expected scope, and optional replay store.
// now should be UTC wall clock; clock skew is not widened (fail closed).
func VerifyAssertion(key []byte, a Assertion, now time.Time, exp Expected, nonces NonceStore) error {
	if len(key) < 16 {
		return apperr.New(apperr.CodeInvalidArgument, "assertion key too short")
	}
	if err := validateClaimsForIssue(&a.Claims); err != nil {
		return err
	}
	want, err := macClaims(key, a.Claims)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(strings.ToLower(a.MAC)), []byte(want)) {
		return apperr.New(apperr.CodeAuthorization, "assertion mac invalid")
	}
	now = now.UTC()
	if now.Before(a.Claims.IssuedAt.Add(-time.Second)) {
		// 1s skew grace only for issuer clock slightly ahead; larger skew fails.
		return apperr.New(apperr.CodeAuthorization, "assertion not yet valid")
	}
	if !now.Before(a.Claims.ExpiresAt) {
		return apperr.New(apperr.CodeAuthorization, "assertion expired")
	}
	if exp.FleetID != "" && a.Claims.FleetID != exp.FleetID {
		return apperr.New(apperr.CodeAuthorization, "assertion fleet mismatch")
	}
	if exp.LocatorHash != "" && !strings.EqualFold(a.Claims.LocatorHash, exp.LocatorHash) {
		return apperr.New(apperr.CodeAuthorization, "assertion locator mismatch")
	}
	if exp.Operation != "" && a.Claims.Operation != exp.Operation {
		return apperr.New(apperr.CodeAuthorization, "assertion operation mismatch")
	}
	if exp.MaxDecodedBytes > 0 && a.Claims.MaxDecodedBytes > exp.MaxDecodedBytes {
		return apperr.New(apperr.CodeAuthorization, "assertion decoded budget widened")
	}
	if exp.PolicyEpoch > 0 && a.Claims.PolicyEpoch != exp.PolicyEpoch {
		return apperr.New(apperr.CodeAuthorization, "assertion policy epoch mismatch")
	}
	if nonces != nil {
		if nonces.CheckAndRemember(a.Claims.Nonce, a.Claims.ExpiresAt) {
			return apperr.New(apperr.CodeAuthorization, "assertion replay")
		}
	}
	return nil
}

// DeriveAssertionKey derives HMAC key material from a shared pilot secret without
// storing the secret in the assertion. Output is 32 bytes; never log either input.
func DeriveAssertionKey(meshOrFleetSecret []byte, purpose string) []byte {
	if purpose == "" {
		purpose = "fleet-cache-assert-v1"
	}
	mac := hmac.New(sha256.New, meshOrFleetSecret)
	_, _ = mac.Write([]byte(purpose))
	return mac.Sum(nil)
}

func validateClaimsForIssue(c *AssertionClaims) error {
	if c == nil {
		return apperr.New(apperr.CodeInvalidArgument, "assertion claims nil")
	}
	c.FleetID = strings.TrimSpace(c.FleetID)
	c.RequestingMemberID = strings.TrimSpace(c.RequestingMemberID)
	c.LocatorHash = strings.ToLower(strings.TrimSpace(c.LocatorHash))
	c.ManifestDigest = strings.ToLower(strings.TrimSpace(c.ManifestDigest))
	c.Operation = strings.TrimSpace(c.Operation)
	c.SubjectKeyHash = strings.TrimSpace(c.SubjectKeyHash)
	c.Nonce = strings.TrimSpace(c.Nonce)
	if c.FleetID == "" || c.RequestingMemberID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "assertion fleet/member required")
	}
	if len(c.LocatorHash) != 64 || !isHex(c.LocatorHash) {
		return apperr.New(apperr.CodeInvalidArgument, "assertion locator_hash invalid")
	}
	if c.ManifestDigest != "" && (len(c.ManifestDigest) != 64 || !isHex(c.ManifestDigest)) {
		return apperr.New(apperr.CodeInvalidArgument, "assertion manifest_digest invalid")
	}
	switch c.Operation {
	case OpHead, OpRead, OpFrame, OpImport, OpRepair, OpFill:
	default:
		return apperr.New(apperr.CodeInvalidArgument, "assertion operation invalid")
	}
	if c.MaxDecodedBytes < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "assertion max_decoded_bytes negative")
	}
	// Reject accidental secret-shaped subject fields (heuristic fail closed).
	low := strings.ToLower(c.SubjectKeyHash)
	if strings.Contains(low, "bearer ") || strings.Contains(low, "password") ||
		strings.HasPrefix(low, "ghp_") || strings.Contains(c.SubjectKeyHash, "@") {
		return apperr.New(apperr.CodeInvalidArgument, "assertion subject_key_hash looks secret-shaped")
	}
	return nil
}

func macClaims(key []byte, c AssertionClaims) (string, error) {
	raw, err := claimsCanonical(c)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func claimsCanonical(c AssertionClaims) ([]byte, error) {
	// Fixed field order; times as RFC3339Nano UTC.
	var b strings.Builder
	fmt.Fprintf(&b, "fleet_id=%s\n", c.FleetID)
	fmt.Fprintf(&b, "requesting_member_id=%s\n", c.RequestingMemberID)
	fmt.Fprintf(&b, "locator_hash=%s\n", c.LocatorHash)
	fmt.Fprintf(&b, "manifest_digest=%s\n", c.ManifestDigest)
	fmt.Fprintf(&b, "operation=%s\n", c.Operation)
	fmt.Fprintf(&b, "max_decoded_bytes=%d\n", c.MaxDecodedBytes)
	fmt.Fprintf(&b, "subject_key_hash=%s\n", c.SubjectKeyHash)
	fmt.Fprintf(&b, "policy_epoch=%d\n", c.PolicyEpoch)
	fmt.Fprintf(&b, "issued_at=%s\n", c.IssuedAt.UTC().Format(time.RFC3339Nano))
	fmt.Fprintf(&b, "expires_at=%s\n", c.ExpiresAt.UTC().Format(time.RFC3339Nano))
	fmt.Fprintf(&b, "nonce=%s\n", c.Nonce)
	return []byte(b.String()), nil
}

func randomNonce() (string, error) {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", apperr.Wrap(apperr.CodeInternal, "assertion nonce entropy", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
