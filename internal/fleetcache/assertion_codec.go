package fleetcache

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Assertion wire envelope (FLC-031): secret-free claims + MAC; never credentials.
// Encoded as base64url(JSON) for HTTP header transport.
type assertionWire struct {
	FleetID            string `json:"fleet_id"`
	RequestingMemberID string `json:"requesting_member_id"`
	LocatorHash        string `json:"locator_hash"`
	ManifestDigest     string `json:"manifest_digest,omitempty"`
	Operation          string `json:"operation"`
	MaxDecodedBytes    int64  `json:"max_decoded_bytes"`
	SubjectKeyHash     string `json:"subject_key_hash,omitempty"`
	PolicyEpoch        int64  `json:"policy_epoch"`
	IssuedAt           string `json:"issued_at"`
	ExpiresAt          string `json:"expires_at"`
	Nonce              string `json:"nonce"`
	MAC                string `json:"mac"`
}

// EncodeAssertionHeader returns base64url JSON for X-Fleet-Cache-Assertion.
func EncodeAssertionHeader(a Assertion) (string, error) {
	if strings.TrimSpace(a.MAC) == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "assertion mac empty")
	}
	if err := validateClaimsForIssue(&a.Claims); err != nil {
		return "", err
	}
	w := assertionWire{
		FleetID:            a.Claims.FleetID,
		RequestingMemberID: a.Claims.RequestingMemberID,
		LocatorHash:        a.Claims.LocatorHash,
		ManifestDigest:     a.Claims.ManifestDigest,
		Operation:          a.Claims.Operation,
		MaxDecodedBytes:    a.Claims.MaxDecodedBytes,
		SubjectKeyHash:     a.Claims.SubjectKeyHash,
		PolicyEpoch:        a.Claims.PolicyEpoch,
		IssuedAt:           a.Claims.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:          a.Claims.ExpiresAt.UTC().Format(time.RFC3339Nano),
		Nonce:              a.Claims.Nonce,
		MAC:                strings.ToLower(a.MAC),
	}
	raw, err := json.Marshal(w)
	if err != nil {
		return "", apperr.Wrap(apperr.CodeInternal, "assertion encode", err)
	}
	// Bound header size (claims are small; reject pathological).
	if len(raw) > 8<<10 {
		return "", apperr.New(apperr.CodeInvalidArgument, "assertion envelope too large")
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeAssertionHeader parses base64url JSON into an Assertion (does not verify MAC).
func DecodeAssertionHeader(encoded string) (Assertion, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return Assertion{}, apperr.New(apperr.CodeInvalidArgument, "assertion header empty")
	}
	if len(encoded) > 12<<10 {
		return Assertion{}, apperr.New(apperr.CodeInvalidArgument, "assertion header too large")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		// Also accept standard base64.
		raw, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			return Assertion{}, apperr.New(apperr.CodeInvalidArgument, "assertion header encoding invalid")
		}
	}
	if len(raw) > 8<<10 {
		return Assertion{}, apperr.New(apperr.CodeInvalidArgument, "assertion envelope too large")
	}
	var w assertionWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return Assertion{}, apperr.New(apperr.CodeInvalidArgument, "assertion envelope invalid JSON")
	}
	issued, err := time.Parse(time.RFC3339Nano, w.IssuedAt)
	if err != nil {
		return Assertion{}, apperr.New(apperr.CodeInvalidArgument, "assertion issued_at invalid")
	}
	exp, err := time.Parse(time.RFC3339Nano, w.ExpiresAt)
	if err != nil {
		return Assertion{}, apperr.New(apperr.CodeInvalidArgument, "assertion expires_at invalid")
	}
	a := Assertion{
		Claims: AssertionClaims{
			FleetID:            w.FleetID,
			RequestingMemberID: w.RequestingMemberID,
			LocatorHash:        w.LocatorHash,
			ManifestDigest:     w.ManifestDigest,
			Operation:          w.Operation,
			MaxDecodedBytes:    w.MaxDecodedBytes,
			SubjectKeyHash:     w.SubjectKeyHash,
			PolicyEpoch:        w.PolicyEpoch,
			IssuedAt:           issued.UTC(),
			ExpiresAt:          exp.UTC(),
			Nonce:              w.Nonce,
		},
		MAC: strings.ToLower(strings.TrimSpace(w.MAC)),
	}
	if err := validateClaimsForIssue(&a.Claims); err != nil {
		return Assertion{}, err
	}
	if a.MAC == "" {
		return Assertion{}, apperr.New(apperr.CodeInvalidArgument, "assertion mac empty")
	}
	return a, nil
}
