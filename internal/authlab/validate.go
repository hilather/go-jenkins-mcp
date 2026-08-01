package authlab

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultClockSkew for exp/nbf validation in the lab RS.
const DefaultClockSkew = 60 * time.Second

// ValidateParams configures fail-closed JWT validation for mock-rs.
type ValidateParams struct {
	Issuer    string
	Audience  string
	ClockSkew time.Duration
	Now       func() time.Time
}

// ValidatedClaims are non-secret claims after successful validation.
// Never include the raw token.
type ValidatedClaims struct {
	Subject  string
	Issuer   string
	Audience string
	Expires  time.Time
}

// ValidateAccessToken verifies RS256 signature + iss/aud/exp/nbf fail-closed.
// Errors never embed the raw token (secret-free).
func ValidateAccessToken(raw string, jwks *JWKS, p ValidateParams) (ValidatedClaims, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ValidatedClaims{}, errors.New("authlab: missing token")
	}
	// Bound absurd tokens (also limits error/log risk).
	if len(raw) > 16<<10 {
		return ValidatedClaims{}, errors.New("authlab: token too large")
	}

	iss := strings.TrimRight(strings.TrimSpace(p.Issuer), "/")
	aud := strings.TrimSpace(p.Audience)
	if iss == "" {
		return ValidatedClaims{}, errors.New("authlab: issuer required")
	}
	if aud == "" {
		return ValidatedClaims{}, errors.New("authlab: audience required")
	}
	skew := p.ClockSkew
	if skew <= 0 {
		skew = DefaultClockSkew
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	t0 := now()

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ValidatedClaims{}, errors.New("authlab: malformed jwt")
	}
	headerJSON, err := b64Decode(parts[0])
	if err != nil {
		return ValidatedClaims{}, errors.New("authlab: invalid jwt header")
	}
	payloadJSON, err := b64Decode(parts[1])
	if err != nil {
		return ValidatedClaims{}, errors.New("authlab: invalid jwt payload")
	}
	sig, err := b64Decode(parts[2])
	if err != nil {
		return ValidatedClaims{}, errors.New("authlab: invalid jwt signature")
	}

	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return ValidatedClaims{}, errors.New("authlab: jwt header json")
	}
	alg := strings.ToUpper(strings.TrimSpace(hdr.Alg))
	if alg == "" || alg == "NONE" {
		return ValidatedClaims{}, errors.New("authlab: alg none rejected")
	}
	if alg != "RS256" {
		return ValidatedClaims{}, fmt.Errorf("authlab: algorithm %q not accepted", hdr.Alg)
	}

	pub, err := jwks.KeyByID(hdr.Kid)
	if err != nil {
		return ValidatedClaims{}, err
	}
	signingInput := parts[0] + "." + parts[1]
	sum := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return ValidatedClaims{}, errors.New("authlab: signature verification failed")
	}

	var pl struct {
		Iss string          `json:"iss"`
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
		Exp int64           `json:"exp"`
		Nbf int64           `json:"nbf"`
	}
	if err := json.Unmarshal(payloadJSON, &pl); err != nil {
		return ValidatedClaims{}, errors.New("authlab: jwt payload json")
	}
	gotIss := strings.TrimRight(strings.TrimSpace(pl.Iss), "/")
	if gotIss != iss {
		return ValidatedClaims{}, errors.New("authlab: issuer mismatch")
	}
	audiences, err := parseAud(pl.Aud)
	if err != nil {
		return ValidatedClaims{}, err
	}
	if !audienceMatch(audiences, aud) {
		return ValidatedClaims{}, errors.New("authlab: audience mismatch")
	}
	if pl.Exp == 0 {
		return ValidatedClaims{}, errors.New("authlab: exp required")
	}
	exp := time.Unix(pl.Exp, 0)
	if t0.After(exp.Add(skew)) {
		return ValidatedClaims{}, errors.New("authlab: token expired")
	}
	if pl.Nbf != 0 {
		nbf := time.Unix(pl.Nbf, 0)
		if t0.Before(nbf.Add(-skew)) {
			return ValidatedClaims{}, errors.New("authlab: token not yet valid")
		}
	}
	sub := strings.TrimSpace(pl.Sub)
	if sub == "" {
		return ValidatedClaims{}, errors.New("authlab: sub required")
	}
	return ValidatedClaims{
		Subject:  sub,
		Issuer:   gotIss,
		Audience: aud,
		Expires:  exp,
	}, nil
}

func parseAud(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, errors.New("authlab: aud required")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, errors.New("authlab: empty aud")
		}
		return []string{s}, nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, errors.New("authlab: aud shape invalid")
	}
	out := make([]string, 0, len(arr))
	for _, a := range arr {
		a = strings.TrimSpace(a)
		if a != "" {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("authlab: empty aud list")
	}
	return out, nil
}

func audienceMatch(got []string, want string) bool {
	for _, g := range got {
		if g == want {
			return true
		}
	}
	return false
}

func b64Decode(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// ExtractBearer returns the token from an Authorization header value.
// Only "Bearer <token>" is accepted. Empty / Basic / other schemes return "".
func ExtractBearer(authorization string) string {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return ""
	}
	const prefix = "Bearer "
	// Case-insensitive scheme, require space separator.
	if len(authorization) < len(prefix) {
		return ""
	}
	scheme := authorization[:len(prefix)-1] // "Bearer"
	if !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	if authorization[len(prefix)-1] != ' ' {
		return ""
	}
	return strings.TrimSpace(authorization[len(prefix):])
}

// HasBearerScheme reports whether Authorization presents a Bearer scheme
// (even if the token is empty/invalid). Used to refuse Basic fallthrough.
func HasBearerScheme(authorization string) bool {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return false
	}
	parts := strings.SplitN(authorization, " ", 2)
	return strings.EqualFold(parts[0], "Bearer")
}
