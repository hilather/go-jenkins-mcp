package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// DefaultClockSkew is the allowed skew for exp / nbf validation (OAUTH-003).
const DefaultClockSkew = 60 * time.Second

// MaxAccessTokenBytes rejects absurdly large tokens (fail closed; also limits log risk).
const MaxAccessTokenBytes = 16 << 10 // 16 KiB

// TokenForm distinguishes JWT-shaped access tokens from opaque tokens.
type TokenForm string

const (
	// TokenFormJWT is a compact JWS with three base64url segments (header.payload.sig).
	TokenFormJWT TokenForm = "jwt"
	// TokenFormOpaque is a non-JWT access token (reference token). JWT claims are
	// not available; Jenkins whoAmI (AUTH-004) remains the identity binding path.
	TokenFormOpaque TokenForm = "opaque"
)

// known Graph / generic audiences that must never be accepted as Jenkins audience
// (even if a profile mis-sets jenkinsAudience to one of these strings).
// Common mistakes: Graph, Azure ARM, "common" multiscope tokens.
var defaultRejectedAudiences = []string{
	"https://graph.microsoft.com",
	"https://graph.microsoft.com/",
	"00000003-0000-0000-c000-000000000000", // Microsoft Graph app id
	"https://graph.microsoft.com/.default",
	"https://management.azure.com",
	"https://management.azure.com/",
	"https://management.core.windows.net/",
}

// AccessTokenParams configures JWT access-token validation for a profile.
// Bearer tokens must be for the exact Jenkins resource/audience (never Graph-only).
type AccessTokenParams struct {
	// Issuer is the expected OIDC issuer (exact match after trailing-slash trim).
	Issuer string
	// Audience is the exact Jenkins API resource/audience (profile jenkinsAudience).
	Audience string
	// ClientID when non-empty requires azp / appid / client_id to match (authorized party).
	ClientID string
	// TenantID when non-empty requires tid claim match (Entra tenant restriction).
	TenantID string
	// ClockSkew allows small clock drift for exp/nbf (0 → DefaultClockSkew).
	ClockSkew time.Duration
	// Now overrides time.Now for tests.
	Now func() time.Time
}

// AccessTokenClaims are non-secret claims extracted after successful JWT validation.
// Never log the raw token; these fields are safe for session labels / diagnostics.
//
// OAUTH-006: Entra group overage markers (_claim_names / _claim_sources) without a
// concrete groups array fail closed in ValidateAccessToken — Groups is never an
// invented empty-or-partial membership set for multi-user gateway bind.
type AccessTokenClaims struct {
	Subject           string
	PreferredUsername string
	Issuer            string
	Audience          []string
	ExpiresAt         time.Time
	NotBefore         time.Time
	AuthorizedParty   string
	TenantID          string
	TokenUse          string
	// Groups are optional IdP group claims (normalized later by OAUTH-006).
	// Populated only from concrete groups/roles string lists in the token.
	Groups []string
}

// AccessTokenResult is the outcome of Classify/Validate for an access token.
type AccessTokenResult struct {
	Form   TokenForm
	Claims AccessTokenClaims // populated only for TokenFormJWT
}

// ClassifyAccessToken returns TokenFormJWT when the string has three non-empty
// base64url-ish segments (header.payload.sig); otherwise TokenFormOpaque.
// It does not validate the JWT.
func ClassifyAccessToken(raw string) TokenForm {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return TokenFormOpaque
	}
	if looksLikeJWT(raw) {
		return TokenFormJWT
	}
	return TokenFormOpaque
}

// looksLikeJWT reports whether raw has the compact JWS three-segment shape.
func looksLikeJWT(raw string) bool {
	// Exactly two dots → three segments. Reject trailing/leading dots.
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		// Header typically starts with eyJ (base64url of {"…}).
		// Do not require eyJ on all segments (sig is random).
		for i := 0; i < len(p); i++ {
			c := p[i]
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
				c == '-' || c == '_' {
				continue
			}
			// Some tokens pad; accept '=' only in last segment positions.
			if c == '=' {
				continue
			}
			return false
		}
	}
	// Heuristic: JWT headers are JSON objects → base64 starts with "eyJ".
	return strings.HasPrefix(parts[0], "eyJ")
}

// ValidateAccessToken validates a bearer access token for Jenkins use.
//
//   - JWT-shaped tokens: signature via JWKS, iss/aud/exp/nbf/sub, reject alg=none,
//     reject ID tokens and wrong audiences (fail closed).
//   - Opaque tokens: skip JWT parse; return Form=opaque with empty claims.
//     Callers must bind identity via Jenkins whoAmI (AUTH-004). Residual: no
//     RFC 7662 introspection in MVP.
//
// Errors never include the raw token bytes (OAUTH-003 canary).
func ValidateAccessToken(raw string, jwks *JWKS, p AccessTokenParams) (AccessTokenResult, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return AccessTokenResult{}, apperr.New(apperr.CodeAuthentication, "access token is required")
	}
	if len(raw) > MaxAccessTokenBytes {
		return AccessTokenResult{}, apperr.New(apperr.CodeAuthentication, "access token exceeds size limit")
	}

	form := ClassifyAccessToken(raw)
	if form == TokenFormOpaque {
		// Residual: opaque reference tokens are accepted at the MCP layer only
		// after Jenkins whoAmI succeeds; no local claim validation possible.
		return AccessTokenResult{Form: TokenFormOpaque}, nil
	}

	if jwks == nil || len(jwks.Keys) == 0 {
		return AccessTokenResult{}, apperr.New(apperr.CodeAuthentication, "jwks is required to validate jwt access tokens")
	}
	p = normalizeAccessTokenParams(p)
	if p.Issuer == "" {
		return AccessTokenResult{}, apperr.New(apperr.CodeInvalidArgument, "issuer is required for jwt validation")
	}
	if p.Audience == "" {
		return AccessTokenResult{}, apperr.New(apperr.CodeInvalidArgument, "jenkins audience is required for jwt validation")
	}

	claims, err := validateJWTAccessToken(raw, jwks, p)
	if err != nil {
		return AccessTokenResult{}, scrubTokenFromError(err, raw)
	}
	return AccessTokenResult{Form: TokenFormJWT, Claims: claims}, nil
}

func normalizeAccessTokenParams(p AccessTokenParams) AccessTokenParams {
	p.Issuer = strings.TrimRight(strings.TrimSpace(p.Issuer), "/")
	p.Audience = strings.TrimSpace(p.Audience)
	p.ClientID = strings.TrimSpace(p.ClientID)
	p.TenantID = strings.TrimSpace(p.TenantID)
	if p.ClockSkew <= 0 {
		p.ClockSkew = DefaultClockSkew
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	return p
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// jwtPayload holds the claim subset we enforce. Additional claims are ignored.
type jwtPayload struct {
	Iss               string          `json:"iss"`
	Sub               string          `json:"sub"`
	Aud               json.RawMessage `json:"aud"`
	Exp               int64           `json:"exp"`
	Nbf               int64           `json:"nbf"`
	Iat               int64           `json:"iat"`
	PreferredUsername string          `json:"preferred_username"`
	Azp               string          `json:"azp"`
	AppID             string          `json:"appid"`
	ClientID          string          `json:"client_id"`
	Tid               string          `json:"tid"`
	TokenUse          string          `json:"token_use"` // Entra: access_token | id_token
	Typ               string          `json:"typ"`       // sometimes "JWT" / "at+jwt" / id_token
	Ver               string          `json:"ver"`       // rarely mis-set; reject when it names id_token
	Nonce             string          `json:"nonce"`     // typical of ID tokens
	// Resource is used by some IdPs as the resource indicator (treat like aud).
	Resource string   `json:"resource"`
	Groups   []string `json:"groups"`
	// Roles is an optional alternate group/role claim key (OAUTH-006 parity with
	// ExtractGroups DefaultGroupClaimNames). Merged into AccessTokenClaims.Groups.
	Roles []string `json:"roles"`
	// SCP presence helps distinguish access tokens; not required for MVP.
	Scp string `json:"scp"`
}

// isIDTokenHeaderTyp reports JOSE header typ values that mark an ID token.
// Empty, "JWT", and RFC 9068 "at+jwt" are accepted as non-ID-token.
func isIDTokenHeaderTyp(typ string) bool {
	t := strings.ToLower(strings.TrimSpace(typ))
	if t == "" || t == "jwt" || t == "at+jwt" || t == "application/at+jwt" {
		return false
	}
	if t == "id_token" || t == "id+jwt" || t == "application/id+jwt" ||
		t == "application/id-token+jwt" {
		return true
	}
	// Defensive: any typ that contains "id_token" as a token segment.
	return strings.Contains(t, "id_token")
}

// rejectIDTokenClaims fails closed when payload claims indicate an OIDC ID token
// rather than a Jenkins-audience API access token (OAUTH-003).
func rejectIDTokenClaims(pl jwtPayload) error {
	tokenUse := strings.ToLower(strings.TrimSpace(pl.TokenUse))
	if tokenUse == "id_token" {
		return apperr.New(apperr.CodeAuthentication,
			"id_token is not accepted for jenkins api authentication")
	}
	typ := strings.ToLower(strings.TrimSpace(pl.Typ))
	if typ == "id_token" || strings.Contains(typ, "id_token") {
		return apperr.New(apperr.CodeAuthentication,
			"token typ claim indicates id_token; not accepted for jenkins api authentication")
	}
	ver := strings.ToLower(strings.TrimSpace(pl.Ver))
	if ver == "id_token" || strings.Contains(ver, "id_token") {
		return apperr.New(apperr.CodeAuthentication,
			"token ver claim indicates id_token; not accepted for jenkins api authentication")
	}
	// Presence of nonce without token_use=access_token is a strong ID-token signal.
	if strings.TrimSpace(pl.Nonce) != "" && tokenUse != "access_token" {
		return apperr.New(apperr.CodeAuthentication,
			"token with nonce looks like an id_token; rejected for jenkins api")
	}
	return nil
}

func validateJWTAccessToken(raw string, jwks *JWKS, p AccessTokenParams) (AccessTokenClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt is malformed")
	}
	headerJSON, err := decodeB64URL(parts[0])
	if err != nil {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt header is invalid")
	}
	payloadJSON, err := decodeB64URL(parts[1])
	if err != nil {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt payload is invalid")
	}
	sig, err := decodeB64URL(parts[2])
	if err != nil {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt signature is invalid")
	}

	var hdr jwtHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt header JSON is invalid")
	}
	// Header typ: reject explicit ID-token misuse. "JWT" / "at+jwt" / empty are OK.
	if isIDTokenHeaderTyp(hdr.Typ) {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication,
			"jwt header typ indicates id_token; not accepted for jenkins api authentication")
	}
	alg := strings.TrimSpace(hdr.Alg)
	if alg == "" || strings.EqualFold(alg, "none") {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt algorithm none or empty is rejected")
	}
	// MVP allow-list: asymmetric algorithms only (no HS* shared-secret).
	switch strings.ToUpper(alg) {
	case "RS256", "ES256":
		// ok
	default:
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication,
			fmt.Sprintf("jwt algorithm %q is not accepted", alg))
	}

	pub, err := jwks.KeyByID(hdr.Kid)
	if err != nil {
		return AccessTokenClaims{}, err
	}

	signingInput := parts[0] + "." + parts[1]
	if err := verifyJWS(strings.ToUpper(alg), pub, []byte(signingInput), sig); err != nil {
		return AccessTokenClaims{}, err
	}

	// Map parse first so Entra group overage (_claim_names / groups-as-ref) is
	// visible before typed unmarshal (object-shaped groups would otherwise fail
	// as generic "payload JSON invalid"). Fail closed — never invent membership.
	var rawClaims map[string]any
	if err := json.Unmarshal(payloadJSON, &rawClaims); err != nil {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt payload JSON is invalid")
	}
	if err := CheckIncompleteGroupOverage(rawClaims); err != nil {
		return AccessTokenClaims{}, err
	}

	var pl jwtPayload
	if err := json.Unmarshal(payloadJSON, &pl); err != nil {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt payload JSON is invalid")
	}

	// Distinguish ID tokens from API access tokens (never send id_token to Jenkins).
	if err := rejectIDTokenClaims(pl); err != nil {
		return AccessTokenClaims{}, err
	}
	tokenUse := strings.ToLower(strings.TrimSpace(pl.TokenUse))

	iss := strings.TrimRight(strings.TrimSpace(pl.Iss), "/")
	if iss == "" || iss != p.Issuer {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt issuer does not match profile")
	}

	sub := strings.TrimSpace(pl.Sub)
	if sub == "" {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt subject (sub) is required")
	}

	auds := parseAudience(pl.Aud)
	if pl.Resource != "" {
		auds = appendUnique(auds, strings.TrimSpace(pl.Resource))
	}
	if !audienceIncludesExact(auds, p.Audience) {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication,
			"jwt audience does not include the configured jenkins audience")
	}
	// Reject known Graph-only tokens even if misconfigured jenkinsAudience equals Graph
	// when multiple audiences include Graph without the exact profile audience already checked.
	// Primary fail-closed path is exact audience match above. Additional guard: if the only
	// audiences are Graph defaults and profile audience is not one of them — already failed.
	// If profile wrongly sets Graph as audience, still reject by policy canary:
	if isDefaultRejectedAudience(p.Audience) {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication,
			"jenkins audience must not be a generic graph or default microsoft graph resource")
	}
	for _, a := range auds {
		if isDefaultRejectedAudience(a) && !strings.EqualFold(a, p.Audience) {
			// Graph co-listed is OK only if exact Jenkins audience is also present (already verified).
			// No extra reject; exact match already required.
			_ = a
		}
	}

	now := p.Now()
	if pl.Exp == 0 {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt exp is required")
	}
	exp := time.Unix(pl.Exp, 0)
	if now.After(exp.Add(p.ClockSkew)) {
		return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt is expired")
	}
	if pl.Nbf > 0 {
		nbf := time.Unix(pl.Nbf, 0)
		if now.Before(nbf.Add(-p.ClockSkew)) {
			return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt not valid yet (nbf)")
		}
	}

	// Optional tenant restriction.
	if p.TenantID != "" {
		tid := strings.TrimSpace(pl.Tid)
		if tid == "" || !strings.EqualFold(tid, p.TenantID) {
			return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt tenant does not match profile")
		}
	}

	// Optional authorized party / client binding.
	azp := firstNonEmpty(pl.Azp, pl.AppID, pl.ClientID)
	if p.ClientID != "" {
		if azp == "" || !strings.EqualFold(azp, p.ClientID) {
			return AccessTokenClaims{}, apperr.New(apperr.CodeAuthentication, "jwt authorized party does not match client id")
		}
	}

	var nbfTime time.Time
	if pl.Nbf > 0 {
		nbfTime = time.Unix(pl.Nbf, 0)
	}

	// Merge groups + roles claim arrays (OAUTH-006 / DefaultGroupClaimNames).
	// Full bound/dedupe/overage is applied by gateway BindSubject / ExtractGroups.
	groups := mergeStringClaims(pl.Groups, pl.Roles)

	return AccessTokenClaims{
		Subject:           sub,
		PreferredUsername: strings.TrimSpace(pl.PreferredUsername),
		Issuer:            iss,
		Audience:          auds,
		ExpiresAt:         exp,
		NotBefore:         nbfTime,
		AuthorizedParty:   azp,
		TenantID:          strings.TrimSpace(pl.Tid),
		TokenUse:          tokenUse,
		Groups:            groups,
	}, nil
}

// mergeStringClaims concatenates non-empty trimmed strings from claim slices
// (preserves order; does not hard-cap — callers apply MaxStoredGroups bounds).
func mergeStringClaims(parts ...[]string) []string {
	var out []string
	for _, list := range parts {
		for _, s := range list {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func verifyJWS(alg string, pub any, signingInput, sig []byte) error {
	sum := sha256.Sum256(signingInput)
	switch alg {
	case "RS256":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return apperr.New(apperr.CodeAuthentication, "jwks key type does not match rs256")
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, sum[:], sig); err != nil {
			return apperr.New(apperr.CodeAuthentication, "jwt signature verification failed")
		}
		return nil
	case "ES256":
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return apperr.New(apperr.CodeAuthentication, "jwks key type does not match es256")
		}
		// JWS ECDSA signature is R||S fixed-width (32+32 for P-256).
		if len(sig) != 64 {
			return apperr.New(apperr.CodeAuthentication, "jwt es256 signature length is invalid")
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(ecPub, sum[:], r, s) {
			return apperr.New(apperr.CodeAuthentication, "jwt signature verification failed")
		}
		return nil
	default:
		return apperr.New(apperr.CodeAuthentication, "jwt algorithm is not accepted")
	}
}

func parseAudience(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		single = strings.TrimSpace(single)
		if single == "" {
			return nil
		}
		return []string{single}
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err == nil {
		out := make([]string, 0, len(multi))
		for _, a := range multi {
			a = strings.TrimSpace(a)
			if a != "" {
				out = append(out, a)
			}
		}
		return out
	}
	return nil
}

func audienceIncludesExact(auds []string, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	for _, a := range auds {
		// Exact match (case-sensitive for URLs / resource IDs).
		if a == want {
			return true
		}
	}
	return false
}

func isDefaultRejectedAudience(a string) bool {
	a = strings.TrimSpace(a)
	for _, bad := range defaultRejectedAudiences {
		if strings.EqualFold(a, bad) {
			return true
		}
	}
	return false
}

func appendUnique(ss []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ss
	}
	for _, s := range ss {
		if s == v {
			return ss
		}
	}
	return append(ss, v)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// SessionLabelFromClaims maps JWT claims to a non-secret session user label.
// Prefers preferred_username, then sub. Empty when opaque / missing claims.
func SessionLabelFromClaims(c AccessTokenClaims) string {
	if u := strings.TrimSpace(c.PreferredUsername); u != "" {
		return u
	}
	return strings.TrimSpace(c.Subject)
}

// BindAccessTokenSession applies validated token material to an in-memory OIDC session.
// The raw token is stored only in Session.Secret (memory); never log it.
// JWT claim labels set Session.User; AUTH-004 whoAmI still required for Jenkins principal.
func BindAccessTokenSession(sess Session, rawToken string, result AccessTokenResult) Session {
	sess.Method = MethodOIDC
	sess.Secret = rawToken
	if result.Form == TokenFormJWT {
		if label := SessionLabelFromClaims(result.Claims); label != "" {
			sess.User = label
		}
		if !result.Claims.ExpiresAt.IsZero() {
			// Bound session lifetime to token exp when earlier than existing ExpiresAt.
			if sess.ExpiresAt.IsZero() || result.Claims.ExpiresAt.Before(sess.ExpiresAt) {
				sess.ExpiresAt = result.Claims.ExpiresAt
			}
		}
	}
	// Opaque: User may already be set by caller; whoAmI binds Principal later.
	return sess
}

// AccessTokenParamsFromOIDC builds validation params from a non-secret OIDC profile block.
func AccessTokenParamsFromOIDC(issuer, jenkinsAudience, clientID, tenantID string) AccessTokenParams {
	return AccessTokenParams{
		Issuer:   issuer,
		Audience: jenkinsAudience,
		ClientID: clientID,
		TenantID: tenantID,
	}
}

// scrubTokenFromError ensures apperr / wrapped errors never echo the raw token.
func scrubTokenFromError(err error, raw string) error {
	if err == nil {
		return nil
	}
	if raw == "" {
		return err
	}
	msg := err.Error()
	if strings.Contains(msg, raw) {
		return apperr.New(apperr.CodeOf(err), "access token validation failed")
	}
	// Also scrub long JWT-looking substrings if partially echoed.
	if looksLikeJWT(raw) {
		parts := strings.Split(raw, ".")
		for _, p := range parts {
			if len(p) > 12 && strings.Contains(msg, p) {
				return apperr.New(apperr.CodeOf(err), "access token validation failed")
			}
		}
	}
	return err
}

func decodeB64URL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
