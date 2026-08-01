package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// MaxJWKSBodyBytes bounds JWKS JSON responses (fail closed).
const MaxJWKSBodyBytes = 1 << 20 // 1 MiB

// DefaultJWKSTimeout is used when the injected client has no Timeout and the
// call context has no deadline.
const DefaultJWKSTimeout = 15 * time.Second

// JWKS is a JSON Web Key Set (RFC 7517) subset used for access-token verification.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is a single JSON Web Key. Only public RSA/EC verification material is retained.
// Private key material is never expected or stored.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// FetchJWKS retrieves a JWKS document from jwksURI via the injected HTTP client
// (use httptest in unit tests). Does not cache; durable JWKS caching is residual.
func FetchJWKS(ctx context.Context, client *http.Client, jwksURI string) (*JWKS, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "jwks fetch cancelled", err)
	}
	if client == nil {
		return nil, apperr.New(apperr.CodeInternal, "jwks HTTP client is required")
	}
	jwksURI = strings.TrimSpace(jwksURI)
	if jwksURI == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "jwks_uri is required")
	}
	u, err := url.Parse(jwksURI)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "jwks_uri is not a valid http(s) URL")
	}
	if u.User != nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "jwks_uri must not embed credentials")
	}

	if client.Timeout == 0 {
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, DefaultJWKSTimeout)
			defer cancel()
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to build jwks request", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, apperr.Wrap(apperr.CodeCancelled, "jwks fetch cancelled", err)
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, apperr.Wrap(apperr.CodeTimeout, "jwks request timed out", err)
		}
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "jwks request failed", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBodyBytes+1))
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "failed to read jwks body", err)
	}
	if len(body) > MaxJWKSBodyBytes {
		return nil, apperr.New(apperr.CodeUpstreamProtocol, "jwks response exceeds size limit")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, apperr.New(apperr.CodeUpstreamProtocol,
			fmt.Sprintf("jwks HTTP %d", resp.StatusCode))
	}

	var set JWKS
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "jwks JSON is invalid", err)
	}
	if len(set.Keys) == 0 {
		return nil, apperr.New(apperr.CodeUpstreamProtocol, "jwks contains no keys")
	}
	return &set, nil
}

// FetchJWKSFromDiscovery loads discovery then fetches JWKS from doc.JWKSURI.
func FetchJWKSFromDiscovery(ctx context.Context, client *http.Client, doc *DiscoveryDocument) (*JWKS, error) {
	if doc == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "discovery document is nil")
	}
	return FetchJWKS(ctx, client, doc.JWKSURI)
}

// KeyByID returns the first usable verification key matching kid.
// Empty kid matches the first usable key when the set has a single candidate
// (some IdPs omit kid on single-key sets); multi-key sets without kid fail closed.
func (s *JWKS) KeyByID(kid string) (any, error) {
	if s == nil || len(s.Keys) == 0 {
		return nil, apperr.New(apperr.CodeAuthentication, "jwks has no keys")
	}
	kid = strings.TrimSpace(kid)

	var candidates []JWK
	for _, k := range s.Keys {
		if k.Use != "" && !strings.EqualFold(k.Use, "sig") {
			continue
		}
		if kid != "" {
			if k.Kid != kid {
				continue
			}
		}
		candidates = append(candidates, k)
	}

	if kid == "" {
		// Only allow kid-less lookup when exactly one sig key is present.
		var allSig []JWK
		for _, k := range s.Keys {
			if k.Use != "" && !strings.EqualFold(k.Use, "sig") {
				continue
			}
			allSig = append(allSig, k)
		}
		if len(allSig) != 1 {
			return nil, apperr.New(apperr.CodeAuthentication,
				"token missing kid and jwks is multi-key; refuse ambiguous key selection")
		}
		candidates = allSig
	}

	if len(candidates) == 0 {
		return nil, apperr.New(apperr.CodeAuthentication, "no jwks key matches token kid")
	}
	// Prefer exact kid match first entry.
	pub, err := candidates[0].PublicKey()
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// PublicKey converts a JWK into a crypto public key for signature verification.
// Supports RSA (RS256) and EC P-256 (ES256). Private key fields are ignored.
func (k JWK) PublicKey() (any, error) {
	switch strings.ToUpper(strings.TrimSpace(k.Kty)) {
	case "RSA":
		return k.rsaPublic()
	case "EC":
		return k.ecPublic()
	default:
		return nil, apperr.New(apperr.CodeAuthentication,
			fmt.Sprintf("unsupported jwk kty %q", k.Kty))
	}
}

func (k JWK) rsaPublic() (*rsa.PublicKey, error) {
	if strings.TrimSpace(k.N) == "" || strings.TrimSpace(k.E) == "" {
		return nil, apperr.New(apperr.CodeAuthentication, "rsa jwk missing n or e")
	}
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		// Some issuers pad base64url.
		nb, err = base64.URLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, apperr.New(apperr.CodeAuthentication, "rsa jwk n is invalid")
		}
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		eb, err = base64.URLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, apperr.New(apperr.CodeAuthentication, "rsa jwk e is invalid")
		}
	}
	if len(nb) == 0 || len(eb) == 0 {
		return nil, apperr.New(apperr.CodeAuthentication, "rsa jwk n/e empty")
	}
	n := new(big.Int).SetBytes(nb)
	var eInt int
	for _, b := range eb {
		eInt = eInt<<8 + int(b)
	}
	if eInt <= 1 {
		return nil, apperr.New(apperr.CodeAuthentication, "rsa jwk e is invalid")
	}
	return &rsa.PublicKey{N: n, E: eInt}, nil
}

func (k JWK) ecPublic() (*ecdsa.PublicKey, error) {
	crv := strings.ToUpper(strings.TrimSpace(k.Crv))
	var curve elliptic.Curve
	switch crv {
	case "P-256", "P256":
		curve = elliptic.P256()
	default:
		return nil, apperr.New(apperr.CodeAuthentication,
			fmt.Sprintf("unsupported ec curve %q", k.Crv))
	}
	xb, err := decodeB64URL(k.X)
	if err != nil || len(xb) == 0 {
		return nil, apperr.New(apperr.CodeAuthentication, "ec jwk x is invalid")
	}
	yb, err := decodeB64URL(k.Y)
	if err != nil || len(yb) == 0 {
		return nil, apperr.New(apperr.CodeAuthentication, "ec jwk y is invalid")
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if !curve.IsOnCurve(x, y) {
		return nil, apperr.New(apperr.CodeAuthentication, "ec jwk point is not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
