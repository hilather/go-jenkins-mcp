package auth_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
)

const jwtCanary = "CANARY_JWT_ACCESS_TOKEN_must_not_appear_in_errors_XYZ789"

func TestClassifyAccessToken(t *testing.T) {
	t.Parallel()
	if auth.ClassifyAccessToken("not-a-jwt") != auth.TokenFormOpaque {
		t.Fatal("expected opaque")
	}
	if auth.ClassifyAccessToken("a.b") != auth.TokenFormOpaque {
		t.Fatal("two segments opaque")
	}
	// Minimal eyJ header shape.
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	tok := hdr + "." + payload + "." + sig
	if auth.ClassifyAccessToken(tok) != auth.TokenFormJWT {
		t.Fatalf("expected jwt, got %s", auth.ClassifyAccessToken(tok))
	}
}

func TestValidateAccessToken_Opaque(t *testing.T) {
	t.Parallel()
	res, err := auth.ValidateAccessToken("opaque-ref-token-abc", nil, auth.AccessTokenParams{
		Issuer:   "https://idp.example.com",
		Audience: "https://jenkins.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Form != auth.TokenFormOpaque {
		t.Fatalf("form: %s", res.Form)
	}
	if res.Claims.Subject != "" {
		t.Fatal("opaque has no claims")
	}
}

func TestValidateAccessToken_GoodRS256(t *testing.T) {
	t.Parallel()
	priv, jwks := testRSAJWKS(t, "kid-1")
	now := time.Unix(1_700_000_000, 0)
	tok := mustSignRS256(t, priv, "kid-1", map[string]any{
		"iss":                "https://idp.example.com/tenant",
		"sub":                "user-sub-1",
		"preferred_username": "alice@corp.example",
		"aud":                "https://jenkins.example.com",
		"exp":                now.Add(time.Hour).Unix(),
		"nbf":                now.Add(-time.Minute).Unix(),
		"azp":                "mcp-public-client",
		"tid":                "tenant-guid",
		"token_use":          "access_token",
	})
	res, err := auth.ValidateAccessToken(tok, jwks, auth.AccessTokenParams{
		Issuer:   "https://idp.example.com/tenant",
		Audience: "https://jenkins.example.com",
		ClientID: "mcp-public-client",
		TenantID: "tenant-guid",
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Form != auth.TokenFormJWT {
		t.Fatal(res.Form)
	}
	if res.Claims.Subject != "user-sub-1" {
		t.Fatalf("sub: %q", res.Claims.Subject)
	}
	if res.Claims.PreferredUsername != "alice@corp.example" {
		t.Fatalf("pref: %q", res.Claims.PreferredUsername)
	}
	label := auth.SessionLabelFromClaims(res.Claims)
	if label != "alice@corp.example" {
		t.Fatalf("label: %q", label)
	}
	sess := auth.BindAccessTokenSession(auth.Session{}, tok, res)
	if sess.Method != auth.MethodOIDC || sess.User != "alice@corp.example" || sess.Secret != tok {
		t.Fatalf("session: %+v", sess)
	}
}

// TestValidateAccessToken_FailClosedCases is the OAUTH-003 completeness checklist
// (wrong issuer/audience/alg/time/client/tenant, ID token, Graph, size, empty).
func TestValidateAccessToken_FailClosedCases(t *testing.T) {
	t.Parallel()
	priv, jwks := testRSAJWKS(t, "kid-1")
	now := time.Unix(1_700_000_000, 0)
	baseClaims := func(mut func(map[string]any)) string {
		c := map[string]any{
			"iss":       "https://idp.example.com",
			"sub":       "user-1",
			"aud":       "https://jenkins.example.com",
			"exp":       now.Add(time.Hour).Unix(),
			"token_use": "access_token",
		}
		if mut != nil {
			mut(c)
		}
		return mustSignRS256(t, priv, "kid-1", c)
	}
	params := auth.AccessTokenParams{
		Issuer:   "https://idp.example.com",
		Audience: "https://jenkins.example.com",
		Now:      func() time.Time { return now },
	}
	// Oversized compact JWT (size check runs before signature).
	oversized := func() string {
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"kid-1","typ":"JWT"}`))
		// Inflate payload so total token > MaxAccessTokenBytes.
		pad := strings.Repeat("A", auth.MaxAccessTokenBytes)
		pl := base64.RawURLEncoding.EncodeToString([]byte(`{"pad":"` + pad + `"}`))
		sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
		return hdr + "." + pl + "." + sig
	}()

	cases := []struct {
		name string
		tok  string
		p    auth.AccessTokenParams
		jwks *auth.JWKS
	}{
		{
			name: "empty_token",
			tok:  "",
			p:    params,
			jwks: jwks,
		},
		{
			name: "oversized_token",
			tok:  oversized,
			p:    params,
			jwks: jwks,
		},
		{
			name: "wrong_issuer",
			tok:  baseClaims(func(m map[string]any) { m["iss"] = "https://evil.example.com" }),
			p:    params,
			jwks: jwks,
		},
		{
			name: "wrong_audience",
			tok:  baseClaims(func(m map[string]any) { m["aud"] = "https://other.example.com" }),
			p:    params,
			jwks: jwks,
		},
		{
			name: "graph_audience",
			tok: baseClaims(func(m map[string]any) {
				m["aud"] = "https://graph.microsoft.com"
			}),
			p:    params,
			jwks: jwks,
		},
		{
			name: "graph_appid_audience",
			tok: baseClaims(func(m map[string]any) {
				m["aud"] = "00000003-0000-0000-c000-000000000000"
			}),
			p:    params,
			jwks: jwks,
		},
		{
			name: "graph_default_scope_audience",
			tok: baseClaims(func(m map[string]any) {
				m["aud"] = "https://graph.microsoft.com/.default"
			}),
			p:    params,
			jwks: jwks,
		},
		{
			name: "azure_arm_audience",
			tok: baseClaims(func(m map[string]any) {
				m["aud"] = "https://management.azure.com"
			}),
			p:    params,
			jwks: jwks,
		},
		{
			name: "expired",
			tok:  baseClaims(func(m map[string]any) { m["exp"] = now.Add(-time.Hour).Unix() }),
			p:    params,
			jwks: jwks,
		},
		{
			name: "nbf_future",
			tok:  baseClaims(func(m map[string]any) { m["nbf"] = now.Add(2 * time.Hour).Unix() }),
			p:    params,
			jwks: jwks,
		},
		{
			name: "missing_sub",
			tok:  baseClaims(func(m map[string]any) { delete(m, "sub") }),
			p:    params,
			jwks: jwks,
		},
		{
			name: "id_token_use",
			tok:  baseClaims(func(m map[string]any) { m["token_use"] = "id_token" }),
			p:    params,
			jwks: jwks,
		},
		{
			name: "id_token_payload_typ",
			tok: baseClaims(func(m map[string]any) {
				delete(m, "token_use")
				m["typ"] = "id_token"
			}),
			p:    params,
			jwks: jwks,
		},
		{
			name: "id_token_ver_claim",
			tok: baseClaims(func(m map[string]any) {
				delete(m, "token_use")
				m["ver"] = "id_token"
			}),
			p:    params,
			jwks: jwks,
		},
		{
			name: "id_token_nonce",
			tok: baseClaims(func(m map[string]any) {
				delete(m, "token_use")
				m["nonce"] = "abc"
			}),
			p:    params,
			jwks: jwks,
		},
		{
			name: "id_token_header_typ",
			tok: mustSignRS256Header(t, priv, "kid-1", map[string]string{
				"alg": "RS256", "typ": "id_token", "kid": "kid-1",
			}, map[string]any{
				"iss": "https://idp.example.com", "sub": "user-1",
				"aud": "https://jenkins.example.com",
				"exp": now.Add(time.Hour).Unix(),
			}),
			p:    params,
			jwks: jwks,
		},
		{
			name: "alg_none",
			tok: func() string {
				hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"kid-1"}`))
				payload := base64.RawURLEncoding.EncodeToString([]byte(
					`{"iss":"https://idp.example.com","sub":"u","aud":"https://jenkins.example.com","exp":9999999999,"token_use":"access_token"}`))
				return hdr + "." + payload + "." + "e30"
			}(),
			p:    params,
			jwks: jwks,
		},
		{
			name: "alg_hs256",
			tok: func() string {
				hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"kid-1","typ":"JWT"}`))
				payload := base64.RawURLEncoding.EncodeToString([]byte(
					`{"iss":"https://idp.example.com","sub":"u","aud":"https://jenkins.example.com","exp":9999999999,"token_use":"access_token"}`))
				return hdr + "." + payload + "." + base64.RawURLEncoding.EncodeToString([]byte("not-a-real-hmac"))
			}(),
			p:    params,
			jwks: jwks,
		},
		{
			name: "bad_sig",
			tok: func() string {
				// Sign with different key.
				other, _ := testRSAJWKS(t, "kid-1")
				return mustSignRS256(t, other, "kid-1", map[string]any{
					"iss": "https://idp.example.com", "sub": "u",
					"aud": "https://jenkins.example.com",
					"exp": now.Add(time.Hour).Unix(),
				})
			}(),
			p:    params,
			jwks: jwks,
		},
		{
			name: "unknown_kid",
			tok:  baseClaims(nil),
			p:    params,
			jwks: func() *auth.JWKS {
				_, j := testRSAJWKS(t, "other-kid")
				return j
			}(),
		},
		{
			name: "wrong_client",
			tok:  baseClaims(func(m map[string]any) { m["azp"] = "other-client" }),
			p: auth.AccessTokenParams{
				Issuer: "https://idp.example.com", Audience: "https://jenkins.example.com",
				ClientID: "mcp-public-client", Now: params.Now,
			},
			jwks: jwks,
		},
		{
			name: "wrong_tenant",
			tok:  baseClaims(func(m map[string]any) { m["tid"] = "other-tenant" }),
			p: auth.AccessTokenParams{
				Issuer: "https://idp.example.com", Audience: "https://jenkins.example.com",
				TenantID: "expected-tenant", Now: params.Now,
			},
			jwks: jwks,
		},
		{
			name: "profile_graph_audience_rejected",
			tok: baseClaims(func(m map[string]any) {
				m["aud"] = "https://graph.microsoft.com"
			}),
			p: auth.AccessTokenParams{
				Issuer: "https://idp.example.com", Audience: "https://graph.microsoft.com",
				Now: params.Now,
			},
			jwks: jwks,
		},
		{
			name: "profile_graph_appid_audience_rejected",
			tok: baseClaims(func(m map[string]any) {
				m["aud"] = "00000003-0000-0000-c000-000000000000"
			}),
			p: auth.AccessTokenParams{
				Issuer: "https://idp.example.com", Audience: "00000003-0000-0000-c000-000000000000",
				Now: params.Now,
			},
			jwks: jwks,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := auth.ValidateAccessToken(tc.tok, tc.jwks, tc.p)
			if err == nil {
				t.Fatal("expected fail closed")
			}
			if apperr.CodeOf(err) != apperr.CodeAuthentication && apperr.CodeOf(err) != apperr.CodeInvalidArgument {
				t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
			}
			if tc.tok != "" && strings.Contains(err.Error(), tc.tok) {
				t.Fatalf("token leaked in error: %v", err)
			}
		})
	}
}

// TestValidateAccessToken_IDTokenShapeRejected is the explicit OAUTH-003 canary:
// Entra-like ID token must never be accepted as a Jenkins API access token.
func TestValidateAccessToken_IDTokenShapeRejected(t *testing.T) {
	t.Parallel()
	priv, jwks := testRSAJWKS(t, "kid-1")
	now := time.Unix(1_700_000_000, 0)
	// Classic Entra ID token shape: aud=client_id, token_use=id_token, nonce present.
	tok := mustSignRS256(t, priv, "kid-1", map[string]any{
		"iss":                "https://idp.example.com",
		"sub":                "user-oid",
		"aud":                "mcp-public-client",
		"exp":                now.Add(time.Hour).Unix(),
		"nbf":                now.Add(-time.Minute).Unix(),
		"iat":                now.Unix(),
		"token_use":          "id_token",
		"nonce":              "login-nonce-xyz",
		"preferred_username": "alice@corp.example",
		"ver":                "2.0",
	})
	_, err := auth.ValidateAccessToken(tok, jwks, auth.AccessTokenParams{
		Issuer:   "https://idp.example.com",
		Audience: "https://jenkins.example.com",
		ClientID: "mcp-public-client",
		Now:      func() time.Time { return now },
	})
	if err == nil {
		t.Fatal("id_token shape must be rejected for Jenkins bearer path")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code: %v", apperr.CodeOf(err))
	}
	if strings.Contains(err.Error(), tok) {
		t.Fatalf("token leaked: %v", err)
	}
	// Even if profile audience were wrongly set to the client id, token_use still rejects.
	_, err = auth.ValidateAccessToken(tok, jwks, auth.AccessTokenParams{
		Issuer:   "https://idp.example.com",
		Audience: "mcp-public-client",
		ClientID: "mcp-public-client",
		Now:      func() time.Time { return now },
	})
	if err == nil {
		t.Fatal("id_token must fail even when aud matches client_id")
	}
}

func TestValidateAccessToken_AlgNoneRejected(t *testing.T) {
	t.Parallel()
	_, jwks := testRSAJWKS(t, "kid-1")
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"kid-1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://idp.example.com","sub":"u","aud":"https://jenkins.example.com","exp":9999999999}`))
	tok := hdr + "." + payload + "."
	// looksLikeJWT rejects empty sig segment; force three non-empty segments with empty sig bytes encoded.
	tok = hdr + "." + payload + "." + base64.RawURLEncoding.EncodeToString([]byte{})
	// Empty base64 of empty is empty string — still 2 dots with empty last. Craft dummy sig.
	tok = hdr + "." + payload + "." + "e30"
	_, err := auth.ValidateAccessToken(tok, jwks, auth.AccessTokenParams{
		Issuer: "https://idp.example.com", Audience: "https://jenkins.example.com",
	})
	if err == nil {
		t.Fatal("alg=none must fail")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "none") &&
		!strings.Contains(strings.ToLower(err.Error()), "algorithm") &&
		!strings.Contains(strings.ToLower(err.Error()), "signature") {
		// Accept either alg rejection or signature failure — both fail closed.
		t.Logf("err: %v", err)
	}
	if strings.Contains(err.Error(), tok) {
		t.Fatal("token leak")
	}
}

func TestValidateAccessToken_JWKSRotation(t *testing.T) {
	t.Parallel()
	priv1, j1 := testRSAJWKS(t, "k1")
	priv2, j2 := testRSAJWKS(t, "k2")
	// Combined set simulates rotation overlap.
	combined := &auth.JWKS{Keys: append(append([]auth.JWK{}, j1.Keys...), j2.Keys...)}
	now := time.Unix(1_700_000_000, 0)
	claims := map[string]any{
		"iss": "https://idp.example.com", "sub": "u",
		"aud":       "https://jenkins.example.com",
		"exp":       now.Add(time.Hour).Unix(),
		"token_use": "access_token",
	}
	tok1 := mustSignRS256(t, priv1, "k1", claims)
	tok2 := mustSignRS256(t, priv2, "k2", claims)
	p := auth.AccessTokenParams{
		Issuer: "https://idp.example.com", Audience: "https://jenkins.example.com",
		Now: func() time.Time { return now },
	}
	if _, err := auth.ValidateAccessToken(tok1, combined, p); err != nil {
		t.Fatalf("k1 during rotation: %v", err)
	}
	if _, err := auth.ValidateAccessToken(tok2, combined, p); err != nil {
		t.Fatalf("k2 during rotation: %v", err)
	}
	// After old key removed, k1 fails closed; unknown issuer keys not accepted.
	if _, err := auth.ValidateAccessToken(tok1, j2, p); err == nil {
		t.Fatal("old kid after rotation must fail")
	}
}

func TestValidateAccessToken_AudienceArrayAndResource(t *testing.T) {
	t.Parallel()
	priv, jwks := testRSAJWKS(t, "kid-1")
	now := time.Unix(1_700_000_000, 0)
	tok := mustSignRS256(t, priv, "kid-1", map[string]any{
		"iss":       "https://idp.example.com",
		"sub":       "u",
		"aud":       []string{"api://other", "https://jenkins.example.com"},
		"exp":       now.Add(time.Hour).Unix(),
		"token_use": "access_token",
	})
	_, err := auth.ValidateAccessToken(tok, jwks, auth.AccessTokenParams{
		Issuer: "https://idp.example.com", Audience: "https://jenkins.example.com",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	// resource claim as exact audience
	tok2 := mustSignRS256(t, priv, "kid-1", map[string]any{
		"iss": "https://idp.example.com", "sub": "u",
		"aud":       "api://something",
		"resource":  "https://jenkins.example.com",
		"exp":       now.Add(time.Hour).Unix(),
		"token_use": "access_token",
	})
	_, err = auth.ValidateAccessToken(tok2, jwks, auth.AccessTokenParams{
		Issuer: "https://idp.example.com", Audience: "https://jenkins.example.com",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateAccessToken_ClockSkew(t *testing.T) {
	t.Parallel()
	priv, jwks := testRSAJWKS(t, "kid-1")
	now := time.Unix(1_700_000_000, 0)
	// Expired 30s ago — within default 60s skew.
	tok := mustSignRS256(t, priv, "kid-1", map[string]any{
		"iss": "https://idp.example.com", "sub": "u",
		"aud":       "https://jenkins.example.com",
		"exp":       now.Add(-30 * time.Second).Unix(),
		"token_use": "access_token",
	})
	_, err := auth.ValidateAccessToken(tok, jwks, auth.AccessTokenParams{
		Issuer: "https://idp.example.com", Audience: "https://jenkins.example.com",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("within skew should pass: %v", err)
	}
	// Expired 2 minutes ago — fail.
	tok2 := mustSignRS256(t, priv, "kid-1", map[string]any{
		"iss": "https://idp.example.com", "sub": "u",
		"aud":       "https://jenkins.example.com",
		"exp":       now.Add(-2 * time.Minute).Unix(),
		"token_use": "access_token",
	})
	_, err = auth.ValidateAccessToken(tok2, jwks, auth.AccessTokenParams{
		Issuer: "https://idp.example.com", Audience: "https://jenkins.example.com",
		Now: func() time.Time { return now },
	})
	if err == nil {
		t.Fatal("beyond skew must fail")
	}
}

func TestValidateAccessToken_EmptyAndCanary(t *testing.T) {
	t.Parallel()
	_, err := auth.ValidateAccessToken("", nil, auth.AccessTokenParams{})
	if err == nil {
		t.Fatal("empty")
	}
	// Canary: force scrub path with a crafted JWT that embeds canary-like material only in token.
	// Opaque path doesn't error; use JWT with missing jwks.
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"x"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"i","sub":"s","aud":"a","exp":1}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte(jwtCanary))
	tok := hdr + "." + payload + "." + sig
	_, err = auth.ValidateAccessToken(tok, &auth.JWKS{Keys: []auth.JWK{{Kty: "RSA", Kid: "x", N: "AQAB", E: "AQAB"}}}, auth.AccessTokenParams{
		Issuer: "i", Audience: "a",
	})
	if err == nil {
		// May fail on key parse or sig — either way.
		t.Log("unexpected success")
	} else if strings.Contains(err.Error(), jwtCanary) {
		t.Fatalf("canary leaked: %v", err)
	}
}

func TestSessionCredentialsFrom(t *testing.T) {
	t.Parallel()
	basic := auth.SessionCredentialsFrom(auth.Session{Method: auth.MethodAPIToken, User: "a", Secret: "t", ProfileID: "p"})
	if basic.Scheme != auth.HTTPAuthBasic || basic.User != "a" || basic.Secret != "t" {
		t.Fatalf("%+v", basic)
	}
	oidc := auth.SessionCredentialsFrom(auth.Session{Method: auth.MethodOIDC, User: "alice", Secret: "tok"})
	if oidc.Scheme != auth.HTTPAuthBearer {
		t.Fatalf("%+v", oidc)
	}
}

// --- test helpers ---

func testRSAJWKS(t *testing.T, kid string) (*rsa.PrivateKey, *auth.JWKS) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())
	return priv, &auth.JWKS{Keys: []auth.JWK{{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   n,
		E:   e,
	}}}
}

func mustSignRS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	return mustSignRS256Header(t, priv, kid, map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}, claims)
}

func mustSignRS256Header(t *testing.T, priv *rsa.PrivateKey, kid string, header map[string]string, claims map[string]any) string {
	t.Helper()
	if header == nil {
		header = map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	}
	if _, ok := header["kid"]; !ok && kid != "" {
		header["kid"] = kid
	}
	hdr, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	h := base64.RawURLEncoding.EncodeToString(hdr)
	p := base64.RawURLEncoding.EncodeToString(pl)
	input := h + "." + p
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
