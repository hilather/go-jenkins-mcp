package gateway_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

func TestLabIdentityEnabled(t *testing.T) {
	t.Parallel()
	if gateway.LabIdentityEnabled(func(string) string { return "" }) {
		t.Fatal("empty off")
	}
	for _, v := range []string{"1", "true", "TRUE", "yes", "on"} {
		if !gateway.LabIdentityEnabled(func(string) string { return v }) {
			t.Fatalf("%q should enable", v)
		}
	}
	if gateway.LabIdentityEnabled(func(string) string { return "0" }) {
		t.Fatal("0 off")
	}
}

func TestParseLabHTTPInbound_FailClosed(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	h.Set(gateway.HeaderLabSubject, "alice")
	if in := gateway.ParseLabHTTPInbound(h, false); in.Present() {
		t.Fatal("lab mode off must ignore headers")
	}
	in := gateway.ParseLabHTTPInbound(h, true)
	if !in.Present() || in.ExternalSubject != "alice" || !in.Verified {
		t.Fatalf("%+v", in)
	}
	if in.Source != "lab_header" {
		t.Fatalf("source %q", in.Source)
	}
}

func TestBindSubjectFromHTTP_Lab(t *testing.T) {
	t.Parallel()
	in := gateway.HTTPInbound{
		ExternalSubject:  "entra-sub",
		Tenant:           "tid",
		WorkloadID:       "wl",
		JenkinsPrincipal: "alice",
		Source:           "lab_header",
		Verified:         true,
	}
	s, err := gateway.BindSubjectFromHTTP(in, "corp", nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.ExternalSubject != "entra-sub" || s.JenkinsUserID != "alice" {
		t.Fatalf("%+v", s)
	}
	if !s.Valid() {
		t.Fatalf("want Valid subject: %+v", s)
	}
	// Empty inbound fails closed.
	_, err = gateway.BindSubjectFromHTTP(gateway.HTTPInbound{}, "corp", nil)
	if err == nil {
		t.Fatal("expected empty subject fail")
	}
	if strings.Contains(err.Error(), "Bearer") {
		t.Fatalf("token-like error: %v", err)
	}
}

func TestBindSubjectFromHTTP_PartialLabStillBindsExternal(t *testing.T) {
	t.Parallel()
	// Lab subject without Jenkins principal: bind succeeds but Valid() false
	// until OBO residual (same as process env foundation).
	in := gateway.HTTPInbound{
		ExternalSubject: "lab-only-sub",
		Source:          "lab_header",
		Verified:        true,
	}
	s, err := gateway.BindSubjectFromHTTP(in, "corp", nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.ExternalSubject != "lab-only-sub" {
		t.Fatalf("%+v", s)
	}
	if s.Valid() {
		t.Fatalf("partial without jenkins principal should not Valid: %+v", s)
	}
}

func TestBearerAccessToken_SkipsSharedSecret(t *testing.T) {
	t.Parallel()
	const secret = "shared-transport-secret"
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	if got := gateway.BearerAccessToken(req, secret); got != "" {
		t.Fatalf("shared secret must not be identity token, got %q", got)
	}
	req2 := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	req2.Header.Set("Authorization", "Bearer user-access-token")
	if got := gateway.BearerAccessToken(req2, secret); got != "user-access-token" {
		t.Fatalf("got %q", got)
	}
	// Prefer separate header for secret: Bearer is access token.
	req3 := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	req3.Header.Set("Authorization", "Bearer user-jwt")
	req3.Header.Set("X-Jenkins-MCP-Token", secret)
	if got := gateway.BearerAccessToken(req3, secret); got != "user-jwt" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveHTTPInbound_LabAndJWT(t *testing.T) {
	t.Parallel()
	// Lab path.
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/mcp", nil)
	req.Header.Set(gateway.HeaderLabSubject, "lab-user")
	in, err := gateway.ResolveHTTPInbound(req, "", true, nil, auth.AccessTokenParams{})
	if err != nil || !in.Present() || in.ExternalSubject != "lab-user" {
		t.Fatalf("lab: in=%+v err=%v", in, err)
	}

	// JWT path with offline JWKS.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := rsaJWKS(t, priv, "k1")
	now := time.Now()
	raw := mustSignRS256JWT(t, priv, map[string]any{
		"iss": "https://issuer.example",
		"sub": "jwt-sub-1",
		"aud": "https://jenkins.example/api",
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"tid": "tenant-1",
	}, "k1")
	reqJWT := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	reqJWT.Header.Set("Authorization", "Bearer "+raw)
	params := auth.AccessTokenParams{
		Issuer:   "https://issuer.example",
		Audience: "https://jenkins.example/api",
		Now:      func() time.Time { return now },
	}
	in, err = gateway.ResolveHTTPInbound(reqJWT, "transport-secret", false, jwks, params)
	if err != nil {
		t.Fatal(err)
	}
	if !in.Present() || in.ExternalSubject != "jwt-sub-1" || in.Source != "jwt" {
		t.Fatalf("%+v", in)
	}
	if in.Tenant != "tenant-1" {
		t.Fatalf("tenant: %q", in.Tenant)
	}

	// Invalid JWT → error, no token echo.
	reqBad := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	reqBad.Header.Set("Authorization", "Bearer "+raw+"x")
	_, err = gateway.ResolveHTTPInbound(reqBad, "", false, jwks, params)
	if err == nil {
		t.Fatal("expected invalid jwt fail")
	}
	if strings.Contains(err.Error(), raw) {
		t.Fatalf("Regression: raw JWT in error: %v", err)
	}
}

func rsaJWKS(t *testing.T, priv *rsa.PrivateKey, kid string) *auth.JWKS {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())
	return &auth.JWKS{Keys: []auth.JWK{{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   n,
		E:   e,
	}}}
}

func mustSignRS256JWT(t *testing.T, priv *rsa.PrivateKey, claims map[string]any, kid string) string {
	t.Helper()
	hdr, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	pl, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	signing := enc(hdr) + "." + enc(pl)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(sig)
}
