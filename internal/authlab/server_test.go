package authlab_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/authlab"
)

const canaryTokenFragment = "CANARY_MUST_NOT_APPEAR_IN_RS_ERRORS"

func TestOIDC_DiscoveryJWKSMint(t *testing.T) {
	t.Parallel()
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	// Use dynamic issuer from httptest URL after start — bootstrap with placeholder then rebuild.
	// Simpler: fixed issuer matching test server URL after NewServer.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Will rebind after NewOIDCServer
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	oidc, err := authlab.NewOIDCServer(authlab.OIDCConfig{
		Issuer:          srv.URL,
		Key:             key,
		DefaultAudience: authlab.DefaultAudience,
		DefaultSubject:  "lab-user",
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = oidc.Handler()

	// Discovery
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var disc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatal(err)
	}
	if disc["issuer"] != srv.URL {
		t.Fatalf("issuer: %v", disc["issuer"])
	}
	if disc["jwks_uri"] != srv.URL+"/jwks" {
		t.Fatalf("jwks_uri: %v", disc["jwks_uri"])
	}

	// JWKS
	resp2, err := http.Get(srv.URL + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var jwks authlab.JWKS
	if err := json.NewDecoder(resp2.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatal("expected one key")
	}

	// Mint
	resp3, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type": {"client_credentials"},
		"audience":   {authlab.DefaultAudience},
		"subject":    {"mint-user"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	var tokResp map[string]any
	if err := json.NewDecoder(resp3.Body).Decode(&tokResp); err != nil {
		t.Fatal(err)
	}
	access, _ := tokResp["access_token"].(string)
	if access == "" {
		t.Fatal("missing access_token")
	}
	// Validate
	claims, err := authlab.ValidateAccessToken(access, &jwks, authlab.ValidateParams{
		Issuer:   srv.URL,
		Audience: authlab.DefaultAudience,
	})
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "mint-user" {
		t.Fatalf("sub %q", claims.Subject)
	}
}

func TestRS_ValidAndFailClosed(t *testing.T) {
	t.Parallel()
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := key.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	const iss = "http://127.0.0.1:18081"

	rs, err := authlab.NewRSServer(authlab.RSConfig{
		Issuer:   iss,
		Audience: authlab.DefaultAudience,
		JWKS:     jwks,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(rs.Handler())
	t.Cleanup(ts.Close)

	good, err := key.MintAccessToken(authlab.MintParams{
		Issuer: iss, Subject: "alice", Audience: authlab.DefaultAudience,
		TTL: time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	// Valid → 200
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/whoAmI", nil)
	req.Header.Set("Authorization", "Bearer "+good)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), good) {
		t.Fatal("token echoed in body")
	}
	var okBody map[string]any
	if err := json.Unmarshal(body, &okBody); err != nil {
		t.Fatal(err)
	}
	if okBody["ok"] != true || okBody["sub"] != "alice" {
		t.Fatalf("body: %v", okBody)
	}

	// Wrong aud → 401
	badAud, _ := key.MintAccessToken(authlab.MintParams{
		Issuer: iss, Subject: "alice", Audience: "https://graph.microsoft.com",
		TTL: time.Hour, Now: func() time.Time { return now },
	})
	assertRS401(t, ts.URL, "Bearer "+badAud)

	// Expired → 401
	expTok, _ := key.MintAccessToken(authlab.MintParams{
		Issuer: iss, Subject: "alice", Audience: authlab.DefaultAudience,
		ExpOffset: -time.Hour, Now: func() time.Time { return now },
	})
	assertRS401(t, ts.URL, "Bearer "+expTok)

	// Wrong iss → 401
	badIss, _ := key.MintAccessToken(authlab.MintParams{
		Issuer: "https://evil.example", Subject: "alice", Audience: authlab.DefaultAudience,
		TTL: time.Hour, Now: func() time.Time { return now },
	})
	assertRS401(t, ts.URL, "Bearer "+badIss)

	// Missing auth → 401
	assertRS401(t, ts.URL, "")

	// Invalid Bearer must not fall through to Basic
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/whoAmI", nil)
	req2.Header.Set("Authorization", "Bearer "+canaryTokenFragment+".not.jwt")
	req2.Header.Add("Authorization", "Basic YWRtaW46dGVzdA==") // ignored; net/http keeps first
	// Set both via single header simulation: Bearer present → 401, not 200.
	req2.Header.Set("Authorization", "Bearer invalid-token-value")
	// Also prove Basic alone fails on OAuth-required route.
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != 401 {
		t.Fatalf("invalid bearer status %d", resp2.StatusCode)
	}
	if strings.Contains(string(b2), canaryTokenFragment) || strings.Contains(string(b2), "invalid-token-value") {
		t.Fatal("token leaked in error body")
	}

	req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/mcp-rs/check", nil)
	req3.Header.Set("Authorization", "Basic YWRtaW46dGVzdA==")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp3.Body.Close()
	if resp3.StatusCode != 401 {
		t.Fatalf("basic fallthrough status %d", resp3.StatusCode)
	}
}

func assertRS401(t *testing.T, base, authz string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/api/whoAmI", nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 got %d body %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "Bearer ") && strings.Count(string(body), ".") >= 2 {
		// crude: JWT-shaped leak
		t.Fatalf("possible token leak: %s", body)
	}
}

func TestToken_Scenarios(t *testing.T) {
	t.Parallel()
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	const iss = "http://127.0.0.1:18081"
	tokSrv, err := authlab.NewTokenServer(authlab.TokenConfig{
		Issuer:          iss,
		Key:             key,
		DefaultAudience: authlab.DefaultAudience,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(tokSrv.Handler())
	t.Cleanup(ts.Close)

	// Success
	resp, err := http.PostForm(ts.URL+"/oauth2/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject":    {"gw-user"},
		"audience":   {authlab.DefaultAudience},
	})
	if err != nil {
		t.Fatal(err)
	}
	var ok map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&ok); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ok["access_token"] == nil || ok["token_type"] != "Bearer" {
		t.Fatalf("resp: %v", ok)
	}
	if ok["audience"] != authlab.DefaultAudience {
		t.Fatalf("aud: %v", ok["audience"])
	}
	if ok["jenkins_principal"] != "gw-user" {
		t.Fatalf("principal: %v", ok["jenkins_principal"])
	}

	// Wrong audience scenario
	resp2, err := http.Get(ts.URL + "/token?scenario=wrong_audience")
	if err != nil {
		t.Fatal(err)
	}
	var wa map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&wa)
	_ = resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("status %d", resp2.StatusCode)
	}
	if wa["audience"] != "https://graph.microsoft.com" {
		t.Fatalf("expected graph aud, got %v", wa["audience"])
	}

	// Consent — 403, no access_token
	resp3, err := http.Get(ts.URL + "/token?scenario=consent")
	if err != nil {
		t.Fatal(err)
	}
	body3, _ := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()
	if resp3.StatusCode != 403 {
		t.Fatalf("consent status %d", resp3.StatusCode)
	}
	var cr map[string]any
	if err := json.Unmarshal(body3, &cr); err != nil {
		t.Fatal(err)
	}
	if cr["error"] != "consent_required" {
		t.Fatalf("%v", cr)
	}
	if cr["authorization_url"] == nil || cr["authorization_url"] == "" {
		t.Fatal("missing authorization_url")
	}
	if _, has := cr["access_token"]; has {
		t.Fatal("consent must not include access_token")
	}
	if strings.Contains(string(body3), "eyJ") {
		t.Fatal("jwt-looking material in consent body")
	}

	// Error scenario → 500
	resp4, err := http.Get(ts.URL + "/token?scenario=error")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp4.Body.Close()
	if resp4.StatusCode != 500 {
		t.Fatalf("error status %d", resp4.StatusCode)
	}
}

func TestOIDC_ScenarioWrongAudience(t *testing.T) {
	t.Parallel()
	key, _ := authlab.GenerateLabKey()
	ts := httptest.NewServer(nil)
	t.Cleanup(ts.Close)
	oidc, err := authlab.NewOIDCServer(authlab.OIDCConfig{Issuer: ts.URL, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = oidc.Handler()

	resp, err := http.Get(ts.URL + "/token?scenario=wrong_audience")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	_ = resp.Body.Close()
	if body["audience"] != "https://graph.microsoft.com" {
		t.Fatalf("%v", body)
	}
	jwks, _ := key.JWKS()
	tok, _ := body["access_token"].(string)
	_, err = authlab.ValidateAccessToken(tok, jwks, authlab.ValidateParams{
		Issuer:   ts.URL,
		Audience: authlab.DefaultAudience,
	})
	if err == nil {
		t.Fatal("expected reject")
	}
}
