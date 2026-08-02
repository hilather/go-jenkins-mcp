package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
)

func TestDiscoveryURL(t *testing.T) {
	t.Parallel()
	u, err := auth.DiscoveryURL("https://login.example.com/tenant/v2.0/")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://login.example.com/tenant/v2.0/.well-known/openid-configuration"
	if u != want {
		t.Fatalf("got %q want %q", u, want)
	}
	if _, err := auth.DiscoveryURL(""); err == nil {
		t.Fatal("empty issuer should fail")
	}
}

func TestFetchAndValidateDiscovery_Good(t *testing.T) {
	t.Parallel()
	var loopIssuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=3600")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 loopIssuer,
			"authorization_endpoint": loopIssuer + "/auth",
			"token_endpoint":         loopIssuer + "/token",
			"jwks_uri":               loopIssuer + "/jwks",
		})
	}))
	defer srv.Close()
	loopIssuer = srv.URL

	client := srv.Client()
	jenkinsURL := "https://jenkins.example.com"
	doc, err := auth.FetchAndValidateDiscovery(context.Background(), client, loopIssuer, jenkinsURL)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Issuer != loopIssuer {
		t.Fatalf("issuer: %q", doc.Issuer)
	}
	if doc.JWKSURI == "" || doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		t.Fatalf("missing endpoints: %+v", doc)
	}
	if doc.ExpiresAt.IsZero() {
		t.Fatal("expected cache max-age hint on ExpiresAt")
	}
}

func TestFetchAndValidateDiscovery_IssuerMismatch(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 "https://other-idp.example.com",
			"authorization_endpoint": "https://other-idp.example.com/auth",
			"token_endpoint":         "https://other-idp.example.com/token",
			"jwks_uri":               "https://other-idp.example.com/jwks",
		})
	}))
	defer srv.Close()

	_, err := auth.FetchAndValidateDiscovery(context.Background(), srv.Client(), srv.URL, "https://jenkins.example.com")
	if err == nil {
		t.Fatal("expected issuer mismatch")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code: %v", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("msg: %v", err)
	}
}

func TestFetchAndValidateDiscovery_JenkinsAsIssuer(t *testing.T) {
	t.Parallel()
	// Discovery that points AS endpoints at the Jenkins controller host.
	jenkins := "https://jenkins.example.com"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 r.Host, // will mismatch scheme — use full loopback issuer
			"authorization_endpoint": jenkins + "/securityRealm/finishLogin",
			"token_endpoint":         jenkins + "/oauth/token",
			"jwks_uri":               jenkins + "/oauth/jwks",
		})
	}))
	defer srv.Close()

	// Correct issuer string for fetch, but document claims Jenkins endpoints.
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": jenkins + "/securityRealm/finishLogin",
			"token_endpoint":         jenkins + "/oauth/token",
			"jwks_uri":               jenkins + "/oauth/jwks",
		})
	})

	_, err := auth.FetchAndValidateDiscovery(context.Background(), srv.Client(), srv.URL, jenkins)
	if err == nil {
		t.Fatal("expected Jenkins host rejection")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "jenkins") {
		t.Fatalf("expected jenkins mention: %v", err)
	}
}

func TestValidateDiscoveryDocument_JenkinsURLAsConfiguredIssuer(t *testing.T) {
	t.Parallel()
	jenkins := "https://jenkins.example.com/"
	doc := &auth.DiscoveryDocument{
		Issuer:                "https://jenkins.example.com",
		AuthorizationEndpoint: "https://jenkins.example.com/oauth/authorize",
		TokenEndpoint:         "https://jenkins.example.com/oauth/token",
		JWKSURI:               "https://jenkins.example.com/oauth/jwks",
	}
	err := auth.ValidateDiscoveryDocument(doc, "https://jenkins.example.com", jenkins)
	if err == nil {
		t.Fatal("Jenkins-as-issuer must fail")
	}
}

func TestValidateDiscoveryDocument_MissingJWKS(t *testing.T) {
	t.Parallel()
	doc := &auth.DiscoveryDocument{
		Issuer:                "https://idp.example.com",
		AuthorizationEndpoint: "https://idp.example.com/auth",
		TokenEndpoint:         "https://idp.example.com/token",
		JWKSURI:               "",
	}
	err := auth.ValidateDiscoveryDocument(doc, "https://idp.example.com", "https://jenkins.example.com")
	if err == nil {
		t.Fatal("missing jwks must fail")
	}
	if !strings.Contains(err.Error(), "jwks_uri") {
		t.Fatalf("msg: %v", err)
	}
}

func TestValidateDiscoveryDocument_EmptyEndpointHost(t *testing.T) {
	t.Parallel()
	doc := &auth.DiscoveryDocument{
		Issuer:                "https://idp.example.com",
		AuthorizationEndpoint: "https://idp.example.com/auth",
		TokenEndpoint:         "https:///token", // empty host
		JWKSURI:               "https://idp.example.com/jwks",
	}
	err := auth.ValidateDiscoveryDocument(doc, "https://idp.example.com", "https://jenkins.example.com")
	if err == nil {
		t.Fatal("empty host must fail")
	}
}

func TestValidateOIDCProfileOffline(t *testing.T) {
	t.Parallel()
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp-oidc",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodOIDC,
		OIDC: &profile.OIDCConfig{
			Issuer:          "https://login.microsoftonline.com/tenant/v2.0",
			ClientID:        "public-client-id",
			JenkinsAudience: "api://jenkins-api",
			Scopes:          []string{"openid"},
			RedirectURIs:    []string{"http://127.0.0.1:8765/callback"},
		},
	}
	if err := auth.ValidateOIDCProfileOffline(p); err != nil {
		t.Fatal(err)
	}
	// api_token profile rejected for oauth validate path
	p.AuthMethod = profile.AuthMethodAPIToken
	p.OIDC = nil
	if err := auth.ValidateOIDCProfileOffline(p); err == nil {
		t.Fatal("api_token should not pass oauth offline validate")
	}
}
