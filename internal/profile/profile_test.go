package profile_test

import (
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

func TestMigrateMissingVersion(t *testing.T) {
	t.Parallel()
	p := &profile.Profile{
		ID:         "corp",
		JenkinsURL: "https://jenkins.example.com",
		// ConfigVersion 0, AuthMethod empty
	}
	if err := profile.Migrate(p); err != nil {
		t.Fatal(err)
	}
	if p.ConfigVersion != profile.CurrentConfigVersion {
		t.Fatalf("version: got %d want %d", p.ConfigVersion, profile.CurrentConfigVersion)
	}
	if p.AuthMethod != profile.AuthMethodAPIToken {
		t.Fatalf("default authMethod: %q", p.AuthMethod)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

// QA-004: fixtures for every prior config version (0 = pre-versioned; 1 = current).
func TestMigrate_AllPriorConfigVersions(t *testing.T) {
	t.Parallel()
	// CurrentConfigVersion is 1: only v0→v1 migration exists; v1 is identity.
	if profile.CurrentConfigVersion != 1 {
		t.Fatalf("update fixtures when CurrentConfigVersion bumps (got %d)", profile.CurrentConfigVersion)
	}

	cases := []struct {
		name     string
		in       profile.Profile
		wantVer  int
		wantAuth profile.AuthMethod
	}{
		{
			name: "v0_missing_auth_defaults_api_token",
			in: profile.Profile{
				ConfigVersion: 0,
				ID:            "corp",
				JenkinsURL:    "https://jenkins.example.com",
			},
			wantVer:  profile.CurrentConfigVersion,
			wantAuth: profile.AuthMethodAPIToken,
		},
		{
			name: "v0_preserves_explicit_auth",
			in: profile.Profile{
				ConfigVersion: 0,
				ID:            "corp",
				JenkinsURL:    "https://jenkins.example.com",
				AuthMethod:    profile.AuthMethodAPIToken,
				Username:      "alice",
			},
			wantVer:  profile.CurrentConfigVersion,
			wantAuth: profile.AuthMethodAPIToken,
		},
		{
			name: "v1_noop",
			in: profile.Profile{
				ConfigVersion: 1,
				ID:            "corp",
				JenkinsURL:    "https://jenkins.example.com",
				AuthMethod:    profile.AuthMethodAPIToken,
				Username:      "bob",
				DisplayName:   "Corp Jenkins",
			},
			wantVer:  1,
			wantAuth: profile.AuthMethodAPIToken,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := tc.in // copy
			if err := profile.Migrate(&p); err != nil {
				t.Fatalf("Migrate: %v", err)
			}
			if p.ConfigVersion != tc.wantVer {
				t.Fatalf("version: got %d want %d", p.ConfigVersion, tc.wantVer)
			}
			if p.AuthMethod != tc.wantAuth {
				t.Fatalf("auth: got %q want %q", p.AuthMethod, tc.wantAuth)
			}
			// Field survival
			if tc.in.Username != "" && p.Username != tc.in.Username {
				t.Fatalf("username lost: %q", p.Username)
			}
			if tc.in.DisplayName != "" && p.DisplayName != tc.in.DisplayName {
				t.Fatalf("displayName lost: %q", p.DisplayName)
			}
			if tc.in.JenkinsURL != "" && p.JenkinsURL != tc.in.JenkinsURL {
				t.Fatalf("jenkinsURL lost: %q", p.JenkinsURL)
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("Validate after migrate: %v", err)
			}
		})
	}
}

func TestValidate_CacheEncryptionRequiresKeyVersion(t *testing.T) {
	t.Parallel()
	p := &profile.Profile{
		ConfigVersion:   profile.CurrentConfigVersion,
		ID:              "corp",
		JenkinsURL:      "https://jenkins.example.com",
		AuthMethod:      profile.AuthMethodAPIToken,
		CacheEncryption: true,
		CacheKeyVersion: 0,
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected fail closed without cacheKeyVersion")
	}
	p.CacheKeyVersion = 1
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	// Keys must never be valid profile JSON fields (store secretFieldPresent).
	p.CacheEncryption = false
	p.CacheKeyVersion = 0
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateUnsupportedVersion(t *testing.T) {
	t.Parallel()
	p := &profile.Profile{
		ConfigVersion: 99,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodAPIToken,
	}
	err := profile.Migrate(p)
	if err == nil {
		t.Fatal("expected error for future version")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code: %v", apperr.CodeOf(err))
	}
	// Non-destructive: profile fields left as loaded; clear operator message.
	if p.ConfigVersion != 99 {
		t.Fatalf("must not rewrite future configVersion: got %d", p.ConfigVersion)
	}
	msg := err.Error()
	if !strings.Contains(msg, "unsupported configVersion") {
		t.Fatalf("message: %q", msg)
	}
	if !strings.Contains(msg, "upgrade jenkins-mcp") {
		t.Fatalf("message should suggest binary upgrade: %q", msg)
	}
}

func TestMigrate_NegativeVersionRejected(t *testing.T) {
	t.Parallel()
	p := &profile.Profile{
		ConfigVersion: -1,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com",
	}
	err := profile.Migrate(p)
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("expected invalid_argument, got %v", err)
	}
}

func TestValidateURLs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		url string
		ok  bool
		sub string
	}{
		{"https://jenkins.example.com", true, ""},
		{"http://localhost:8080", true, ""},
		{"https://jenkins.example.com/jenkins", true, ""},
		{"", false, "required"},
		{"ftp://jenkins.example.com", false, "scheme"},
		{"https://", false, "host"},
		{"not a url", false, ""},
		{"https://user:pass@jenkins.example.com", false, "credential"},
		{"https://jenkins.example.com#frag", false, "fragment"},
	}
	for _, tc := range cases {
		err := profile.ValidateJenkinsURL(tc.url)
		if tc.ok && err != nil {
			t.Errorf("url %q: unexpected err %v", tc.url, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("url %q: expected error", tc.url)
		}
		if !tc.ok && tc.sub != "" && err != nil && !strings.Contains(strings.ToLower(err.Error()), tc.sub) {
			t.Errorf("url %q: error %q should mention %q", tc.url, err.Error(), tc.sub)
		}
	}
}

func TestValidateIDAndMethod(t *testing.T) {
	t.Parallel()
	ro := true
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            contracts.ProfileID("corp"),
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodAPIToken,
		ReadOnly:      &ro,
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if !p.EffectiveReadOnly() {
		t.Fatal("readOnly")
	}

	badIDs := []string{"", "../etc", "has space", "a/b", string(make([]byte, 80))}
	for _, id := range badIDs {
		p.ID = contracts.ProfileID(id)
		if err := p.Validate(); err == nil {
			t.Errorf("id %q should fail", id)
		}
	}
	p.ID = "corp"
	p.AuthMethod = "basic_auth"
	if err := p.Validate(); err == nil {
		t.Fatal("bad method should fail")
	}
	// OIDC without settings must fail.
	p.AuthMethod = profile.AuthMethodOIDC
	if err := p.Validate(); err == nil {
		t.Fatal("oidc without settings should fail")
	}
	// OIDC with Jenkins-as-issuer must fail (ADR 0003).
	p.OIDC = &profile.OIDCConfig{
		Issuer:          "https://jenkins.example.com",
		ClientID:        "client",
		JenkinsAudience: "api://jenkins",
	}
	if err := p.Validate(); err == nil {
		t.Fatal("Jenkins URL as issuer must fail")
	}
	// Valid external IdP OIDC profile.
	p.OIDC = &profile.OIDCConfig{
		Issuer:          "https://login.example.com/tenant/v2.0",
		ClientID:        "public-client",
		JenkinsAudience: "api://jenkins-api",
		Scopes:          []string{"openid", "offline_access"},
		RedirectURIs:    []string{"http://127.0.0.1:9876/callback"},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid oidc: %v", err)
	}
	// client secret must never be a profile field — covered by store canary.
	// agentcore remains reserved.
	p.AuthMethod = profile.AuthMethodAgentCoreDelegated
	p.OIDC = nil
	if err := p.Validate(); err == nil {
		t.Fatal("agentcore_delegated still reserved")
	}
}

func TestValidateOIDC_DefaultsScopesAndRejectsSecretShapes(t *testing.T) {
	t.Parallel()
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "oidc1",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodOIDC,
		OIDC: &profile.OIDCConfig{
			Issuer:          "https://idp.example.com",
			ClientID:        "cid",
			JenkinsAudience: "api://j",
			// scopes empty → default openid
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(p.OIDC.Scopes) != 1 || p.OIDC.Scopes[0] != "openid" {
		t.Fatalf("default scopes: %v", p.OIDC.Scopes)
	}
	// Missing audience
	p.OIDC.JenkinsAudience = ""
	if err := p.Validate(); err == nil {
		t.Fatal("empty audience")
	}
	p.OIDC.JenkinsAudience = "api://j"
	// oidc block on api_token profile
	p.AuthMethod = profile.AuthMethodAPIToken
	if err := p.Validate(); err == nil {
		t.Fatal("oidc settings only for oidc_bearer")
	}
}

func TestNormalizedOrigin(t *testing.T) {
	t.Parallel()
	o, err := profile.NormalizedOrigin("https://Jenkins.Example.com:8443/jenkins")
	if err != nil {
		t.Fatal(err)
	}
	if o != "https://jenkins.example.com:8443" {
		t.Fatalf("origin: %q", o)
	}
}

func TestAuthView(t *testing.T) {
	t.Parallel()
	p := &profile.Profile{
		ID:         "corp",
		JenkinsURL: "https://j.example",
		AuthMethod: profile.AuthMethodAPIToken,
		Username:   "alice",
	}
	v := p.AuthView()
	if v.ID != "corp" || v.Username != "alice" || v.Method != "api_token" {
		t.Fatalf("%+v", v)
	}
}

func TestValidateNetworkFields_NET004(t *testing.T) {
	t.Parallel()
	base := func() *profile.Profile {
		return &profile.Profile{
			ConfigVersion: profile.CurrentConfigVersion,
			ID:            "corp",
			JenkinsURL:    "https://jenkins.example.com",
			AuthMethod:    profile.AuthMethodAPIToken,
		}
	}

	p := base()
	p.CABundlePath = "/etc/ssl/corp-ca.pem"
	p.ProxyURL = "http://proxy.corp:8080"
	p.NoProxy = []string{"localhost", ".corp.internal"}
	p.ClientCertFile = "/etc/ssl/client.crt"
	p.ClientKeyFile = "/etc/ssl/client.key"
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	// Relative CA path rejected.
	p = base()
	p.CABundlePath = "relative/ca.pem"
	if err := p.Validate(); err == nil {
		t.Fatal("relative caBundlePath should fail")
	}

	// Proxy with embedded credentials rejected (no secrets in profile).
	p = base()
	p.ProxyURL = "http://user:pass@proxy.corp:8080"
	if err := p.Validate(); err == nil {
		t.Fatal("proxy credentials should fail")
	}

	// direct/none allowed.
	p = base()
	p.ProxyURL = "direct"
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	// mTLS pair must be complete.
	p = base()
	p.ClientCertFile = "/etc/ssl/client.crt"
	if err := p.Validate(); err == nil {
		t.Fatal("client cert without key should fail")
	}
}
