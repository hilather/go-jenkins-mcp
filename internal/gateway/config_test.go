package gateway_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

func TestValidateProviderConfig_OK(t *testing.T) {
	t.Parallel()
	err := gateway.ValidateProviderConfig(gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://login.microsoftonline.com/tenant/v2.0",
		Audience:                   "api://jenkins-api",
		ClientID:                   "public-client",
		Mode:                       gateway.ModeAuthorizationCode,
		JenkinsBaseURL:             "https://jenkins.example.com",
		AuthorizationEndpoint:      "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
		TokenEndpoint:              "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateProviderConfig_RejectsJenkinsAsAS(t *testing.T) {
	t.Parallel()
	// Regression / OAUTH-011 canary: stock Jenkins must never be configured as
	// OAuth authorization server (default no-go; ADR 0013 / docs/auth/jas-no-go.md §4.1).
	cases := []gateway.AgentCoreConfig{
		{
			AuthorizationServerBaseURL: "https://jenkins.example.com",
			Audience:                   "api://jenkins-api",
			JenkinsBaseURL:             "https://jenkins.example.com",
		},
		{
			AuthorizationServerBaseURL: "https://login.microsoftonline.com/t/v2.0",
			Audience:                   "api://jenkins-api",
			JenkinsBaseURL:             "https://jenkins.example.com",
			TokenEndpoint:              "https://jenkins.example.com/oauth/token",
		},
		{
			AuthorizationServerBaseURL: "https://login.microsoftonline.com/t/v2.0",
			Audience:                   "api://jenkins-api",
			JenkinsBaseURL:             "https://jenkins.example.com/",
			AuthorizationEndpoint:      "https://jenkins.example.com/as/authorization.oauth2",
		},
		{
			// Same origin different path still Jenkins.
			AuthorizationServerBaseURL: "https://jenkins.example.com/jenkins",
			Audience:                   "api://jenkins-api",
			JenkinsBaseURL:             "https://jenkins.example.com",
		},
	}
	for i, cfg := range cases {
		err := gateway.ValidateProviderConfig(cfg)
		if err == nil {
			t.Fatalf("case %d: expected reject Jenkins-as-AS", i)
		}
		if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("case %d: code %v err %v", i, apperr.CodeOf(err), err)
		}
		msg := strings.ToLower(err.Error())
		if !strings.Contains(msg, "jenkins") {
			t.Fatalf("case %d: expected jenkins wording: %v", i, err)
		}
	}
}

func TestValidateProviderConfig_MissingAudience(t *testing.T) {
	t.Parallel()
	err := gateway.ValidateProviderConfig(gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://login.microsoftonline.com/t/v2.0",
		JenkinsBaseURL:             "https://jenkins.example.com",
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "audience") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateProviderConfig_MissingAS(t *testing.T) {
	t.Parallel()
	err := gateway.ValidateProviderConfig(gateway.AgentCoreConfig{
		Audience:       "api://jenkins-api",
		JenkinsBaseURL: "https://jenkins.example.com",
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "authorization server") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateProviderConfig_RelativeEndpointsOK(t *testing.T) {
	t.Parallel()
	err := gateway.ValidateProviderConfig(gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://login.microsoftonline.com/t/v2.0",
		Audience:                   "api://jenkins-api",
		JenkinsBaseURL:             "https://jenkins.example.com",
		AuthorizationEndpoint:      "/oauth2/v2.0/authorize",
		TokenEndpoint:              "/oauth2/v2.0/token",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateProviderConfig_BadMode(t *testing.T) {
	t.Parallel()
	err := gateway.ValidateProviderConfig(gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://login.microsoftonline.com/t/v2.0",
		Audience:                   "api://jenkins-api",
		Mode:                       "password",
	})
	if err == nil {
		t.Fatal("expected bad mode")
	}
}

func TestNormalizeMode(t *testing.T) {
	t.Parallel()
	if gateway.NormalizeMode("obo") != gateway.ModeTokenExchange {
		t.Fatal("obo alias")
	}
	if gateway.NormalizeMode("AUTHORIZATION_CODE") != gateway.ModeAuthorizationCode {
		t.Fatal("auth code")
	}
	if !gateway.ModeOBO.Valid() {
		t.Fatal("ModeOBO should normalize as valid")
	}
}
