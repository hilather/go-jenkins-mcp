package gateway_test

import (
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

func TestModeEnabled(t *testing.T) {
	// Uses t.Setenv — not parallel.
	if !gateway.ModeEnabled(true, false) {
		t.Fatal("flag")
	}
	if !gateway.ModeEnabled(false, true) {
		t.Fatal("profile")
	}
	t.Setenv(gateway.EnvGatewayModeVar, "")
	if gateway.ModeEnabled(false, false) {
		t.Fatal("expected disabled")
	}
	t.Setenv(gateway.EnvGatewayModeVar, "1")
	if !gateway.ModeEnabled(false, false) {
		t.Fatal("env")
	}
}

func TestConfigFromEnviron(t *testing.T) {
	t.Setenv(gateway.EnvAgentCoreASURL, "https://login.microsoftonline.com/t/v2.0")
	t.Setenv(gateway.EnvAgentCoreAudience, "api://jenkins-api")
	t.Setenv(gateway.EnvAgentCoreClientID, "cid")
	t.Setenv(gateway.EnvAgentCoreMode, "token_exchange")
	cfg := gateway.ConfigFromEnviron("https://jenkins.example.com")
	if cfg.AuthorizationServerBaseURL == "" || cfg.Audience == "" {
		t.Fatalf("%+v", cfg)
	}
	if err := gateway.ValidateProviderConfig(cfg); err != nil {
		t.Fatal(err)
	}
}
