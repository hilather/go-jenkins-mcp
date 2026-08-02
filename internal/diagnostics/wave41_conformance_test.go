package diagnostics_test

import (
	"os"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/mcpserver"
)

// Wave 41 / POL-005: HTTP deny-anonymous is env alias for RequireToken (default off).

// TestWave41_HTTPDenyAnonymous_Hard asserts loopback residual default + require-token fail-closed.
// Deny-anonymous is cmd-level env OR into RequireToken (tested in cmd package); here we
// assert the ValidateHTTPConfig semantics that alias shares.
func TestWave41_HTTPDenyAnonymous_Hard(t *testing.T) {
	t.Parallel()

	// Hard baseline (KD-008): RequireToken without BearerToken fails closed.
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.RequireToken = true
	cfg.BearerToken = ""
	if err := mcpserver.ValidateHTTPConfig(cfg); err == nil {
		t.Fatal("RequireToken with empty BearerToken must fail closed")
	}

	// Loopback without RequireToken remains allowed (documented residual; deny-anonymous default off).
	cfgLoop := mcpserver.DefaultHTTPConfig()
	cfgLoop.Addr = "127.0.0.1:0"
	cfgLoop.RequireToken = false
	cfgLoop.BearerToken = ""
	if err := mcpserver.ValidateHTTPConfig(cfgLoop); err != nil {
		t.Fatalf("loopback default must still validate: %v", err)
	}

	// Env name documented for operators (no secret values).
	for _, key := range []string{
		"JENKINS_MCP_HTTP_DENY_ANONYMOUS",
		"JENKINS_MCP_HTTP_REQUIRE_TOKEN",
	} {
		_ = os.Getenv(key) // presence optional; name is the public contract
	}
}
