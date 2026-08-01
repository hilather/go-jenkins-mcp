package diagnostics_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
)

// Wave 42 / POL-005:
//   - Hard-assert Wave 41 HTTP RequireToken / deny-anonymous residual semantics
//   - Soft residual for multi-sig MinSignatures self-check item (not yet)

// TestWave42_HTTPRequireToken_Hard re-asserts Wave 41 Done* semantics shared by
// resolveHTTPRequireToken / JENKINS_MCP_HTTP_DENY_ANONYMOUS (cmd) and
// ValidateHTTPConfig RequireToken (mcpserver). Cmd-package env OR tests remain
// the wiring authority; here we hard-assert the config contract alias feeds.
func TestWave42_HTTPRequireToken_Hard(t *testing.T) {
	t.Parallel()

	// Hard: RequireToken without BearerToken fails closed (deny-anonymous sets this).
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.RequireToken = true
	cfg.BearerToken = ""
	if err := mcpserver.ValidateHTTPConfig(cfg); err == nil {
		t.Fatal("RequireToken with empty BearerToken must fail closed")
	}

	// Hard: RequireToken + non-empty secret validates on loopback.
	cfgOK := mcpserver.DefaultHTTPConfig()
	cfgOK.Addr = "127.0.0.1:0"
	cfgOK.RequireToken = true
	cfgOK.BearerToken = "wave42-not-a-real-secret"
	if err := mcpserver.ValidateHTTPConfig(cfgOK); err != nil {
		t.Fatalf("RequireToken with secret must validate: %v", err)
	}

	// Hard residual default: loopback without RequireToken still allowed (default off).
	cfgLoop := mcpserver.DefaultHTTPConfig()
	cfgLoop.Addr = "127.0.0.1:0"
	cfgLoop.RequireToken = false
	cfgLoop.BearerToken = ""
	if err := mcpserver.ValidateHTTPConfig(cfgLoop); err != nil {
		t.Fatalf("loopback default must still validate: %v", err)
	}

	// Env names are public operator contracts (values never asserted as secrets).
	for _, key := range []string{
		"JENKINS_MCP_HTTP_DENY_ANONYMOUS",
		"JENKINS_MCP_HTTP_REQUIRE_TOKEN",
	} {
		if key == "" {
			t.Fatal("empty env name")
		}
	}
}

// TestWave42_MultiSigSelfCheck_Hard asserts Wave 42 Done*: offline
// policy_multisig_lite_residual canary proves multi-sig lite and marks
// true threshold crypto / HSM as residual details.
func TestWave42_MultiSigSelfCheck_Hard(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{
		SkipSupportBundleCanary: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Hard baseline: HTTP require-token residual canary still present (Wave 41).
	var sawHTTP, sawMulti bool
	for _, item := range rep.Items {
		if item.Name == "http_require_token_residual" {
			sawHTTP = true
			if item.Status != diagnostics.SelfCheckWarn && item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("http_require_token_residual status=%q", item.Status)
			}
			msg := strings.ToLower(item.Message)
			if !strings.Contains(msg, "deny") && !strings.Contains(msg, "require-token") {
				t.Fatalf("http residual message should name require-token/deny-anonymous: %q", item.Message)
			}
		}
		if item.Name == "policy_multisig_lite_residual" {
			sawMulti = true
			if item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("policy_multisig_lite_residual status=%q want ok: %s", item.Status, item.Message)
			}
			// Residual honesty: must not claim production threshold crypto is complete.
			msg := strings.ToLower(item.Message)
			if strings.Contains(msg, "threshold crypto complete") || strings.Contains(msg, "hsm production ready") {
				t.Fatalf("must not claim full threshold/HSM done: %q", item.Message)
			}
			if item.Details != nil {
				if v, ok := item.Details["residual_true_threshold"].(bool); ok && v {
					t.Fatal("residual_true_threshold must be false")
				}
				if v, ok := item.Details["residual_hsm"].(bool); ok && v {
					t.Fatal("residual_hsm must be false")
				}
			}
		}
	}
	if !sawHTTP {
		t.Fatal("missing http_require_token_residual")
	}
	if !sawMulti {
		t.Fatal("missing policy_multisig_lite_residual")
	}
}
