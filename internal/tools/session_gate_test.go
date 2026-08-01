package tools_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

const sessionGateCanary = "SESSION_GATE_CANARY_token_must_not_appear_xyz"

// emptyArgs is a schema-safe tool input for gate tests (jsonschema requires struct).
type emptyArgs struct{}

type gateOut struct {
	OK bool `json:"ok"`
}

// Regression: revoked SessionGuard blocks tools even if the Jenkins client still
// holds a secret (fail closed before handler / network).
func TestAuthGate_RevokedBlocksTools(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	guard := auth.NewSessionGuard("fp-revoked")
	if err := guard.Check(); err != nil {
		t.Fatal(err)
	}
	guard.MarkRevoked()

	// Client still has a secret — must not be used when gate fails.
	client := &jenkins.Client{
		URL:        "http://127.0.0.1:9",
		Token:      sessionGateCanary,
		AuthScheme: jenkins.AuthSchemeBearer,
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "gate-revoked", Version: "test"}, nil)
	tools.Register(server, client, &tools.RegisterOptions{
		Gate:     policy.NewDefaultReadOnlyGate(),
		AuthGate: guard,
	})

	// Force a simple read tool dispatch via ForceRegister so we don't depend on
	// full seed inventory; production path is the same addTool middleware.
	tools.ForceRegisterReadToolForTest(server, &tools.RegisterOptions{
		Gate:     policy.NewDefaultReadOnlyGate(),
		AuthGate: guard,
	}, &mcp.Tool{
		Name:        "test_session_gate_ping",
		Description: "test only",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args emptyArgs) (*mcp.CallToolResult, gateOut, error) {
		t.Fatal("handler must not run when guard is revoked")
		return structuredGateOK()
	})

	cs := connectToolClient(t, ctx, server)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "test_session_gate_ping",
		Arguments: map[string]any{},
	})
	if err != nil {
		// Transport-level error is also acceptable if error text is secret-free.
		if strings.Contains(err.Error(), sessionGateCanary) {
			t.Fatalf("canary in transport error: %v", err)
		}
		return
	}
	if res == nil || !res.IsError {
		t.Fatalf("want tool error, got %#v", res)
	}
	text := toolErrorText(res)
	if strings.Contains(text, sessionGateCanary) {
		t.Fatalf("canary in tool error: %q", text)
	}
	if !strings.Contains(strings.ToLower(text), "revok") &&
		!strings.Contains(text, string(apperr.CodeAuthentication)) &&
		!strings.Contains(strings.ToLower(text), "re-authenticate") &&
		!strings.Contains(strings.ToLower(text), "session") {
		t.Fatalf("unexpected denial text: %q", text)
	}
}

// Regression: refresh-failed guard blocks subsequent tool calls.
func TestAuthGate_RefreshFailedBlocksTools(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	guard := auth.NewSessionGuard("fp-refresh")
	guard.MarkRefreshFailed()

	server := mcp.NewServer(&mcp.Implementation{Name: "gate-refresh", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, &tools.RegisterOptions{
		Gate:     policy.NewDefaultReadOnlyGate(),
		AuthGate: guard,
	}, &mcp.Tool{Name: "test_refresh_gate", Description: "test"},
		func(ctx context.Context, req *mcp.CallToolRequest, args emptyArgs) (*mcp.CallToolResult, gateOut, error) {
			t.Fatal("handler must not run")
			return structuredGateOK()
		})

	cs := connectToolClient(t, ctx, server)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_refresh_gate", Arguments: map[string]any{}})
	if err != nil {
		if strings.Contains(err.Error(), sessionGateCanary) {
			t.Fatal(err)
		}
		return
	}
	if res == nil || !res.IsError {
		t.Fatalf("want error %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(strings.ToLower(text), "refresh") &&
		!strings.Contains(text, string(apperr.CodeAuthentication)) {
		t.Fatalf("expected refresh failure text: %q", text)
	}
	if strings.Contains(text, sessionGateCanary) {
		t.Fatalf("canary: %q", text)
	}
}

// Usable guard allows handler to run.
func TestAuthGate_AllowsWhenUsable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	guard := auth.NewSessionGuard("fp-ok")
	var ran bool
	server := mcp.NewServer(&mcp.Implementation{Name: "gate-ok", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, &tools.RegisterOptions{
		Gate:     policy.NewDefaultReadOnlyGate(),
		AuthGate: guard,
	}, &mcp.Tool{Name: "test_gate_ok", Description: "test"},
		func(ctx context.Context, req *mcp.CallToolRequest, args emptyArgs) (*mcp.CallToolResult, gateOut, error) {
			ran = true
			return structuredGateOK()
		})

	cs := connectToolClient(t, ctx, server)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_gate_ok", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil && res.IsError {
		t.Fatalf("unexpected tool error: %s", toolErrorText(res))
	}
	if !ran {
		t.Fatal("handler did not run")
	}
}

func structuredGateOK() (*mcp.CallToolResult, gateOut, error) {
	return &mcp.CallToolResult{}, gateOut{OK: true}, nil
}

func connectToolClient(t *testing.T, ctx context.Context, server *mcp.Server) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}
