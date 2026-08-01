package mcpserver_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
)

// TestRunStdio_CancelledContextDoesNotHang ensures RunStdio returns promptly
// when the context is already cancelled (no real Cursor host; avoids hanging CI).
func TestRunStdio_CancelledContextDoesNotHang(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("stdio-smoke", "test")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done

	done := make(chan error, 1)
	go func() {
		done <- mcpserver.RunStdioWith(ctx, srv, mcpserver.StdioOptions{LogWriter: io.Discard})
	}()

	select {
	case err := <-done:
		// Cancelled before/during connect → nil (clean) or wrapped error; must return.
		_ = err
	case <-time.After(3 * time.Second):
		t.Fatal("RunStdio hung with cancelled context")
	}
}

func TestRunStdio_NilServer(t *testing.T) {
	t.Parallel()
	err := mcpserver.RunStdio(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil server")
	}
}

// TestNewServerInMemorySmoke mirrors tools package FND-006 pattern: construct
// server via mcpserver.NewServer and complete initialize over in-memory transport.
func TestNewServerInMemorySmoke(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server := mcpserver.NewServer("mcpserver-smoke", "test")
	client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer ss.Close()
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client Connect: %v", err)
	}
	defer cs.Close()
	if cs.InitializeResult() == nil || cs.InitializeResult().ProtocolVersion == "" {
		t.Fatal("missing negotiated protocol version")
	}
}
