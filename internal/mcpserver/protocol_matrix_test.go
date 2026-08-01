package mcpserver_test

import (
	"context"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
)

// FND-006 Wave 20: offline protocol matrix for Streamable HTTP (loopback RunHTTP).
// No Cursor binary, Docker, or live Jenkins. Prefer stdio for pilot (ADR 0002).
// Residual: Cursor host stdio lifecycle CI remains open.

func TestProtocolMatrix_HTTPInitializeListTools(t *testing.T) {
	t.Parallel()

	// Bind ephemeral loopback; RunHTTP enforces ValidateHTTPConfig.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	const serverName = "mcpserver-http-matrix"
	srv := mcpserver.NewServer(serverName, "test")
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "matrix_ping",
		Description: "protocol-matrix HTTP probe (test-only)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{}, map[string]any{"ok": true}, nil
	})

	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = addr
	cfg.ShutdownTimeout = 2 * time.Second
	// Silence start/stop logs in unit CI.
	cfg.Logger = log.New(io.Discard, "", 0)

	serveCtx, serveCancel := context.WithCancel(context.Background())
	defer serveCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- mcpserver.RunHTTP(serveCtx, srv, cfg)
	}()

	// Wait until the port accepts connections (fast poll; no multi-second sleep).
	deadline := time.Now().Add(2 * time.Second)
	var dialErr error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			dialErr = nil
			break
		}
		dialErr = err
		time.Sleep(10 * time.Millisecond)
	}
	if dialErr != nil {
		t.Fatalf("RunHTTP never became ready on %s: %v", addr, dialErr)
	}

	endpoint := "http://" + addr
	client := mcp.NewClient(&mcp.Implementation{Name: "http-matrix-client", Version: "test"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint}, nil)
	if err != nil {
		t.Fatalf("StreamableClientTransport Connect: %v", err)
	}

	initRes := cs.InitializeResult()
	if initRes == nil {
		t.Fatal("InitializeResult is nil over HTTP")
	}
	if initRes.ProtocolVersion == "" {
		t.Fatal("HTTP negotiated protocol version is empty")
	}
	// Declared set matches ADR 0006 / go-sdk v1.1.0.
	switch initRes.ProtocolVersion {
	case "2025-06-18", "2025-03-26", "2024-11-05":
	default:
		t.Fatalf("unexpected protocol version %q", initRes.ProtocolVersion)
	}
	if initRes.ServerInfo == nil || initRes.ServerInfo.Name != serverName {
		t.Fatalf("ServerInfo = %#v, want Name=%q", initRes.ServerInfo, serverName)
	}

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools over HTTP: %v", err)
	}
	found := false
	for _, tool := range list.Tools {
		if tool != nil && tool.Name == "matrix_ping" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("matrix_ping not listed over HTTP")
	}

	// Drop client session before server shutdown so graceful close is prompt.
	_ = cs.Close()

	// Clean shutdown: cancel RunHTTP and ensure it exits.
	serveCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunHTTP after cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunHTTP did not exit after context cancel")
	}
}
