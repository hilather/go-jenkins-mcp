package mcpserver_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/mcpserver"
)

// FND-006 residual: prove tool-handler contexts are cancelled when the client
// cancels CallTool (in-memory session; no Cursor host / live Jenkins).

func TestCallTool_SlowHandlerObservesCancel(t *testing.T) {
	t.Parallel()

	server := mcpserver.NewServer("cancel-smoke", "test")
	started := make(chan struct{}, 1)
	var serverSawCancel atomic.Bool
	var handlerDone sync.WaitGroup
	handlerDone.Add(1)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "slow_cancel_probe",
		Description: "blocks until cancelled (test-only)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		defer handlerDone.Done()
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-time.After(5 * time.Second):
			return &mcp.CallToolResult{}, map[string]any{"status": "done"}, nil
		case <-ctx.Done():
			serverSawCancel.Store(true)
			return nil, nil, ctx.Err()
		}
	})

	client := mcp.NewClient(&mcp.Implementation{Name: "cancel-client", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatalf("server Connect: %v", err)
	}
	defer ss.Close()
	cs, err := client.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatalf("client Connect: %v", err)
	}
	defer cs.Close()

	// Discovery still works on a healthy session.
	listCtx, listCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer listCancel()
	list, err := cs.ListTools(listCtx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	found := false
	for _, tool := range list.Tools {
		if tool != nil && tool.Name == "slow_cancel_probe" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("slow_cancel_probe not listed")
	}

	callCtx, callCancel := context.WithCancel(context.Background())
	var callWG sync.WaitGroup
	var callErr error
	callWG.Add(1)
	go func() {
		defer callWG.Done()
		_, callErr = cs.CallTool(callCtx, &mcp.CallToolParams{Name: "slow_cancel_probe"})
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		callCancel()
		t.Fatal("tool handler never started")
	}
	callCancel()
	callWG.Wait()
	// CallTool may return before the server handler records cancel; wait for handler exit.
	done := make(chan struct{})
	go func() {
		handlerDone.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("tool handler did not finish after cancel")
	}

	if callErr == nil {
		t.Fatal("expected CallTool error after cancel")
	}
	if !errors.Is(callErr, context.Canceled) &&
		!strings.Contains(strings.ToLower(callErr.Error()), "cancel") {
		t.Fatalf("client err = %v, want cancel-related", callErr)
	}
	if !serverSawCancel.Load() {
		t.Fatal("tool handler did not observe ctx cancellation (FND-006)")
	}
}

// TestRunHTTP_CancelShutsDown is a focused residual for graceful cancel of the
// HTTP serve path (loopback bind already covered in http_test).
func TestRunHTTP_CancelShutsDown(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := mcpserver.NewServer("http-cancel", "test")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = addr
	cfg.ShutdownTimeout = 2 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- mcpserver.RunHTTP(ctx, srv, cfg)
	}()

	// Wait until the port accepts connections.
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
		cancel()
		t.Fatalf("server never became ready: %v", dialErr)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunHTTP after cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunHTTP did not exit after context cancel")
	}
}
