package tools_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// FND-006: seed-tool registration path + CallTool cancel reaches handler context.
// Uses a custom slow tool on the same server as Register for inventory smoke.

func TestMCP_ListToolsAndCancelSlowTool(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcpserver.NewServer("tools-cancel-smoke", "test")
	// Read-only seed inventory (no Jenkins I/O for ListTools).
	tools.Register(server, &jenkins.Client{}, nil)

	started := make(chan struct{}, 1)
	var sawCancel atomic.Bool
	var handlerDone sync.WaitGroup
	handlerDone.Add(1)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "test_slow_cancel",
		Description: "test-only cancel probe",
	}, func(toolCtx context.Context, req *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		defer handlerDone.Done()
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-time.After(5 * time.Second):
			return &mcp.CallToolResult{}, map[string]any{"ok": true}, nil
		case <-toolCtx.Done():
			sawCancel.Store(true)
			return nil, nil, toolCtx.Err()
		}
	})

	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil)
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

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if list == nil || len(list.Tools) == 0 {
		t.Fatal("no tools listed")
	}
	// Seed inventory present + cancel probe.
	names := make(map[string]struct{}, len(list.Tools))
	for _, tool := range list.Tools {
		if tool != nil {
			names[tool.Name] = struct{}{}
		}
	}
	if _, ok := names["jenkins_get_jobs"]; !ok {
		t.Fatal("missing seed tool jenkins_get_jobs")
	}
	if _, ok := names["test_slow_cancel"]; !ok {
		t.Fatal("missing test_slow_cancel")
	}

	callCtx, callCancel := context.WithCancel(context.Background())
	var callWG sync.WaitGroup
	var callErr error
	callWG.Add(1)
	go func() {
		defer callWG.Done()
		_, callErr = cs.CallTool(callCtx, &mcp.CallToolParams{Name: "test_slow_cancel"})
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		callCancel()
		t.Fatal("slow tool never started")
	}
	callCancel()
	callWG.Wait()
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
		t.Fatal("expected cancel error from CallTool")
	}
	if !errors.Is(callErr, context.Canceled) &&
		!strings.Contains(strings.ToLower(callErr.Error()), "cancel") {
		t.Fatalf("err = %v", callErr)
	}
	if !sawCancel.Load() {
		t.Fatal("registered tool handler did not see cancelled context")
	}
}
