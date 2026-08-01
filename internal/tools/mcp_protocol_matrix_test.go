package tools_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// FND-006 Wave 20: offline MCP protocol matrix (in-memory transport).
// Does not require Cursor binary, Docker, or live Jenkins.
// Residual: Cursor host stdio lifecycle CI (see ADR 0006, packaging.md).

const matrixServerName = "jenkins-mcp-protocol-matrix"

// declaredProtocolVersions lives in mcp_smoke_test.go (same package tools_test).

func TestMCPProtocolMatrix_Initialize(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcpserver.NewServer(matrixServerName, "test")
	tools.Register(server, &jenkins.Client{}, nil)

	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	initRes := cs.InitializeResult()
	if initRes == nil {
		t.Fatal("InitializeResult is nil")
	}
	if initRes.ProtocolVersion == "" {
		t.Fatal("negotiated protocol version is empty")
	}
	if _, ok := declaredProtocolVersions[initRes.ProtocolVersion]; !ok {
		t.Fatalf("protocol version %q not in declared set %v",
			initRes.ProtocolVersion, mapsKeys(declaredProtocolVersions))
	}
	if initRes.ServerInfo == nil || initRes.ServerInfo.Name == "" {
		t.Fatal("ServerInfo.Name is empty")
	}
	if initRes.ServerInfo.Name != matrixServerName {
		t.Fatalf("ServerInfo.Name = %q, want %q", initRes.ServerInfo.Name, matrixServerName)
	}
}

func TestMCPProtocolMatrix_ListToolsReadOnly(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcpserver.NewServer(matrixServerName, "test")
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(),
		Doctor: func(ctx context.Context, offline bool) (diagnostics.Report, error) {
			return diagnostics.Report{Overall: diagnostics.StatusOK}, nil
		},
	})

	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if list == nil || len(list.Tools) == 0 {
		t.Fatal("ListTools returned no tools")
	}
	got := make(map[string]struct{}, len(list.Tools))
	for _, tool := range list.Tools {
		if tool == nil || tool.Name == "" {
			t.Fatalf("tool entry missing name: %#v", tool)
		}
		got[tool.Name] = struct{}{}
	}

	// Sample of seed read tools must be present under RO.
	for _, name := range []string{
		"jenkins_get_jobs",
		"jenkins_get_job",
		"jenkins_get_build",
		"jenkins_get_nodes",
		"jenkins_get_node",
		"jenkins_list_views",
		"jenkins_doctor",
	} {
		if _, ok := got[name]; !ok {
			t.Errorf("missing read tool %q under RO", name)
		}
	}
	for _, name := range policy.MutationToolNames() {
		if _, ok := got[name]; ok {
			t.Errorf("mutation tool %q must be absent under RO", name)
		}
	}
}

func TestMCPProtocolMatrix_CallToolGetJobs(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const canary = "CANARY_SECRET_token_matrix_xyz"
	fix := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/json" || strings.HasPrefix(r.URL.Path, "/api/json") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jobs": []map[string]any{
					{
						"name":      "demo",
						"url":       "http://example/job/demo/",
						"color":     "blue",
						"buildable": true,
					},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer fix.Close()

	jc := &jenkins.Client{
		URL:        fix.URL,
		User:       "matrix-user",
		Token:      canary,
		Client:     fix.Client(),
		LogsClient: fix.Client(),
	}

	server := mcpserver.NewServer(matrixServerName, "test")
	tools.Register(server, jc, &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(),
	})

	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_jobs",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool transport: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("jenkins_get_jobs failed: %#v text=%q", res, toolErrorText(res))
	}
	payload := toolStructuredJSON(t, res)
	// Job list may appear as jobList (struct) or nested; accept either shape.
	raw, _ := json.Marshal(payload)
	if !strings.Contains(string(raw), "demo") {
		t.Fatalf("expected demo job in response, got %s", raw)
	}
	if strings.Contains(string(raw), canary) {
		t.Fatalf("token canary leaked in tool result: %s", raw)
	}
}

func TestMCPProtocolMatrix_CallToolInvalidArgs(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const canary = "CANARY_SECRET_token_invalid_args"
	// Client must not be dialed: validation fails first.
	jc := &jenkins.Client{
		URL:   "http://127.0.0.1:1",
		User:  "u",
		Token: canary,
	}
	server := mcpserver.NewServer(matrixServerName, "test")
	tools.Register(server, jc, nil)

	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	// Typed-ref invalid_argument: absolute job URL rejected before Jenkins I/O.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_get_job",
		Arguments: map[string]any{
			"name": "https://jenkins.example/job/x?token=" + canary,
		},
	})
	if err != nil {
		t.Fatalf("CallTool transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want tool error for invalid job URL, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(text, string(apperr.CodeInvalidArgument)) &&
		!strings.Contains(strings.ToLower(text), "invalid") {
		t.Fatalf("expected invalid_argument, got %q", text)
	}
	// Fail closed: no panic path; secrets must not appear in model-visible text.
	if strings.Contains(text, canary) {
		t.Fatalf("secret canary leaked in error message: %q", text)
	}
	if strings.Contains(text, "Bearer ") || strings.Contains(text, "api_token") {
		t.Fatalf("credential-shaped leak in error: %q", text)
	}

	// Second stable invalid_argument: queue_id must be positive.
	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_queue_item",
		Arguments: map[string]any{"queue_id": 0},
	})
	if err != nil {
		t.Fatalf("queue CallTool transport: %v", err)
	}
	if res2 == nil || !res2.IsError {
		t.Fatalf("want error for queue_id=0, got %#v", res2)
	}
	text2 := toolErrorText(res2)
	if !strings.Contains(text2, "queue_id") &&
		!strings.Contains(text2, string(apperr.CodeInvalidArgument)) {
		t.Fatalf("expected queue_id / invalid_argument, got %q", text2)
	}
	if strings.Contains(text2, canary) {
		t.Fatalf("canary in queue error: %q", text2)
	}
}

func TestMCPProtocolMatrix_CallToolUnknown(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcpserver.NewServer(matrixServerName, "test")
	tools.Register(server, &jenkins.Client{}, nil)

	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	// SDK fail-closed: unknown tool → transport/RPC error (not a success result).
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_definitely_not_a_tool",
		Arguments: map[string]any{},
	})
	if err == nil {
		if res != nil && res.IsError {
			// Accept tool-error shape if SDK maps it that way in a future pin.
			text := toolErrorText(res)
			if !strings.Contains(strings.ToLower(text), "unknown") {
				t.Fatalf("tool error without unknown marker: %q", text)
			}
			return
		}
		t.Fatalf("unknown tool must fail closed, got res=%#v err=nil", res)
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "unknown") && !strings.Contains(low, "not found") &&
		!strings.Contains(low, "invalid") {
		t.Fatalf("unknown tool err = %v, want fail-closed marker", err)
	}
}

func TestMCPProtocolMatrix_CallToolCancel(t *testing.T) {
	t.Parallel()
	// Reuse cancel pattern: mid CallTool cancel reaches handler context (FND-006).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcpserver.NewServer(matrixServerName+"-cancel", "test")
	tools.Register(server, &jenkins.Client{}, nil)

	started := make(chan struct{}, 1)
	var sawCancel atomic.Bool
	var handlerDone sync.WaitGroup
	handlerDone.Add(1)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "matrix_slow_cancel",
		Description: "protocol-matrix cancel probe (test-only)",
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

	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	callCtx, callCancel := context.WithCancel(context.Background())
	var callWG sync.WaitGroup
	var callErr error
	callWG.Add(1)
	go func() {
		defer callWG.Done()
		_, callErr = cs.CallTool(callCtx, &mcp.CallToolParams{Name: "matrix_slow_cancel"})
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
		t.Fatal("handler did not finish after cancel")
	}

	if callErr == nil {
		t.Fatal("expected cancel error from CallTool")
	}
	if !errors.Is(callErr, context.Canceled) &&
		!strings.Contains(strings.ToLower(callErr.Error()), "cancel") {
		t.Fatalf("err = %v", callErr)
	}
	if !sawCancel.Load() {
		t.Fatal("handler did not observe cancelled context")
	}
}
