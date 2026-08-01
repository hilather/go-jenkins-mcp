package tools_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// TestMCPToolRejectsAbsoluteJobURL is the MCP-002 wire check: model-constructed
// http(s) job URLs must fail closed with invalid_argument before any Jenkins call.
func TestMCPToolRejectsAbsoluteJobURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "typed-ref", Version: "test"}, nil)
	// Client is unused when validation fails first; empty URL would fail if called.
	tools.Register(server, &jenkins.Client{}, nil)

	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	cases := []struct {
		tool string
		args map[string]any
	}{
		{"jenkins_get_job", map[string]any{"name": "http://jenkins.example/job/x"}},
		{"jenkins_get_build", map[string]any{"job_name": "https://jenkins.example/job/x", "build_number": 1}},
		{"jenkins_get_build_logs", map[string]any{"job_name": "http://evil/job/x", "build_number": 1, "offset": 0, "length": 100}},
		{"jenkins_get_build_log_tail", map[string]any{"job_name": "//evil/job/x", "build_number": 1}},
		{"jenkins_search_builds", map[string]any{"job_name": "https://jenkins/job/folder/job/x"}},
		{"jenkins_wait_for_running_build", map[string]any{"job_name": "http://jenkins/job/x", "build_number": 2}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
			if err != nil {
				t.Fatalf("transport: %v", err)
			}
			if res == nil || !res.IsError {
				t.Fatalf("want tool error for absolute URL, got %#v", res)
			}
			text := toolErrorText(res)
			if !strings.Contains(text, string(apperr.CodeInvalidArgument)) &&
				!strings.Contains(strings.ToLower(text), "invalid") &&
				!strings.Contains(strings.ToLower(text), "url") {
				t.Fatalf("expected invalid_argument / URL rejection, got %q", text)
			}
			if !strings.Contains(text, "allowed form") && !strings.Contains(strings.ToLower(text), "url") {
				t.Fatalf("want field/allowed-form guidance: %q", text)
			}
		})
	}
}

// TestMCPToolAcceptsNestedJobPath ensures folder/job full names are not rejected
// by typed-ref validation (encoding is client-side BuildJobPath).
func TestMCPToolAcceptsNestedJobPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "typed-ref-ok", Version: "test"}, nil)
	// Will fail on Jenkins network — we only assert validation does not reject
	// the path form. Use invalid base so CallJenkins fails with non-validation code.
	tools.Register(server, &jenkins.Client{URL: "http://127.0.0.1:1"}, nil)

	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_build",
		Arguments: map[string]any{"job_name": "folder/sub/job", "build_number": 3},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	// Expect upstream/network failure, not invalid_argument about job_name URL.
	text := toolErrorText(res)
	if strings.Contains(text, "absolute or scheme URL") {
		t.Fatalf("nested path must not be treated as URL: %q", text)
	}
	if strings.Contains(text, "missing or empty") {
		t.Fatalf("nested path rejected as empty: %q", text)
	}
}

// TestMCPQueueItemRequiresPositiveID covers queue_id typed ref validation.
func TestMCPQueueItemRequiresPositiveID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "queue-ref", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, nil)

	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_queue_item",
		Arguments: map[string]any{"queue_id": 0},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want error for queue_id=0, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(text, "queue_id") {
		t.Fatalf("want queue_id field: %q", text)
	}
}
