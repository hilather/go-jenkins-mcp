package tools_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// traceRefsFixture serves build JSON with optional parameters for INT-002 tests.
type traceRefsFixture struct {
	srv    *httptest.Server
	params []map[string]any
}

func newTraceRefsFixture(params []map[string]any) *traceRefsFixture {
	f := &traceRefsFixture{params: params}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/logText/progressiveText") {
			w.Header().Set("X-Text-Size", "20")
			_, _ = w.Write([]byte("BUILD FAILURE\n"))
			return
		}
		if strings.Contains(r.URL.Path, "/api/json") && strings.Contains(r.URL.Path, "/job/") {
			actions := []map[string]any{}
			if len(f.params) > 0 {
				actions = append(actions, map[string]any{
					"_class":     "hudson.model.ParametersAction",
					"parameters": f.params,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"number":      7,
				"url":         "http://example/job/demo/7/",
				"building":    false,
				"result":      "FAILURE",
				"timestamp":   1_700_000_000_000,
				"duration":    1000,
				"displayName": "#7",
				"actions":     actions,
			})
			return
		}
		http.NotFound(w, r)
	}))
	return f
}

func (f *traceRefsFixture) close() { f.srv.Close() }

func (f *traceRefsFixture) client() *jenkins.Client {
	return &jenkins.Client{
		URL:        f.srv.URL,
		User:       "u",
		Token:      "t",
		Client:     f.srv.Client(),
		LogsClient: f.srv.Client(),
	}
}

func TestTraceRefs_DisabledByDefault(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	names := listToolNames(t, ctx, nil)
	if _, ok := names[tools.ToolGetTraceRefs]; ok {
		t.Fatalf("%s registered when EnableTraceRefs=false", tools.ToolGetTraceRefs)
	}
}

func TestTraceRefs_EnabledRegistersTool(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	names := listToolNames(t, ctx, &tools.RegisterOptions{EnableTraceRefs: true})
	if _, ok := names[tools.ToolGetTraceRefs]; !ok {
		t.Fatalf("%s not registered when EnableTraceRefs=true", tools.ToolGetTraceRefs)
	}
}

func TestTraceRefs_ExtractsFromBuildParams(t *testing.T) {
	t.Parallel()
	f := newTraceRefsFixture([]map[string]any{
		{"name": "TRACEPARENT", "value": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		{"name": "API_TOKEN", "value": "super-secret-token-value"},
		{"name": "BRANCH", "value": "main"},
	})
	defer f.close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{EnableTraceRefs: true})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolGetTraceRefs,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	raw, _ := json.Marshal(payload)
	s := string(raw)
	if !strings.Contains(s, "4bf92f3577b34da6a3ce929d0e0e4736") {
		t.Fatalf("missing trace id in %s", s)
	}
	if !strings.Contains(s, "jenkins_build_metadata") {
		t.Fatalf("missing evidence source in %s", s)
	}
	if strings.Contains(s, "super-secret-token-value") {
		t.Fatal("secret leaked into tool response")
	}
	// Residuals must label OTLP backend residual.
	residuals, _ := payload["residuals"].([]any)
	if len(residuals) == 0 {
		t.Fatalf("want residuals, got %s", s)
	}
	if payload["freshness"] != "live" {
		t.Fatalf("freshness=%v", payload["freshness"])
	}
}

func TestTraceRefs_NoRefsMessage(t *testing.T) {
	t.Parallel()
	f := newTraceRefsFixture([]map[string]any{
		{"name": "BRANCH", "value": "main"},
	})
	defer f.close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{EnableTraceRefs: true})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolGetTraceRefs,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := toolStructuredJSON(t, res)
	msg, _ := payload["message"].(string)
	if !strings.Contains(msg, "no recognized") {
		t.Fatalf("want empty-message, got %+v", payload)
	}
	if n, _ := payload["count"].(float64); n != 0 {
		t.Fatalf("count=%v", payload["count"])
	}
}

func TestDiagnose_TraceRefsEnrichmentWhenEnabled(t *testing.T) {
	t.Parallel()
	f := newTraceRefsFixture([]map[string]any{
		{"name": "OTEL_TRACE_ID", "value": "4bf92f3577b34da6a3ce929d0e0e4736"},
		{"name": "OTEL_SPAN_ID", "value": "00f067aa0ba902b7"},
		{"name": "SERVICE_NAME", "value": "checkout"},
	})
	defer f.close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{EnableTraceRefs: true})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	raw, _ := json.Marshal(payload)
	s := string(raw)
	if !strings.Contains(s, "4bf92f3577b34da6a3ce929d0e0e4736") {
		t.Fatalf("diagnose missing trace_refs: %s", s)
	}
	if !strings.Contains(s, "checkout") {
		t.Fatalf("diagnose missing service: %s", s)
	}
	refs, ok := payload["trace_refs"].([]any)
	if !ok || len(refs) == 0 {
		t.Fatalf("trace_refs missing: %s", s)
	}
}

func TestDiagnose_NoTraceRefsWhenDisabled(t *testing.T) {
	t.Parallel()
	f := newTraceRefsFixture([]map[string]any{
		{"name": "TRACEPARENT", "value": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
	})
	defer f.close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	// EnableTraceRefs false (default)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := toolStructuredJSON(t, res)
	if _, ok := payload["trace_refs"]; ok {
		t.Fatalf("unexpected trace_refs when disabled: %+v", payload["trace_refs"])
	}
}
