package tools_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mockTraceExporter records export attempts for tools-layer tests.
type mockTraceExporter struct {
	calls     atomic.Int32
	last      tools.TraceExportRequest
	status    string
	backend   string
	err       error
	residuals []string
}

func (m *mockTraceExporter) ExportTraceRefs(ctx context.Context, req tools.TraceExportRequest) (tools.TraceExportResult, error) {
	m.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return tools.TraceExportResult{}, err
	}
	m.last = req
	if m.err != nil {
		return tools.TraceExportResult{}, m.err
	}
	status := m.status
	if status == "" {
		status = "recorded"
	}
	backend := m.backend
	if backend == "" {
		backend = "mock"
	}
	res := tools.TraceExportResult{
		Status:         status,
		Backend:        backend,
		Accepted:       len(req.Envelopes),
		Attempted:      len(req.Envelopes),
		EvidenceSource: "otel_export_stub",
		Residuals:      m.residuals,
		Message:        "mock export",
	}
	if res.Residuals == nil {
		res.Residuals = []string{"real OTLP residual"}
	}
	return res, nil
}

// exportTraceJenkinsFixture serves build API with params and configurable status.
type exportTraceJenkinsFixture struct {
	srv        *httptest.Server
	statusCode int
	params     []map[string]any
	hits       atomic.Int32
}

func newExportTraceJenkinsFixture(statusCode int, params []map[string]any) *exportTraceJenkinsFixture {
	f := &exportTraceJenkinsFixture{statusCode: statusCode, params: params}
	if f.statusCode == 0 {
		f.statusCode = http.StatusOK
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/json") && strings.Contains(r.URL.Path, "/job/") {
			f.hits.Add(1)
			if f.statusCode != http.StatusOK {
				w.WriteHeader(f.statusCode)
				_, _ = w.Write([]byte(http.StatusText(f.statusCode)))
				return
			}
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

func (f *exportTraceJenkinsFixture) close() { f.srv.Close() }

func (f *exportTraceJenkinsFixture) client() *jenkins.Client {
	return &jenkins.Client{
		URL:        f.srv.URL,
		User:       "u",
		Token:      "t",
		Client:     f.srv.Client(),
		LogsClient: f.srv.Client(),
	}
}

func TestExportTraceRefs_DisabledByDefault(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	names := listToolNames(t, ctx, nil)
	if _, ok := names[tools.ToolExportTraceRefs]; ok {
		t.Fatalf("%s registered when TraceExporter=nil", tools.ToolExportTraceRefs)
	}
}

func TestExportTraceRefs_EnabledRegistersTool(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	names := listToolNames(t, ctx, &tools.RegisterOptions{
		TraceExporter: &mockTraceExporter{},
	})
	if _, ok := names[tools.ToolExportTraceRefs]; !ok {
		t.Fatalf("%s not registered", tools.ToolExportTraceRefs)
	}
}

func TestExportTraceRefs_ExportsAllowlistedOnly_SecretCanary(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// ghp_ body must be long enough for built-in detector (SEC-002).
	secret := "ghp_" + strings.Repeat("A", 36)
	f := newExportTraceJenkinsFixture(http.StatusOK, []map[string]any{
		{"name": "TRACEPARENT", "value": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		{"name": "API_TOKEN", "value": secret},
		{"name": "PASSWORD", "value": "super-secret-password-value"},
		{"name": "BRANCH", "value": "main"},
	})
	defer f.close()
	mock := &mockTraceExporter{}
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{TraceExporter: mock})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolExportTraceRefs,
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
	if strings.Contains(s, secret) {
		t.Fatal("secret canary leaked into export tool response")
	}
	if strings.Contains(s, "super-secret-password") {
		t.Fatal("password value leaked into export tool response")
	}
	if strings.Contains(strings.ToLower(s), "console") || strings.Contains(s, "log_text") {
		t.Fatal("log-like fields must not appear")
	}
	if !strings.Contains(s, "4bf92f3577b34da6a3ce929d0e0e4736") {
		t.Fatalf("expected trace id in response: %s", s)
	}
	if !strings.Contains(s, "residual") {
		t.Fatalf("expected residual: %s", s)
	}
	if mock.calls.Load() != 1 {
		t.Fatalf("exporter calls=%d want 1", mock.calls.Load())
	}
	// Exporter must only see allowlisted envelope fields (no token values).
	for _, env := range mock.last.Envelopes {
		if strings.Contains(env.TraceID, secret) || strings.Contains(env.Service, secret) {
			t.Fatalf("secret in export request: %+v", env)
		}
		if env.Job != "demo" || env.Build != 7 {
			t.Fatalf("identity=%+v", env)
		}
	}
	if len(mock.last.Envelopes) == 0 {
		t.Fatal("expected at least one envelope from TRACEPARENT")
	}
}

// Regression: Jenkins 403 must fail closed — exporter never called.
func TestExportTraceRefs_Jenkins403_NoExporter(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := newExportTraceJenkinsFixture(http.StatusForbidden, nil)
	defer f.close()
	mock := &mockTraceExporter{}
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{TraceExporter: mock})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolExportTraceRefs,
		Arguments: map[string]any{
			"job_name":     "secret-job",
			"build_number": 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if mock.calls.Load() != 0 {
		t.Fatalf("Regression: exporter called on Jenkins 403 (calls=%d)", mock.calls.Load())
	}
	text := toolErrorText(res)
	if !res.IsError && !strings.Contains(text, string(apperr.CodeAuthorization)) &&
		!strings.Contains(strings.ToLower(text), "403") &&
		!strings.Contains(strings.ToLower(text), "authoriz") &&
		!strings.Contains(strings.ToLower(text), "forbidden") {
		raw, _ := json.Marshal(res)
		if !strings.Contains(string(raw), string(apperr.CodeAuthorization)) &&
			!strings.Contains(string(raw), "403") {
			t.Fatalf("expected authorization-style error on 403, isError=%v text=%q raw=%s",
				res.IsError, text, raw)
		}
	}
}

func TestExportTraceRefs_KnownSeedTool(t *testing.T) {
	t.Parallel()
	if !policy.IsKnownSeedTool(tools.ToolExportTraceRefs) {
		t.Fatalf("%s must be in knownSeedTools for RBAC", tools.ToolExportTraceRefs)
	}
}

func TestExportTraceRefs_EmptyWhenNoRefs(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := newExportTraceJenkinsFixture(http.StatusOK, []map[string]any{
		{"name": "BRANCH", "value": "main"},
	})
	defer f.close()
	mock := &mockTraceExporter{}
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{TraceExporter: mock})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolExportTraceRefs,
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
	if mock.calls.Load() != 1 {
		t.Fatalf("exporter should still be called with empty envelopes: calls=%d", mock.calls.Load())
	}
	if len(mock.last.Envelopes) != 0 {
		t.Fatalf("envelopes=%+v", mock.last.Envelopes)
	}
	payload := toolStructuredJSON(t, res)
	raw, _ := json.Marshal(payload)
	if !strings.Contains(string(raw), "residual") {
		t.Fatalf("expected residual: %s", raw)
	}
}
