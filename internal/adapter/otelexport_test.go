package adapter_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/adapter"
)

func TestOtelExport_DisabledByDefault(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	if r.Get(adapter.IDOtelExport) != nil {
		t.Fatal("otel-export must not register by default")
	}
}

func TestOtelExport_EnableNoop_NoNetwork(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{
		EnabledIDs: []string{adapter.IDOtelExport},
	})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := r.StartAll(ctx); err != nil {
		t.Fatal(err)
	}
	h := r.Health(ctx, adapter.IDOtelExport)
	if h.Status != adapter.HealthHealthy {
		t.Fatalf("health=%+v", h)
	}
	entry := r.Get(adapter.IDOtelExport)
	if entry == nil {
		t.Fatal("missing")
	}
	// CapOtelExport present
	var saw bool
	for _, c := range entry.Capabilities {
		if c == adapter.CapOtelExport {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("want CapOtelExport, got %v", entry.Capabilities)
	}
	exp, ok := entry.Adapter.(adapter.TraceExporter)
	if !ok {
		t.Fatalf("type %T", entry.Adapter)
	}
	res, err := exp.ExportTraceRefs(ctx, adapter.TraceExportRequest{
		Job:   "demo",
		Build: 1,
		Envelopes: []adapter.TraceExportEnvelope{
			{TraceID: "0123456789abcdef0123456789abcdef", Job: "demo", Build: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "noop" || res.Backend != "noop" {
		t.Fatalf("res=%+v", res)
	}
	if res.Accepted != 1 {
		t.Fatalf("accepted=%d", res.Accepted)
	}
	if res.EvidenceSource != adapter.EvidenceSourceOtelExport {
		t.Fatalf("evidence=%s", res.EvidenceSource)
	}
	found := false
	for _, r := range res.Residuals {
		if strings.Contains(r, "residual") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected OTLP residual: %+v", res.Residuals)
	}
	// noop records nothing
	if oe, ok := entry.Adapter.(*adapter.OtelExport); ok {
		if n := len(oe.RecordedExports()); n != 0 {
			t.Fatalf("noop recorded %d", n)
		}
	}
}

func TestOtelExport_MockCountsExports(t *testing.T) {
	t.Parallel()
	a, err := adapter.NewOtelExport(adapter.Host{}, adapter.OtelExportConfig{
		Backend: adapter.OtelExportBackendMock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	oe := a.(*adapter.OtelExport)
	exp := a.(adapter.TraceExporter)

	// Invalid identity
	if _, err := exp.ExportTraceRefs(context.Background(), adapter.TraceExportRequest{}); err == nil {
		t.Fatal("expected job required")
	}
	if _, err := exp.ExportTraceRefs(context.Background(), adapter.TraceExportRequest{
		Job: "https://evil.example/job", Build: 1,
	}); err == nil {
		t.Fatal("expected URL rejection")
	}

	res, err := exp.ExportTraceRefs(context.Background(), adapter.TraceExportRequest{
		Job:   "folder/job",
		Build: 9,
		Envelopes: []adapter.TraceExportEnvelope{
			{
				TraceID: "aabbccddeeff00112233445566778899",
				SpanID:  "0011223344556677",
				Service: "checkout",
				Format:  "w3c_traceparent",
			},
			// Invalid trace id dropped; secretish service dropped
			{TraceID: "not-hex!!!", Service: "password=supersecret"},
			// Service-only ok
			{Service: "payments-api"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "recorded" || res.Backend != "mock" {
		t.Fatalf("res=%+v", res)
	}
	if res.Accepted != 2 {
		t.Fatalf("accepted=%d want 2 (hex + service-only)", res.Accepted)
	}
	attempts := oe.RecordedExports()
	if len(attempts) != 1 {
		t.Fatalf("attempts=%d", len(attempts))
	}
	if attempts[0].Job != "folder/job" || attempts[0].Build != 9 {
		t.Fatalf("attempt=%+v", attempts[0])
	}
	// Second call increments
	_, err = exp.ExportTraceRefs(context.Background(), adapter.TraceExportRequest{
		Job: "folder/job", Build: 9,
		Envelopes: []adapter.TraceExportEnvelope{
			{TraceID: "11223344556677889900aabbccddeeff"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(oe.RecordedExports()) != 2 {
		t.Fatalf("want 2 recorded, got %d", len(oe.RecordedExports()))
	}
}

func TestOtelExport_NotStarted(t *testing.T) {
	t.Parallel()
	a, err := adapter.NewOtelExport(adapter.Host{}, adapter.OtelExportConfig{
		Backend: adapter.OtelExportBackendMock,
	})
	if err != nil {
		t.Fatal(err)
	}
	exp := a.(adapter.TraceExporter)
	_, err = exp.ExportTraceRefs(context.Background(), adapter.TraceExportRequest{
		Job: "j", Build: 1,
		Envelopes: []adapter.TraceExportEnvelope{{TraceID: "aabbccddeeff00112233445566778899"}},
	})
	if err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("err=%v", err)
	}
}

func TestOtelExport_HTTPRejectsHTTPAndUserinfo(t *testing.T) {
	t.Parallel()
	_, err := adapter.NewOtelExport(adapter.Host{}, adapter.OtelExportConfig{
		Backend: adapter.OtelExportBackendHTTP,
		BaseURL: "http://example.com/export",
	})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err=%v", err)
	}
	_, err = adapter.NewOtelExport(adapter.Host{}, adapter.OtelExportConfig{
		Backend: adapter.OtelExportBackendHTTP,
		BaseURL: "https://user:pass@example.com/export",
	})
	if err == nil || !strings.Contains(err.Error(), "userinfo") {
		t.Fatalf("err=%v", err)
	}
	_, err = adapter.NewOtelExport(adapter.Host{}, adapter.OtelExportConfig{
		Backend: adapter.OtelExportBackendHTTP,
		// missing BaseURL
	})
	if err == nil || !strings.Contains(err.Error(), "BaseURL") {
		t.Fatalf("err=%v", err)
	}
}

func TestOtelExport_HTTPMetadataOnlyPayload_SecretCanary(t *testing.T) {
	t.Parallel()
	const canary = "ghp_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	var sawBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "auth not allowed", 400)
			return
		}
		var err error
		sawBody, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", 400)
			return
		}
		// Must not contain canary secret or log-like fields.
		bodyStr := string(sawBody)
		if strings.Contains(bodyStr, canary) {
			http.Error(w, "secret leaked", 400)
			return
		}
		if strings.Contains(bodyStr, "console") || strings.Contains(bodyStr, "log_text") ||
			strings.Contains(bodyStr, "parameters") {
			http.Error(w, "forbidden field", 400)
			return
		}
		var parsed map[string]any
		if err := json.Unmarshal(sawBody, &parsed); err != nil {
			http.Error(w, "json", 400)
			return
		}
		// Allowlisted top-level keys only.
		for k := range parsed {
			switch k {
			case "job", "build", "envelopes", "kind":
			default:
				http.Error(w, "unexpected key "+k, 400)
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accepted": 1,
			"message":  "ok",
		})
	}))
	defer srv.Close()

	a, err := adapter.NewOtelExport(adapter.Host{}, adapter.OtelExportConfig{
		Backend: adapter.OtelExportBackendHTTP,
		BaseURL: srv.URL + "/export",
		HTTP:    srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	exp := a.(adapter.TraceExporter)
	// Attempt to smuggle secret as service (should be scrubbed) and invalid fields
	// via envelope (struct has no log fields; adapter forces job/build identity).
	res, err := exp.ExportTraceRefs(context.Background(), adapter.TraceExportRequest{
		Job:   "demo",
		Build: 5,
		Envelopes: []adapter.TraceExportEnvelope{
			{
				TraceID: "0123456789abcdef0123456789abcdef",
				Service: "token=" + canary, // secretish → dropped from service
				Job:     "should-be-overridden",
				Build:   999,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "exported" || res.Backend != "http" {
		t.Fatalf("res=%+v", res)
	}
	if res.Accepted != 1 {
		t.Fatalf("accepted=%d (trace_id alone should export)", res.Accepted)
	}
	if len(sawBody) == 0 {
		t.Fatal("server saw no body")
	}
	if strings.Contains(string(sawBody), canary) {
		t.Fatal("secret canary present in HTTP payload")
	}
	var parsed struct {
		Job       string `json:"job"`
		Build     int    `json:"build"`
		Envelopes []struct {
			TraceID string `json:"trace_id"`
			Service string `json:"service"`
			Job     string `json:"job"`
			Build   int    `json:"build"`
		} `json:"envelopes"`
	}
	if err := json.Unmarshal(sawBody, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Job != "demo" || parsed.Build != 5 {
		t.Fatalf("identity=%+v", parsed)
	}
	if len(parsed.Envelopes) != 1 {
		t.Fatalf("envelopes=%+v", parsed.Envelopes)
	}
	if parsed.Envelopes[0].Service != "" {
		t.Fatalf("secretish service should be empty, got %q", parsed.Envelopes[0].Service)
	}
	if parsed.Envelopes[0].Job != "demo" || parsed.Envelopes[0].Build != 5 {
		t.Fatalf("envelope identity override not blocked: %+v", parsed.Envelopes[0])
	}
}

func TestDefaultRateLimitForOtelExportBackend(t *testing.T) {
	t.Parallel()
	cap0, refill0 := adapter.DefaultRateLimitForOtelExportBackend(adapter.OtelExportBackendNoop)
	if cap0 != 0 || refill0 != 0 {
		t.Fatalf("noop want unlimited, got (%v,%v)", cap0, refill0)
	}
	for _, backend := range []adapter.OtelExportBackendName{
		adapter.OtelExportBackendHTTP,
		adapter.OtelExportBackendMock,
		"HTTP",
	} {
		c, r := adapter.DefaultRateLimitForOtelExportBackend(backend)
		if c != adapter.DefaultNetworkAdapterRateCapacity {
			t.Fatalf("backend %q capacity=%v", backend, c)
		}
		if r != adapter.DefaultNetworkAdapterRateRefillPerS {
			t.Fatalf("backend %q refill=%v", backend, r)
		}
	}
}

func TestBuiltinIDsIncludeOtelExport(t *testing.T) {
	t.Parallel()
	if !adapter.IsBuiltin(adapter.IDOtelExport) {
		t.Fatal("otel-export should be builtin")
	}
	cat := adapter.DefaultCatalog()
	if _, ok := cat[adapter.IDOtelExport]; !ok {
		t.Fatal("catalog missing otel-export")
	}
	// Allowlist: builtins enable without file
	r := adapter.NewRegistry(adapter.Config{
		EnabledIDs: []string{adapter.IDOtelExport},
	})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	if r.Get(adapter.IDOtelExport) == nil {
		t.Fatal("missing after enable")
	}
}
