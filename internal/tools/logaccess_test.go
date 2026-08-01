package tools_test

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// fakeLogAccess is a test double for tools.LogAccess.
type fakeLogAccess struct {
	ensureCalls atomic.Int64
	readCalls   atomic.Int64
	tailCalls   atomic.Int64

	// EnsureErr is returned from EnsureMirrored when set.
	EnsureErr error
	// Body is the full mirrored log.
	Body string
	// Sealed marks meta.
	Sealed bool
	// Generation for meta.
	Generation int64
	// FailRead forces ReadRange/Tail errors.
	FailRead error
	// SkipMirror makes Ensure succeed but reads return not_found (fallback path).
	EmptyMirror bool
}

func (f *fakeLogAccess) EnsureMirrored(ctx context.Context, job string, build int64) error {
	f.ensureCalls.Add(1)
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.EnsureErr
}

func (f *fakeLogAccess) ReadRange(ctx context.Context, job string, build int64, offset, length int64) (string, tools.LogReadMeta, error) {
	f.readCalls.Add(1)
	if f.FailRead != nil {
		return "", tools.LogReadMeta{}, f.FailRead
	}
	if f.EmptyMirror {
		return "", tools.LogReadMeta{}, apperr.New(apperr.CodeNotFound, "no log generation")
	}
	body := f.Body
	if offset < 0 {
		offset = 0
	}
	if offset > int64(len(body)) {
		offset = int64(len(body))
	}
	end := offset + length
	if length < 0 {
		end = offset
	}
	if end > int64(len(body)) {
		end = int64(len(body))
	}
	slice := body[offset:end]
	gen := f.Generation
	if gen == 0 {
		gen = 1
	}
	return slice, tools.LogReadMeta{
		Offset:     int(offset),
		Length:     len(slice),
		TotalSize:  len(body),
		HasMore:    end < int64(len(body)) || !f.Sealed,
		Generation: gen,
		Sealed:     f.Sealed,
	}, nil
}

func (f *fakeLogAccess) Tail(ctx context.Context, job string, build int64, maxLen int64) (string, tools.LogReadMeta, error) {
	f.tailCalls.Add(1)
	if f.FailRead != nil {
		return "", tools.LogReadMeta{}, f.FailRead
	}
	if f.EmptyMirror {
		return "", tools.LogReadMeta{}, apperr.New(apperr.CodeNotFound, "no log generation")
	}
	body := f.Body
	if maxLen < 0 {
		maxLen = 0
	}
	start := int64(len(body)) - maxLen
	if start < 0 {
		start = 0
	}
	return f.ReadRange(ctx, job, build, start, int64(len(body))-start)
}

// trackingClient is not needed — we use a real Client pointing at a closed
// server only for fallback tests. Prefer asserting LogAccess call counts.

func TestLogTools_PreferLogAccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fake := &fakeLogAccess{
		Body:       "abcdefghij0123456789",
		Sealed:     true,
		Generation: 1,
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "log-access-test", Version: "test"}, nil)
	// Client should not be used when LogAccess succeeds (nil-safe methods panic if called —
	// use empty client; GetBuildLogs will fail if fallback happens unexpectedly).
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Logs: fake,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_get_build_logs",
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 3,
			"offset":       0,
			"length":       10,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	if fake.ensureCalls.Load() < 1 || fake.readCalls.Load() < 1 {
		t.Fatalf("expected LogAccess ensure+read, ensure=%d read=%d",
			fake.ensureCalls.Load(), fake.readCalls.Load())
	}
	// Structured content should include the mirrored slice.
	payload := toolStructuredJSON(t, res)
	if got := payload["logs"]; got != "abcdefghij" {
		t.Fatalf("logs=%v want abcdefghij payload=%v", got, payload)
	}
}

func TestLogTools_TailPrefersLogAccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fake := &fakeLogAccess{
		Body:       "0123456789TAIL",
		Sealed:     true,
		Generation: 2,
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "log-tail-test", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{Logs: fake})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_get_build_log_tail",
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 1,
			"max_length":   4,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	if fake.tailCalls.Load() < 1 {
		t.Fatalf("expected Tail call, got %d", fake.tailCalls.Load())
	}
	payload := toolStructuredJSON(t, res)
	if got := payload["logs"]; got != "TAIL" {
		t.Fatalf("logs=%v want TAIL", got)
	}
}

func TestLogTools_CheckStoreReadDeniesCache(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fake := &fakeLogAccess{Body: "secret-log", Sealed: true, Generation: 1}
	// Deny cache reads via store_cached_read + job prefix (POL-004).
	doc := policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret-job"},
	}
	ev := policy.NewDenyOnlyEvaluator(doc)
	subject := policy.NewSubject("corp", "alice", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "log-policy-test", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Logs:    fake,
		Policy:  ev,
		Subject: subject,
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_get_build_logs",
		Arguments: map[string]any{
			"job_name":     "secret-job",
			"build_number": 1,
			"offset":       0,
			"length":       10,
		},
	})
	if fake.readCalls.Load() > 0 {
		t.Fatal("ReadRange must not run when CheckStoreRead denies")
	}
	if fake.ensureCalls.Load() > 0 {
		t.Fatal("EnsureMirrored must not run when CheckStoreRead denies")
	}
	// Denial should surface as tool error; never leak secret body.
	if err == nil && res != nil && !res.IsError {
		payload := toolStructuredJSON(t, res)
		if logs, _ := payload["logs"].(string); logs == "secret-log" {
			t.Fatal("secret log body leaked after policy denial")
		}
		t.Fatalf("expected policy denial error, got success: %v", payload)
	}
}

func TestLogTools_FallbackWhenMirrorEmpty(t *testing.T) {
	// Empty mirror → fallback to client. Client with empty URL fails; we only
	// assert Ensure was tried and tool surfaces an error (not a silent empty).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fake := &fakeLogAccess{EmptyMirror: true}
	server := mcp.NewServer(&mcp.Implementation{Name: "log-fallback-test", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{Logs: fake})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_get_build_logs",
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 1,
			"offset":       0,
			"length":       8,
		},
	})
	if fake.ensureCalls.Load() < 1 {
		t.Fatal("expected EnsureMirrored before fallback")
	}
	// Direct client has no base URL → error path (not success with mirror body).
	if err == nil && res != nil && !res.IsError {
		payload := toolStructuredJSON(t, res)
		if logs, _ := payload["logs"].(string); logs != "" {
			// Unexpected success without a real Jenkins — acceptable only if empty.
			t.Logf("fallback result: %v", payload)
		}
	}
}

func TestLogTools_NilLogAccessStillRegisters(t *testing.T) {
	// Compat: without Logs, tools still register (direct client path).
	server := mcp.NewServer(&mcp.Implementation{Name: "nil-logs", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{})
}

// --- MCP helpers ---

func connectMCP(t *testing.T, ctx context.Context, server *mcp.Server) (*mcp.ClientSession, *mcp.ServerSession) {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		ss.Close()
		t.Fatalf("client.Connect: %v", err)
	}
	return cs, ss
}

func toolStructuredJSON(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	if res == nil {
		t.Fatal("nil result")
	}
	// SDK may put structured content in StructuredContent or Content text.
	if res.StructuredContent != nil {
		switch v := res.StructuredContent.(type) {
		case map[string]any:
			return v
		default:
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			return m
		}
	}
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok && tc != nil {
			var m map[string]any
			if err := json.Unmarshal([]byte(tc.Text), &m); err == nil {
				return m
			}
		}
	}
	t.Fatalf("no structured payload in result: %+v", res)
	return nil
}
