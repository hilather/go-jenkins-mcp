package tools_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// mockSubjectLimiter records Hold/release for HOST-006 addTool wire tests.
type mockSubjectLimiter struct {
	holds    atomic.Int32
	releases atomic.Int32
	// failNext when true returns CodeQuota without holding.
	failNext atomic.Bool
	lastKey  atomic.Value // string
}

func (m *mockSubjectLimiter) Hold(subjectKey string) (release func(), err error) {
	m.lastKey.Store(subjectKey)
	if m.failNext.Load() {
		return func() {}, apperr.New(apperr.CodeQuota, "subject concurrent tool budget exceeded")
	}
	m.holds.Add(1)
	var once atomic.Bool
	return func() {
		if once.CompareAndSwap(false, true) {
			m.releases.Add(1)
		}
	}, nil
}

// Regression: HOST-006 SubjectLimiter Hold wraps tool dispatch and releases.
func TestSubjectLimiter_HoldAroundDispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lim := &mockSubjectLimiter{}
	var ran bool
	server := mcp.NewServer(&mcp.Implementation{Name: "subj-hold", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, &tools.RegisterOptions{
		Gate:           policy.NewDefaultReadOnlyGate(),
		SubjectKey:     "tenant-a|alice|corp",
		SubjectLimiter: lim,
	}, &mcp.Tool{Name: "test_subject_hold", Description: "test"},
		func(ctx context.Context, req *mcp.CallToolRequest, args emptyArgs) (*mcp.CallToolResult, gateOut, error) {
			if lim.holds.Load() != 1 {
				t.Errorf("expected Hold before handler: holds=%d", lim.holds.Load())
			}
			if lim.releases.Load() != 0 {
				t.Errorf("release must not run before handler returns")
			}
			ran = true
			return structuredGateOK()
		})

	cs := connectToolClient(t, ctx, server)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_subject_hold", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil && res.IsError {
		t.Fatalf("unexpected tool error: %s", toolErrorText(res))
	}
	if !ran {
		t.Fatal("handler did not run")
	}
	if lim.holds.Load() != 1 || lim.releases.Load() != 1 {
		t.Fatalf("holds=%d releases=%d want 1/1", lim.holds.Load(), lim.releases.Load())
	}
	if got, _ := lim.lastKey.Load().(string); got != "tenant-a|alice|corp" {
		t.Fatalf("subject key: %q", got)
	}
}

// Regression: quota errors fail closed before handler (CodeQuota).
func TestSubjectLimiter_QuotaFailClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lim := &mockSubjectLimiter{}
	lim.failNext.Store(true)
	server := mcp.NewServer(&mcp.Implementation{Name: "subj-quota", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, &tools.RegisterOptions{
		Gate:           policy.NewDefaultReadOnlyGate(),
		SubjectKey:     "tenant-a|bob|corp",
		SubjectLimiter: lim,
	}, &mcp.Tool{Name: "test_subject_quota", Description: "test"},
		func(ctx context.Context, req *mcp.CallToolRequest, args emptyArgs) (*mcp.CallToolResult, gateOut, error) {
			t.Fatal("handler must not run when subject quota exceeded")
			return structuredGateOK()
		})

	cs := connectToolClient(t, ctx, server)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_subject_quota", Arguments: map[string]any{}})
	if err != nil {
		// Transport-level error is acceptable if coded message present.
		if !strings.Contains(err.Error(), "quota") && !strings.Contains(err.Error(), string(apperr.CodeQuota)) {
			t.Fatalf("want quota error: %v", err)
		}
		return
	}
	if res == nil || !res.IsError {
		t.Fatalf("want tool error, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(strings.ToLower(text), "quota") &&
		!strings.Contains(text, string(apperr.CodeQuota)) &&
		!strings.Contains(strings.ToLower(text), "budget") {
		t.Fatalf("unexpected denial text: %q", text)
	}
	if lim.holds.Load() != 0 {
		t.Fatalf("failed Hold must not count as hold: %d", lim.holds.Load())
	}
}

// Empty SubjectKey skips limiter even when limiter is set (stdio pilot residual).
func TestSubjectLimiter_EmptyKeySkips(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lim := &mockSubjectLimiter{}
	var ran bool
	server := mcp.NewServer(&mcp.Implementation{Name: "subj-skip", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, &tools.RegisterOptions{
		Gate:           policy.NewDefaultReadOnlyGate(),
		SubjectKey:     "", // empty → skip
		SubjectLimiter: lim,
	}, &mcp.Tool{Name: "test_subject_skip", Description: "test"},
		func(ctx context.Context, req *mcp.CallToolRequest, args emptyArgs) (*mcp.CallToolResult, gateOut, error) {
			ran = true
			return structuredGateOK()
		})

	cs := connectToolClient(t, ctx, server)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_subject_skip", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil && res.IsError {
		t.Fatalf("unexpected tool error: %s", toolErrorText(res))
	}
	if !ran {
		t.Fatal("handler did not run")
	}
	if lim.holds.Load() != 0 {
		t.Fatalf("empty SubjectKey must skip Hold: holds=%d", lim.holds.Load())
	}
}

// mockSubjectRateLimiter records Allow for HOST-006 addTool rate wire tests.
type mockSubjectRateLimiter struct {
	allows   atomic.Int32
	failNext atomic.Bool
	lastKey  atomic.Value // string
}

func (m *mockSubjectRateLimiter) Allow(subjectKey string) error {
	m.lastKey.Store(subjectKey)
	if m.failNext.Load() {
		return apperr.New(apperr.CodeQuota, "subject tool rate budget exceeded")
	}
	m.allows.Add(1)
	return nil
}

// Regression: HOST-006 SubjectRateLimiter Allow runs before handler and before Hold.
func TestSubjectRateLimiter_AllowAroundDispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rate := &mockSubjectRateLimiter{}
	slots := &mockSubjectLimiter{}
	var ran bool
	server := mcp.NewServer(&mcp.Implementation{Name: "subj-rate", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, &tools.RegisterOptions{
		Gate:               policy.NewDefaultReadOnlyGate(),
		SubjectKey:         "tenant-a|alice|corp",
		SubjectRateLimiter: rate,
		SubjectLimiter:     slots,
	}, &mcp.Tool{Name: "test_subject_rate", Description: "test"},
		func(ctx context.Context, req *mcp.CallToolRequest, args emptyArgs) (*mcp.CallToolResult, gateOut, error) {
			if rate.allows.Load() != 1 {
				t.Errorf("expected Allow before handler: allows=%d", rate.allows.Load())
			}
			if slots.holds.Load() != 1 {
				t.Errorf("expected Hold after Allow: holds=%d", slots.holds.Load())
			}
			ran = true
			return structuredGateOK()
		})

	cs := connectToolClient(t, ctx, server)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_subject_rate", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil && res.IsError {
		t.Fatalf("unexpected tool error: %s", toolErrorText(res))
	}
	if !ran {
		t.Fatal("handler did not run")
	}
	if rate.allows.Load() != 1 {
		t.Fatalf("allows=%d want 1", rate.allows.Load())
	}
	got, _ := rate.lastKey.Load().(string)
	if got != "tenant-a|alice|corp" {
		t.Fatalf("subject key: %q", got)
	}
	// Canary: mock never logs secrets; key is namespace only.
	if strings.Contains(got, "Bearer ") || strings.Contains(got, "token=") {
		t.Fatalf("subject key looks secret-bearing: %q", got)
	}
}

// Regression: rate quota fails closed before handler and does not Hold a slot.
func TestSubjectRateLimiter_QuotaFailClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rate := &mockSubjectRateLimiter{}
	rate.failNext.Store(true)
	slots := &mockSubjectLimiter{}
	server := mcp.NewServer(&mcp.Implementation{Name: "subj-rate-quota", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, &tools.RegisterOptions{
		Gate:               policy.NewDefaultReadOnlyGate(),
		SubjectKey:         "tenant-a|bob|corp",
		SubjectRateLimiter: rate,
		SubjectLimiter:     slots,
	}, &mcp.Tool{Name: "test_subject_rate_quota", Description: "test"},
		func(ctx context.Context, req *mcp.CallToolRequest, args emptyArgs) (*mcp.CallToolResult, gateOut, error) {
			t.Fatal("handler must not run when subject rate exceeded")
			return structuredGateOK()
		})

	cs := connectToolClient(t, ctx, server)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_subject_rate_quota", Arguments: map[string]any{}})
	if err != nil {
		if !strings.Contains(err.Error(), "quota") && !strings.Contains(err.Error(), string(apperr.CodeQuota)) {
			t.Fatalf("want quota error: %v", err)
		}
	} else {
		if res == nil || !res.IsError {
			t.Fatalf("want tool error, got %#v", res)
		}
		text := toolErrorText(res)
		if !strings.Contains(strings.ToLower(text), "quota") &&
			!strings.Contains(text, string(apperr.CodeQuota)) &&
			!strings.Contains(strings.ToLower(text), "budget") &&
			!strings.Contains(strings.ToLower(text), "rate") {
			t.Fatalf("unexpected denial text: %q", text)
		}
	}
	if rate.allows.Load() != 0 {
		t.Fatalf("failed Allow must not count as allow: %d", rate.allows.Load())
	}
	if slots.holds.Load() != 0 {
		t.Fatalf("rate deny must not Hold concurrent slot: holds=%d", slots.holds.Load())
	}
}

// Empty SubjectKey skips rate limiter (stdio pilot residual).
func TestSubjectRateLimiter_EmptyKeySkips(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rate := &mockSubjectRateLimiter{}
	var ran bool
	server := mcp.NewServer(&mcp.Implementation{Name: "subj-rate-skip", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, &tools.RegisterOptions{
		Gate:               policy.NewDefaultReadOnlyGate(),
		SubjectKey:         "",
		SubjectRateLimiter: rate,
	}, &mcp.Tool{Name: "test_subject_rate_skip", Description: "test"},
		func(ctx context.Context, req *mcp.CallToolRequest, args emptyArgs) (*mcp.CallToolResult, gateOut, error) {
			ran = true
			return structuredGateOK()
		})

	cs := connectToolClient(t, ctx, server)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_subject_rate_skip", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil && res.IsError {
		t.Fatalf("unexpected tool error: %s", toolErrorText(res))
	}
	if !ran {
		t.Fatal("handler did not run")
	}
	if rate.allows.Load() != 0 {
		t.Fatalf("empty SubjectKey must skip Allow: allows=%d", rate.allows.Load())
	}
}
