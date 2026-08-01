package mutation_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/mutation"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wave 52 Track C: ResolveMaxPreviewsPerMinute precedence default → env → flag.
func TestResolveMaxPreviewsPerMinute_Precedence(t *testing.T) {
	t.Parallel()

	n, err := mutation.ResolveMaxPreviewsPerMinute("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != mutation.DefaultMaxPreviewsPerMinute {
		t.Fatalf("default: got %d want %d", n, mutation.DefaultMaxPreviewsPerMinute)
	}

	n, err = mutation.ResolveMaxPreviewsPerMinute("", "60")
	if err != nil {
		t.Fatal(err)
	}
	if n != 60 {
		t.Fatalf("env: got %d want 60", n)
	}

	n, err = mutation.ResolveMaxPreviewsPerMinute("45", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 45 {
		t.Fatalf("flag: got %d want 45", n)
	}

	// Flag wins over env.
	n, err = mutation.ResolveMaxPreviewsPerMinute("40", "100")
	if err != nil {
		t.Fatal(err)
	}
	if n != 40 {
		t.Fatalf("flag wins: got %d want 40", n)
	}

	// Whitespace treated as unset.
	n, err = mutation.ResolveMaxPreviewsPerMinute("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if n != mutation.DefaultMaxPreviewsPerMinute {
		t.Fatalf("whitespace: got %d", n)
	}
}

// Explicit 0 means default — operator cannot use 0 for unlimited.
func TestResolveMaxPreviewsPerMinute_ZeroMeansDefault(t *testing.T) {
	t.Parallel()
	n, err := mutation.ResolveMaxPreviewsPerMinute("0", "100")
	if err != nil {
		t.Fatal(err)
	}
	if n != mutation.DefaultMaxPreviewsPerMinute {
		t.Fatalf("flag 0: got %d want default %d", n, mutation.DefaultMaxPreviewsPerMinute)
	}
	n, err = mutation.ResolveMaxPreviewsPerMinute("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != mutation.DefaultMaxPreviewsPerMinute {
		t.Fatalf("env 0: got %d", n)
	}
	n, err = mutation.ResolveMaxPreviewsPerMinute("  ", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != mutation.DefaultMaxPreviewsPerMinute {
		t.Fatalf("whitespace flag + env 0: got %d", n)
	}
}

func TestResolveMaxPreviewsPerMinute_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-number"},
		{"bad flag", "30pm", ""},
		{"negative env", "", "-1"},
		{"negative flag", "-10", "30"},
		{"float", "", "1.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := mutation.ResolveMaxPreviewsPerMinute(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "preview") && !strings.Contains(msg, "invalid") && !strings.Contains(msg, "negative") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestResolveMaxPreviewsPerMinute_AbsoluteCap(t *testing.T) {
	t.Parallel()
	capStr := strconv.Itoa(mutation.AbsoluteMaxPreviewsPerMinute)
	overFlag := strconv.Itoa(mutation.AbsoluteMaxPreviewsPerMinute + 1)
	overEnv := strconv.Itoa(mutation.AbsoluteMaxPreviewsPerMinute * 2)

	n, err := mutation.ResolveMaxPreviewsPerMinute(capStr, "")
	if err != nil {
		t.Fatal(err)
	}
	if n != mutation.AbsoluteMaxPreviewsPerMinute {
		t.Fatalf("at cap: got %d want %d", n, mutation.AbsoluteMaxPreviewsPerMinute)
	}
	n, err = mutation.ResolveMaxPreviewsPerMinute("", capStr)
	if err != nil {
		t.Fatal(err)
	}
	if n != mutation.AbsoluteMaxPreviewsPerMinute {
		t.Fatalf("env at cap: got %d", n)
	}

	n, err = mutation.ResolveMaxPreviewsPerMinute("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n > mutation.AbsoluteMaxPreviewsPerMinute {
		t.Fatalf("default %d exceeds absolute max %d", n, mutation.AbsoluteMaxPreviewsPerMinute)
	}

	_, err = mutation.ResolveMaxPreviewsPerMinute(overFlag, "")
	if err == nil {
		t.Fatal("over absolute flag must fail closed")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "maximum") &&
		!strings.Contains(strings.ToLower(err.Error()), "bound") {
		t.Fatalf("error should cite absolute bound: %v", err)
	}

	_, err = mutation.ResolveMaxPreviewsPerMinute("", overEnv)
	if err == nil {
		t.Fatal("over absolute env must fail closed")
	}

	// Flag wins with valid under-cap; env oversize ignored when flag set valid.
	n, err = mutation.ResolveMaxPreviewsPerMinute(strconv.Itoa(mutation.DefaultMaxPreviewsPerMinute), overEnv)
	if err != nil {
		t.Fatal(err)
	}
	if n != mutation.DefaultMaxPreviewsPerMinute {
		t.Fatalf("valid flag with oversize env: got %d", n)
	}
	// Oversize flag fails even if env valid.
	_, err = mutation.ResolveMaxPreviewsPerMinute(overFlag, strconv.Itoa(mutation.DefaultMaxPreviewsPerMinute))
	if err == nil {
		t.Fatal("oversize flag must fail even with valid env")
	}
}

func TestResolveMaxPreviewsPerMinute_EnvName(t *testing.T) {
	t.Parallel()
	if mutation.EnvMaxPreviewsPerMinute != "JENKINS_MCP_MUTATION_MAX_PREVIEWS_PER_MINUTE" {
		t.Fatalf("env name drift: %q", mutation.EnvMaxPreviewsPerMinute)
	}
	if mutation.AbsoluteMaxPreviewsPerMinute != 300 {
		t.Fatalf("AbsoluteMaxPreviewsPerMinute=%d want 300", mutation.AbsoluteMaxPreviewsPerMinute)
	}
	if mutation.DefaultMaxPreviewsPerMinute != 30 {
		t.Fatalf("DefaultMaxPreviewsPerMinute=%d want 30", mutation.DefaultMaxPreviewsPerMinute)
	}
	// Invalid env fails closed; full env var name may be [REDACTED] by bare-token
	// heuristic (long JENKINS_MCP_* identifiers) — assert layer label only.
	_, err := mutation.ResolveMaxPreviewsPerMinute("", "nope")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "env") || !strings.Contains(msg, "preview") {
		t.Fatalf("error should name env source layer + preview: %v", err)
	}
}

// Process live Set/Get + NewManager zero config honors process live.
// Not parallel: mutates package-level atomic process live.
func TestSetMaxPreviewsPerMinute_NewManagerUsesProcessLive(t *testing.T) {
	mutation.ResetMaxPreviewsPerMinuteForTest()
	defer mutation.ResetMaxPreviewsPerMinuteForTest()

	const liveCap = 3
	mutation.SetMaxPreviewsPerMinute(liveCap)
	if got := mutation.MaxPreviewsPerMinute(); got != liveCap {
		t.Fatalf("MaxPreviewsPerMinute after Set: got %d want %d", got, liveCap)
	}

	// Explicit Config value still wins over process live.
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	mExplicit := mutation.NewManager(mutation.Config{
		Gate:                 policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		MaxPreviewsPerMinute: 1,
		ConfirmCooldown:      -1,
		Now:                  now,
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	if _, err := mExplicit.Preview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := mExplicit.Preview(context.Background(), intent); err == nil || apperr.CodeOf(err) != apperr.CodeThrottled {
		t.Fatalf("explicit Config=1 should throttle on 2nd preview, got %v", err)
	}

	// Config 0 → process live (3).
	mem := &audit.Memory{}
	mLive := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:           mem,
		ConfirmCooldown: -1,
		Now:             now,
		// MaxPreviewsPerMinute left 0 → process live
	})
	for i := 0; i < liveCap; i++ {
		if _, err := mLive.Preview(context.Background(), intent); err != nil {
			t.Fatalf("preview %d under live cap %d: %v", i, liveCap, err)
		}
	}
	_, err := mLive.Preview(context.Background(), intent)
	if err == nil || apperr.CodeOf(err) != apperr.CodeThrottled {
		t.Fatalf("want throttled after live cap %d, got %v", liveCap, err)
	}
	assertDenyReason(t, mem, mutation.ReasonPreviewRateLimited)

	// Non-positive Set → default (getter effective value).
	mutation.SetMaxPreviewsPerMinute(0)
	if got := mutation.MaxPreviewsPerMinute(); got != mutation.DefaultMaxPreviewsPerMinute {
		t.Fatalf("Set(0): got %d want default %d", got, mutation.DefaultMaxPreviewsPerMinute)
	}

	// Oversize Set clamped to absolute (belt-and-suspenders).
	mutation.SetMaxPreviewsPerMinute(mutation.AbsoluteMaxPreviewsPerMinute + 50)
	if got := mutation.MaxPreviewsPerMinute(); got != mutation.AbsoluteMaxPreviewsPerMinute {
		t.Fatalf("oversize Set: got %d want absolute %d", got, mutation.AbsoluteMaxPreviewsPerMinute)
	}

	// Residual: library negative still unlimited (not process live / operator path).
	// Regression: operator cannot set unlimited; library Config negative can.
	mUnlim := mutation.NewManager(mutation.Config{
		Gate:                 policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		MaxPreviewsPerMinute: -1,
		ConfirmCooldown:      -1,
		Now:                  now,
	})
	// Process live is AbsoluteMax; unlimited must allow more than absolute.
	for i := 0; i < mutation.AbsoluteMaxPreviewsPerMinute+5; i++ {
		if _, err := mUnlim.Preview(context.Background(), intent); err != nil {
			t.Fatalf("unlimited residual preview %d: %v", i, err)
		}
	}
}

// When process live is unset (0), NewManager zero config uses Default.
// Serial: mutates process live atomic.
func TestNewManager_ZeroConfigDefaultWhenProcessLiveUnset(t *testing.T) {
	mutation.ResetMaxPreviewsPerMinuteForTest()
	defer mutation.ResetMaxPreviewsPerMinuteForTest()

	// Unset process live: NewManager Config 0 → DefaultMaxPreviewsPerMinute.
	if got := mutation.MaxPreviewsPerMinute(); got != mutation.DefaultMaxPreviewsPerMinute {
		t.Fatalf("unset getter: got %d want default %d", got, mutation.DefaultMaxPreviewsPerMinute)
	}
	now, _ := testClock(time.Date(2026, 8, 1, 14, 0, 0, 0, time.UTC))
	mem := &audit.Memory{}
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:           mem,
		ConfirmCooldown: -1,
		Now:             now,
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "zero-cfg"}
	for i := 0; i < mutation.DefaultMaxPreviewsPerMinute; i++ {
		if _, err := m.Preview(context.Background(), intent); err != nil {
			t.Fatalf("preview %d: %v", i, err)
		}
	}
	if _, err := m.Preview(context.Background(), intent); err == nil || apperr.CodeOf(err) != apperr.CodeThrottled {
		t.Fatalf("want throttled after default cap, got %v", err)
	}
}
