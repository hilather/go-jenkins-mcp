package tools_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

// Wave 37: ResolveHardMaxBytes precedence default → env → flag (flag wins).
func TestResolveHardMaxBytes_Precedence(t *testing.T) {
	t.Parallel()

	// Both unset → default 1 MiB.
	n, err := tools.ResolveHardMaxBytes("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != tools.DefaultHardMaxBytes {
		t.Fatalf("default: got %d want %d", n, tools.DefaultHardMaxBytes)
	}

	// Env only.
	n, err = tools.ResolveHardMaxBytes("", "2097152")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2097152 {
		t.Fatalf("env: got %d want 2097152", n)
	}

	// Flag only.
	n, err = tools.ResolveHardMaxBytes("3145728", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3145728 {
		t.Fatalf("flag: got %d want 3145728", n)
	}

	// Flag wins over env.
	n, err = tools.ResolveHardMaxBytes("1048576", "4194304")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1048576 {
		t.Fatalf("flag wins: got %d want 1048576", n)
	}

	// Whitespace treated as unset.
	n, err = tools.ResolveHardMaxBytes("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if n != tools.DefaultHardMaxBytes {
		t.Fatalf("whitespace: got %d", n)
	}
}

func TestResolveHardMaxBytes_ZeroMeansDefault(t *testing.T) {
	t.Parallel()
	n, err := tools.ResolveHardMaxBytes("0", "2097152")
	if err != nil {
		t.Fatal(err)
	}
	// Explicit flag "0" wins and means default (not keep env).
	if n != tools.DefaultHardMaxBytes {
		t.Fatalf("flag 0: got %d want default %d", n, tools.DefaultHardMaxBytes)
	}
	n, err = tools.ResolveHardMaxBytes("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != tools.DefaultHardMaxBytes {
		t.Fatalf("env 0: got %d", n)
	}
}

func TestResolveHardMaxBytes_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-number"},
		{"bad flag", "1MiB", ""},
		{"negative env", "", "-1"},
		{"negative flag", "-100", "1024"},
		{"float", "", "1.5"},
		{"empty tokens", " ", "  "}, // both unset is ok — skip
	} {
		if tc.name == "empty tokens" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tools.ResolveHardMaxBytes(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := err.Error()
			if strings.Contains(msg, "not-a-number") && tc.env == "not-a-number" {
				// raw value may appear in error for operators — no secrets.
			}
			if !strings.Contains(msg, "hard max") && !strings.Contains(msg, "invalid") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// Wave 38: absolute process fail-closed ceiling (AbsoluteMaxHardMaxBytes).
func TestResolveHardMaxBytes_AbsoluteCap(t *testing.T) {
	t.Parallel()
	capStr := strconv.Itoa(tools.AbsoluteMaxHardMaxBytes)
	overFlag := strconv.Itoa(tools.AbsoluteMaxHardMaxBytes + 1)
	overEnv := strconv.Itoa(tools.AbsoluteMaxHardMaxBytes * 2)
	absurd := strconv.Itoa(1 << 30) // 1 GiB — must fail closed

	// At absolute cap: ok.
	n, err := tools.ResolveHardMaxBytes(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if n != tools.AbsoluteMaxHardMaxBytes {
		t.Fatalf("at cap: got %d want %d", n, tools.AbsoluteMaxHardMaxBytes)
	}
	n, err = tools.ResolveHardMaxBytes("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if n != tools.AbsoluteMaxHardMaxBytes {
		t.Fatalf("at cap env: got %d", n)
	}

	// Default still works and is under the absolute cap.
	n, err = tools.ResolveHardMaxBytes("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != tools.DefaultHardMaxBytes {
		t.Fatalf("default: got %d want %d", n, tools.DefaultHardMaxBytes)
	}
	if n > tools.AbsoluteMaxHardMaxBytes {
		t.Fatalf("default %d exceeds absolute max %d", n, tools.AbsoluteMaxHardMaxBytes)
	}

	// Flag above cap fails closed.
	_, err = tools.ResolveHardMaxBytes(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "hard max") ||
		(!strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute")) {
		t.Fatalf("over-cap flag error should mention hard max / maximum / bound: %v", err)
	}

	// Env above cap fails closed.
	_, err = tools.ResolveHardMaxBytes("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}
	msg = strings.ToLower(err.Error())
	if !strings.Contains(msg, "hard max") {
		t.Fatalf("over-cap env error: %v", err)
	}

	// Absurd multi-GB / GiB values fail closed (Wave 37 residual).
	_, err = tools.ResolveHardMaxBytes(absurd, "")
	if err == nil {
		t.Fatal("1 GiB hard max must fail closed under AbsoluteMaxHardMaxBytes")
	}

	// Flag wins with under-cap value even when env is over cap (env discarded after flag wins).
	// But wait: resolve applies env first then flag; absolute check is on final n.
	// Flag under cap + env over cap → flag wins → ok.
	n, err = tools.ResolveHardMaxBytes(strconv.Itoa(tools.DefaultHardMaxBytes), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if n != tools.DefaultHardMaxBytes {
		t.Fatalf("got %d", n)
	}
	// Flag over cap fails even when env is sane.
	_, err = tools.ResolveHardMaxBytes(overFlag, strconv.Itoa(tools.DefaultHardMaxBytes))
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

// LiveHardMax ceiling equals configured bootstrap; overlay lower does not shrink ceiling.
func TestLiveHardMax_CeilingEqualsBootstrapAfterOverlayLower(t *testing.T) {
	t.Parallel()
	const bootstrap = 2 * 1024 * 1024
	const overlay = 65536

	// Serve wiring: NewLiveHardMax(bootstrap) then LowerTo(overlay).
	live := tools.NewLiveHardMax(bootstrap)
	if live.Ceiling() != bootstrap {
		t.Fatalf("ceiling=%d want bootstrap %d", live.Ceiling(), bootstrap)
	}
	if !live.LowerTo(overlay) {
		t.Fatal("LowerTo overlay should change live value")
	}
	if live.Get() != overlay {
		t.Fatalf("get=%d want overlay %d", live.Get(), overlay)
	}
	if live.Ceiling() != bootstrap {
		t.Fatalf("ceiling must stay bootstrap after overlay lower: got %d", live.Ceiling())
	}
	// Reload can raise back up to bootstrap, not above.
	if !live.SetWithinCeiling(bootstrap) {
		t.Fatal("SetWithinCeiling to bootstrap should succeed")
	}
	if live.Get() != bootstrap {
		t.Fatalf("get=%d want %d", live.Get(), bootstrap)
	}
	if live.SetWithinCeiling(bootstrap * 2) {
		// may return false if already at ceiling after clamp
	}
	if live.Get() != bootstrap {
		t.Fatalf("must not exceed bootstrap ceiling: get=%d", live.Get())
	}

	// LowerHardMax composition: budgets start at bootstrap, overlay only lowers.
	b := tools.DefaultBudgets()
	b.HardMaxBytes = bootstrap
	b = b.Normalize()
	b = tools.LowerHardMax(b, overlay)
	if b.HardMaxBytes != overlay {
		t.Fatalf("LowerHardMax=%d want %d", b.HardMaxBytes, overlay)
	}
	// Overlay cannot raise: LowerHardMax with larger n is a no-op.
	b2 := tools.LowerHardMax(b, bootstrap)
	if b2.HardMaxBytes != overlay {
		t.Fatalf("LowerHardMax must not raise: got %d", b2.HardMaxBytes)
	}
}
