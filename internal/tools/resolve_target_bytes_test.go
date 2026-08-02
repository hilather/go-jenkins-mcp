package tools_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

// Wave 47 Track B: ResolveTargetBytes precedence default → env → flag (flag wins).
func TestResolveTargetBytes_Precedence(t *testing.T) {
	t.Parallel()

	// Both unset → default 64 KiB.
	n, err := tools.ResolveTargetBytes("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != tools.DefaultTargetBytes {
		t.Fatalf("default: got %d want %d", n, tools.DefaultTargetBytes)
	}

	// Env only.
	n, err = tools.ResolveTargetBytes("", "131072")
	if err != nil {
		t.Fatal(err)
	}
	if n != 131072 {
		t.Fatalf("env: got %d want 131072", n)
	}

	// Flag only.
	n, err = tools.ResolveTargetBytes("262144", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 262144 {
		t.Fatalf("flag: got %d want 262144", n)
	}

	// Flag wins over env.
	n, err = tools.ResolveTargetBytes("65536", "524288")
	if err != nil {
		t.Fatal(err)
	}
	if n != 65536 {
		t.Fatalf("flag wins: got %d want 65536", n)
	}

	// Whitespace treated as unset.
	n, err = tools.ResolveTargetBytes("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if n != tools.DefaultTargetBytes {
		t.Fatalf("whitespace: got %d", n)
	}
}

func TestResolveTargetBytes_ZeroMeansDefault(t *testing.T) {
	t.Parallel()
	n, err := tools.ResolveTargetBytes("0", "131072")
	if err != nil {
		t.Fatal(err)
	}
	// Explicit flag "0" wins and means default (not keep env).
	if n != tools.DefaultTargetBytes {
		t.Fatalf("flag 0: got %d want default %d", n, tools.DefaultTargetBytes)
	}
	n, err = tools.ResolveTargetBytes("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != tools.DefaultTargetBytes {
		t.Fatalf("env 0: got %d", n)
	}
}

func TestResolveTargetBytes_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-number"},
		{"bad flag", "64KiB", ""},
		{"negative env", "", "-1"},
		{"negative flag", "-100", "1024"},
		{"float", "", "1.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tools.ResolveTargetBytes(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := err.Error()
			if !strings.Contains(msg, "target") && !strings.Contains(msg, "invalid") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// Wave 47/51: absolute process fail-closed ceiling
// (AbsoluteMaxTargetBytes = AbsoluteMaxHardMaxBytes / 64 MiB).
func TestResolveTargetBytes_AbsoluteCap(t *testing.T) {
	t.Parallel()
	if tools.AbsoluteMaxTargetBytes != tools.AbsoluteMaxHardMaxBytes {
		t.Fatalf("AbsoluteMaxTargetBytes=%d want AbsoluteMaxHardMaxBytes=%d",
			tools.AbsoluteMaxTargetBytes, tools.AbsoluteMaxHardMaxBytes)
	}
	if tools.AbsoluteMaxTargetBytes != 64<<20 {
		t.Fatalf("AbsoluteMaxTargetBytes=%d want 64 MiB", tools.AbsoluteMaxTargetBytes)
	}
	capStr := strconv.Itoa(tools.AbsoluteMaxTargetBytes)
	overFlag := strconv.Itoa(tools.AbsoluteMaxTargetBytes + 1)
	overEnv := strconv.Itoa(tools.AbsoluteMaxTargetBytes * 2)
	absurd := strconv.Itoa(1 << 30) // 1 GiB — must fail closed

	// At absolute cap: ok.
	n, err := tools.ResolveTargetBytes(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if n != tools.AbsoluteMaxTargetBytes {
		t.Fatalf("at cap: got %d want %d", n, tools.AbsoluteMaxTargetBytes)
	}
	n, err = tools.ResolveTargetBytes("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if n != tools.AbsoluteMaxTargetBytes {
		t.Fatalf("at cap env: got %d", n)
	}

	// Values above former 1 MiB soft absolute but under 64 MiB must resolve.
	aboveOldCap := strconv.Itoa(tools.DefaultHardMaxBytes + 1) // 1 MiB + 1
	n, err = tools.ResolveTargetBytes(aboveOldCap, "")
	if err != nil {
		t.Fatalf("above former 1 MiB soft absolute must resolve under 64 MiB: %v", err)
	}
	if n != tools.DefaultHardMaxBytes+1 {
		t.Fatalf("above old cap: got %d want %d", n, tools.DefaultHardMaxBytes+1)
	}
	// Mid-range raise (e.g. 4 MiB) ok when under AbsoluteMaxTargetBytes.
	n, err = tools.ResolveTargetBytes(strconv.Itoa(4<<20), "")
	if err != nil || n != 4<<20 {
		t.Fatalf("4 MiB target: n=%d err=%v", n, err)
	}

	// Default still works and is under the absolute cap.
	n, err = tools.ResolveTargetBytes("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != tools.DefaultTargetBytes {
		t.Fatalf("default: got %d want %d", n, tools.DefaultTargetBytes)
	}
	if n > tools.AbsoluteMaxTargetBytes {
		t.Fatalf("default %d exceeds absolute max %d", n, tools.AbsoluteMaxTargetBytes)
	}

	// Flag above cap fails closed.
	_, err = tools.ResolveTargetBytes(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "target") ||
		(!strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute")) {
		t.Fatalf("over-cap flag error should mention target / maximum / bound: %v", err)
	}

	// Env above cap fails closed.
	_, err = tools.ResolveTargetBytes("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}
	msg = strings.ToLower(err.Error())
	if !strings.Contains(msg, "target") {
		t.Fatalf("over-cap env error: %v", err)
	}

	// Absurd multi-GB values fail closed.
	_, err = tools.ResolveTargetBytes(absurd, "")
	if err == nil {
		t.Fatal("1 GiB target must fail closed under AbsoluteMaxTargetBytes")
	}

	// Flag under cap wins even when env is over cap.
	n, err = tools.ResolveTargetBytes(strconv.Itoa(tools.DefaultTargetBytes), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if n != tools.DefaultTargetBytes {
		t.Fatalf("got %d", n)
	}
	// Flag over cap fails even when env is sane.
	_, err = tools.ResolveTargetBytes(overFlag, strconv.Itoa(tools.DefaultTargetBytes))
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

// Soft target never silently exceeds hard max at enforce (Normalize clamp).
func TestResolveTargetBytes_NormalizeClampsToHardMax(t *testing.T) {
	t.Parallel()
	// Operator may set soft target equal to absolute (64 MiB) while hard max is
	// default/overlay-lowered; Normalize / LowerHardMax clamp target ≤ hard max.
	b := tools.DefaultBudgets()
	b.TargetBytes = tools.AbsoluteMaxTargetBytes
	b.HardMaxBytes = 32 * 1024
	n := b.Normalize()
	if n.TargetBytes != n.HardMaxBytes {
		t.Fatalf("Normalize must clamp target to hard max: target=%d hard=%d", n.TargetBytes, n.HardMaxBytes)
	}
	// Resolve may yield target > bootstrap hard max (e.g. --target-bytes 4MiB with
	// default 1 MiB hard); serve clamps after Normalize (Wave 51 honesty).
	bServe := tools.DefaultBudgets()
	bServe.HardMaxBytes = tools.DefaultHardMaxBytes
	bServe.TargetBytes = 4 << 20 // 4 MiB soft > 1 MiB hard
	clamped := bServe.Normalize()
	if clamped.TargetBytes != tools.DefaultHardMaxBytes {
		t.Fatalf("serve Normalize when target>hard: target=%d want hard=%d",
			clamped.TargetBytes, tools.DefaultHardMaxBytes)
	}
	// Paired raise: target == hard at AbsoluteMaxHardMaxBytes stays equal.
	bPair := tools.Budgets{
		TargetBytes:  tools.AbsoluteMaxHardMaxBytes,
		HardMaxBytes: tools.AbsoluteMaxHardMaxBytes,
		MaxListItems: tools.DefaultMaxListItems,
	}
	nPair := bPair.Normalize()
	if nPair.TargetBytes != tools.AbsoluteMaxHardMaxBytes || nPair.HardMaxBytes != tools.AbsoluteMaxHardMaxBytes {
		t.Fatalf("paired absolute: target=%d hard=%d", nPair.TargetBytes, nPair.HardMaxBytes)
	}
	b2 := tools.LowerHardMax(tools.Budgets{
		TargetBytes:  tools.DefaultTargetBytes,
		HardMaxBytes: tools.DefaultHardMaxBytes,
		MaxListItems: tools.DefaultMaxListItems,
	}, 1024)
	if b2.TargetBytes > b2.HardMaxBytes {
		t.Fatalf("LowerHardMax must clamp target: target=%d hard=%d", b2.TargetBytes, b2.HardMaxBytes)
	}
}

func TestEnvTargetBytes_Name(t *testing.T) {
	t.Parallel()
	if tools.EnvTargetBytes != "JENKINS_MCP_TARGET_BYTES" {
		t.Fatalf("env name drift: %q", tools.EnvTargetBytes)
	}
}
