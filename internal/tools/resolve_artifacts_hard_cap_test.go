package tools_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

// Wave 42: ResolveArtifactsHardCap precedence default → env → flag (flag wins).
func TestResolveArtifactsHardCap_Precedence(t *testing.T) {
	t.Parallel()

	n, err := tools.ResolveArtifactsHardCap("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultArtifactsHardCap {
		t.Fatalf("default: got %d want %d", n, jenkins.DefaultArtifactsHardCap)
	}

	n, err = tools.ResolveArtifactsHardCap("", "1000")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1000 {
		t.Fatalf("env: got %d want 1000", n)
	}

	n, err = tools.ResolveArtifactsHardCap("750", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 750 {
		t.Fatalf("flag: got %d want 750", n)
	}

	// Flag wins over env.
	n, err = tools.ResolveArtifactsHardCap("600", "1500")
	if err != nil {
		t.Fatal(err)
	}
	if n != 600 {
		t.Fatalf("flag wins: got %d want 600", n)
	}

	// Whitespace treated as unset.
	n, err = tools.ResolveArtifactsHardCap("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultArtifactsHardCap {
		t.Fatalf("whitespace: got %d", n)
	}
}

func TestResolveArtifactsHardCap_ZeroMeansDefault(t *testing.T) {
	t.Parallel()
	n, err := tools.ResolveArtifactsHardCap("0", "1000")
	if err != nil {
		t.Fatal(err)
	}
	// Explicit flag "0" wins and means default (not keep env).
	if n != jenkins.DefaultArtifactsHardCap {
		t.Fatalf("flag 0: got %d want default %d", n, jenkins.DefaultArtifactsHardCap)
	}
	n, err = tools.ResolveArtifactsHardCap("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultArtifactsHardCap {
		t.Fatalf("env 0: got %d", n)
	}
}

func TestResolveArtifactsHardCap_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-number"},
		{"bad flag", "50cap", ""},
		{"negative env", "", "-1"},
		{"negative flag", "-10", "500"},
		{"float", "", "1.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tools.ResolveArtifactsHardCap(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "artifact") && !strings.Contains(msg, "invalid") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// Wave 42: absolute process fail-closed ceiling (AbsoluteMaxArtifactsHardCap).
func TestResolveArtifactsHardCap_AbsoluteCap(t *testing.T) {
	t.Parallel()
	capStr := strconv.Itoa(jenkins.AbsoluteMaxArtifactsHardCap)
	overFlag := strconv.Itoa(jenkins.AbsoluteMaxArtifactsHardCap + 1)
	overEnv := strconv.Itoa(jenkins.AbsoluteMaxArtifactsHardCap * 2)
	absurd := "100000"

	// At absolute cap: ok.
	n, err := tools.ResolveArtifactsHardCap(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if n != jenkins.AbsoluteMaxArtifactsHardCap {
		t.Fatalf("at cap: got %d want %d", n, jenkins.AbsoluteMaxArtifactsHardCap)
	}
	n, err = tools.ResolveArtifactsHardCap("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if n != jenkins.AbsoluteMaxArtifactsHardCap {
		t.Fatalf("at cap env: got %d", n)
	}

	// Default under absolute cap.
	n, err = tools.ResolveArtifactsHardCap("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultArtifactsHardCap {
		t.Fatalf("default: got %d want %d", n, jenkins.DefaultArtifactsHardCap)
	}
	if n > jenkins.AbsoluteMaxArtifactsHardCap {
		t.Fatalf("default %d exceeds absolute max %d", n, jenkins.AbsoluteMaxArtifactsHardCap)
	}

	// Flag above cap fails closed.
	_, err = tools.ResolveArtifactsHardCap(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "artifact") ||
		(!strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute")) {
		t.Fatalf("over-cap flag error should mention artifact / maximum / bound: %v", err)
	}

	// Env above cap fails closed.
	_, err = tools.ResolveArtifactsHardCap("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}

	// Absurd multi-thousand values fail closed.
	_, err = tools.ResolveArtifactsHardCap(absurd, "")
	if err == nil {
		t.Fatal("absurd hard cap must fail closed under AbsoluteMax")
	}

	// Flag under cap wins even when env is over cap.
	n, err = tools.ResolveArtifactsHardCap(strconv.Itoa(jenkins.DefaultArtifactsHardCap), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if n != jenkins.DefaultArtifactsHardCap {
		t.Fatalf("got %d", n)
	}
	// Flag over cap fails even when env is sane.
	_, err = tools.ResolveArtifactsHardCap(overFlag, strconv.Itoa(jenkins.DefaultArtifactsHardCap))
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

func TestResolveArtifactsHardCap_EnvName(t *testing.T) {
	t.Parallel()
	if tools.EnvArtifactsHardCap != "JENKINS_MCP_ARTIFACTS_HARD_CAP" {
		t.Fatalf("env name drift: %q", tools.EnvArtifactsHardCap)
	}
}

// Wave 42: SetArtifactsHardCap applies resolved value used by list filter path.
func TestSetArtifactsHardCap_AppliesLiveCap(t *testing.T) {
	// Not parallel: mutates package-level artifactsHardCap.
	prev := tools.ArtifactsHardCap()
	defer tools.SetArtifactsHardCap(prev)

	tools.SetArtifactsHardCap(800)
	if tools.ArtifactsHardCap() != 800 {
		t.Fatalf("set 800: got %d", tools.ArtifactsHardCap())
	}
	tools.SetArtifactsHardCap(0) // non-positive → default
	if tools.ArtifactsHardCap() != jenkins.DefaultArtifactsHardCap {
		t.Fatalf("set 0: got %d want default %d", tools.ArtifactsHardCap(), jenkins.DefaultArtifactsHardCap)
	}
	// Belt-and-suspenders: oversize clamped (resolve should already reject).
	tools.SetArtifactsHardCap(jenkins.AbsoluteMaxArtifactsHardCap + 50)
	if tools.ArtifactsHardCap() != jenkins.AbsoluteMaxArtifactsHardCap {
		t.Fatalf("oversize set: got %d want absolute %d", tools.ArtifactsHardCap(), jenkins.AbsoluteMaxArtifactsHardCap)
	}
}
