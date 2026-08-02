package tools_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

// Wave 43: ResolveArtifactsListBodyBytes precedence default → env → flag (flag wins).
func TestResolveArtifactsListBodyBytes_Precedence(t *testing.T) {
	t.Parallel()

	n, err := tools.ResolveArtifactsListBodyBytes("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultArtifactListBodyBytes {
		t.Fatalf("default: got %d want %d", n, jenkins.DefaultArtifactListBodyBytes)
	}

	n, err = tools.ResolveArtifactsListBodyBytes("", "4194304") // 4 MiB
	if err != nil {
		t.Fatal(err)
	}
	if n != 4<<20 {
		t.Fatalf("env: got %d want 4MiB", n)
	}

	n, err = tools.ResolveArtifactsListBodyBytes("3145728", "") // 3 MiB
	if err != nil {
		t.Fatal(err)
	}
	if n != 3<<20 {
		t.Fatalf("flag: got %d want 3MiB", n)
	}

	// Flag wins over env.
	n, err = tools.ResolveArtifactsListBodyBytes("2097152", "4194304")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2<<20 {
		t.Fatalf("flag wins: got %d want 2MiB", n)
	}

	// Whitespace treated as unset.
	n, err = tools.ResolveArtifactsListBodyBytes("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultArtifactListBodyBytes {
		t.Fatalf("whitespace: got %d", n)
	}
}

func TestResolveArtifactsListBodyBytes_ZeroMeansDefault(t *testing.T) {
	t.Parallel()
	n, err := tools.ResolveArtifactsListBodyBytes("0", "4194304")
	if err != nil {
		t.Fatal(err)
	}
	// Explicit flag "0" wins and means default (not keep env).
	if n != jenkins.DefaultArtifactListBodyBytes {
		t.Fatalf("flag 0: got %d want default %d", n, jenkins.DefaultArtifactListBodyBytes)
	}
	n, err = tools.ResolveArtifactsListBodyBytes("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultArtifactListBodyBytes {
		t.Fatalf("env 0: got %d", n)
	}
}

func TestResolveArtifactsListBodyBytes_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-number"},
		{"bad flag", "2MiB", ""},
		{"negative env", "", "-1"},
		{"negative flag", "-10", "2097152"},
		{"float", "", "1.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tools.ResolveArtifactsListBodyBytes(tc.flag, tc.env)
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

// Wave 43: absolute process fail-closed ceiling (AbsoluteMaxArtifactListBodyBytes).
func TestResolveArtifactsListBodyBytes_AbsoluteCap(t *testing.T) {
	t.Parallel()
	capStr := strconv.Itoa(jenkins.AbsoluteMaxArtifactListBodyBytes)
	overFlag := strconv.Itoa(jenkins.AbsoluteMaxArtifactListBodyBytes + 1)
	overEnv := strconv.Itoa(jenkins.AbsoluteMaxArtifactListBodyBytes * 2)
	absurd := "100000000" // ~95 MiB

	// At absolute cap: ok.
	n, err := tools.ResolveArtifactsListBodyBytes(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if n != jenkins.AbsoluteMaxArtifactListBodyBytes {
		t.Fatalf("at cap: got %d want %d", n, jenkins.AbsoluteMaxArtifactListBodyBytes)
	}
	n, err = tools.ResolveArtifactsListBodyBytes("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if n != jenkins.AbsoluteMaxArtifactListBodyBytes {
		t.Fatalf("at cap env: got %d", n)
	}

	// Default under absolute cap.
	n, err = tools.ResolveArtifactsListBodyBytes("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultArtifactListBodyBytes {
		t.Fatalf("default: got %d want %d", n, jenkins.DefaultArtifactListBodyBytes)
	}
	if n > jenkins.AbsoluteMaxArtifactListBodyBytes {
		t.Fatalf("default %d exceeds absolute max %d", n, jenkins.AbsoluteMaxArtifactListBodyBytes)
	}

	// Flag above cap fails closed.
	_, err = tools.ResolveArtifactsListBodyBytes(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "artifact") ||
		(!strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute")) {
		t.Fatalf("over-cap flag error should mention artifact / maximum / bound: %v", err)
	}

	// Env above cap fails closed.
	_, err = tools.ResolveArtifactsListBodyBytes("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}

	// Absurd multi-MiB values fail closed.
	_, err = tools.ResolveArtifactsListBodyBytes(absurd, "")
	if err == nil {
		t.Fatal("absurd body bytes must fail closed under AbsoluteMax")
	}

	// Flag under cap wins even when env is over cap.
	n, err = tools.ResolveArtifactsListBodyBytes(strconv.Itoa(jenkins.DefaultArtifactListBodyBytes), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if n != jenkins.DefaultArtifactListBodyBytes {
		t.Fatalf("got %d", n)
	}
	// Flag over cap fails even when env is sane.
	_, err = tools.ResolveArtifactsListBodyBytes(overFlag, strconv.Itoa(jenkins.DefaultArtifactListBodyBytes))
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

func TestResolveArtifactsListBodyBytes_EnvName(t *testing.T) {
	t.Parallel()
	if tools.EnvArtifactsListBodyBytes != "JENKINS_MCP_ARTIFACTS_LIST_BODY_BYTES" {
		t.Fatalf("env name drift: %q", tools.EnvArtifactsListBodyBytes)
	}
}

// Wave 43: SetArtifactListBodyBytes applies resolved value used by ListArtifacts.
func TestSetArtifactListBodyBytes_AppliesLiveBound(t *testing.T) {
	// Not parallel: mutates package-level artifactListBodyBytes.
	prev := jenkins.ArtifactListBodyBytes()
	defer jenkins.SetArtifactListBodyBytes(prev)

	jenkins.SetArtifactListBodyBytes(4 << 20)
	if jenkins.ArtifactListBodyBytes() != 4<<20 {
		t.Fatalf("set 4MiB: got %d", jenkins.ArtifactListBodyBytes())
	}
	jenkins.SetArtifactListBodyBytes(0) // non-positive → default
	if jenkins.ArtifactListBodyBytes() != jenkins.DefaultArtifactListBodyBytes {
		t.Fatalf("set 0: got %d want default %d", jenkins.ArtifactListBodyBytes(), jenkins.DefaultArtifactListBodyBytes)
	}
	// Belt-and-suspenders: oversize clamped (resolve should already reject).
	jenkins.SetArtifactListBodyBytes(jenkins.AbsoluteMaxArtifactListBodyBytes + 1024)
	if jenkins.ArtifactListBodyBytes() != jenkins.AbsoluteMaxArtifactListBodyBytes {
		t.Fatalf("oversize set: got %d want absolute %d", jenkins.ArtifactListBodyBytes(), jenkins.AbsoluteMaxArtifactListBodyBytes)
	}
}
