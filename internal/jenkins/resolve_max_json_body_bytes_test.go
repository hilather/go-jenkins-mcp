package jenkins_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// Wave 46 Track A: ResolveMaxJSONBodyBytes precedence default → env → flag (flag wins).
func TestResolveMaxJSONBodyBytes_Precedence(t *testing.T) {
	t.Parallel()

	n, err := jenkins.ResolveMaxJSONBodyBytes("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultMaxJSONBodyBytes {
		t.Fatalf("default: got %d want %d", n, jenkins.DefaultMaxJSONBodyBytes)
	}

	n, err = jenkins.ResolveMaxJSONBodyBytes("", "67108864") // 64 MiB
	if err != nil {
		t.Fatal(err)
	}
	if n != 64<<20 {
		t.Fatalf("env: got %d want 64MiB", n)
	}

	n, err = jenkins.ResolveMaxJSONBodyBytes("50331648", "") // 48 MiB
	if err != nil {
		t.Fatal(err)
	}
	if n != 48<<20 {
		t.Fatalf("flag: got %d want 48MiB", n)
	}

	// Flag wins over env.
	n, err = jenkins.ResolveMaxJSONBodyBytes("33554432", "67108864")
	if err != nil {
		t.Fatal(err)
	}
	if n != 32<<20 {
		t.Fatalf("flag wins: got %d want 32MiB", n)
	}

	// Whitespace treated as unset.
	n, err = jenkins.ResolveMaxJSONBodyBytes("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultMaxJSONBodyBytes {
		t.Fatalf("whitespace: got %d", n)
	}
}

func TestResolveMaxJSONBodyBytes_ZeroMeansDefault(t *testing.T) {
	t.Parallel()
	n, err := jenkins.ResolveMaxJSONBodyBytes("0", "67108864")
	if err != nil {
		t.Fatal(err)
	}
	// Explicit flag "0" wins and means default (not keep env).
	if n != jenkins.DefaultMaxJSONBodyBytes {
		t.Fatalf("flag 0: got %d want default %d", n, jenkins.DefaultMaxJSONBodyBytes)
	}
	n, err = jenkins.ResolveMaxJSONBodyBytes("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultMaxJSONBodyBytes {
		t.Fatalf("env 0: got %d", n)
	}
}

func TestResolveMaxJSONBodyBytes_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-number"},
		{"bad flag", "32MiB", ""},
		{"negative env", "", "-1"},
		{"negative flag", "-10", "33554432"},
		{"float", "", "1.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := jenkins.ResolveMaxJSONBodyBytes(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "json") && !strings.Contains(msg, "invalid") && !strings.Contains(msg, "body") {
				t.Fatalf("unexpected error: %v", err)
			}
			// Non-secret: must not look like a credential dump.
			if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
				t.Fatalf("error must not mention secrets: %v", err)
			}
		})
	}
}

// Wave 46 Track A: absolute process fail-closed ceiling (AbsoluteMaxJSONBodyBytes).
func TestResolveMaxJSONBodyBytes_AbsoluteCap(t *testing.T) {
	t.Parallel()
	capStr := strconv.FormatInt(jenkins.AbsoluteMaxJSONBodyBytes, 10)
	overFlag := strconv.FormatInt(jenkins.AbsoluteMaxJSONBodyBytes+1, 10)
	overEnv := strconv.FormatInt(jenkins.AbsoluteMaxJSONBodyBytes*2, 10)
	absurd := "1073741824" // 1 GiB

	// At absolute cap: ok.
	n, err := jenkins.ResolveMaxJSONBodyBytes(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if n != jenkins.AbsoluteMaxJSONBodyBytes {
		t.Fatalf("at cap: got %d want %d", n, jenkins.AbsoluteMaxJSONBodyBytes)
	}
	n, err = jenkins.ResolveMaxJSONBodyBytes("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if n != jenkins.AbsoluteMaxJSONBodyBytes {
		t.Fatalf("at cap env: got %d", n)
	}

	// Default under absolute cap.
	n, err = jenkins.ResolveMaxJSONBodyBytes("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultMaxJSONBodyBytes {
		t.Fatalf("default: got %d want %d", n, jenkins.DefaultMaxJSONBodyBytes)
	}
	if n > jenkins.AbsoluteMaxJSONBodyBytes {
		t.Fatalf("default %d exceeds absolute max %d", n, jenkins.AbsoluteMaxJSONBodyBytes)
	}

	// Flag above cap fails closed.
	_, err = jenkins.ResolveMaxJSONBodyBytes(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "json") ||
		(!strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute")) {
		t.Fatalf("over-cap flag error should mention json / maximum / bound: %v", err)
	}
	if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
		t.Fatalf("error must not mention secrets: %v", err)
	}

	// Env above cap fails closed.
	_, err = jenkins.ResolveMaxJSONBodyBytes("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}

	// Absurd multi-GB values fail closed.
	_, err = jenkins.ResolveMaxJSONBodyBytes(absurd, "")
	if err == nil {
		t.Fatal("absurd body bytes must fail closed under AbsoluteMax")
	}

	// Flag under cap wins even when env is over cap.
	n, err = jenkins.ResolveMaxJSONBodyBytes(strconv.FormatInt(jenkins.DefaultMaxJSONBodyBytes, 10), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if n != jenkins.DefaultMaxJSONBodyBytes {
		t.Fatalf("got %d", n)
	}
	// Flag over cap fails even when env is sane.
	_, err = jenkins.ResolveMaxJSONBodyBytes(overFlag, strconv.FormatInt(jenkins.DefaultMaxJSONBodyBytes, 10))
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

func TestResolveMaxJSONBodyBytes_EnvName(t *testing.T) {
	t.Parallel()
	if jenkins.EnvMaxJSONBodyBytes != "JENKINS_MCP_MAX_JSON_BODY_BYTES" {
		t.Fatalf("env name drift: %q", jenkins.EnvMaxJSONBodyBytes)
	}
	if jenkins.AbsoluteMaxJSONBodyBytes != 128<<20 {
		t.Fatalf("absolute max drift: %d want 128MiB", jenkins.AbsoluteMaxJSONBodyBytes)
	}
	if jenkins.DefaultMaxJSONBodyBytes != 32<<20 {
		t.Fatalf("default drift: %d want 32MiB", jenkins.DefaultMaxJSONBodyBytes)
	}
	if jenkins.AbsoluteMaxJSONBodyBytes <= jenkins.DefaultMaxJSONBodyBytes {
		t.Fatalf("absolute %d must exceed default %d",
			jenkins.AbsoluteMaxJSONBodyBytes, jenkins.DefaultMaxJSONBodyBytes)
	}
	// Exported defaults for operator_caps Track B.
	if jenkins.DefaultMaxRetries != 2 {
		t.Fatalf("DefaultMaxRetries drift: %d", jenkins.DefaultMaxRetries)
	}
	if jenkins.DefaultCircuitFailureThreshold != 5 {
		t.Fatalf("DefaultCircuitFailureThreshold drift: %d", jenkins.DefaultCircuitFailureThreshold)
	}
	cfg := jenkins.DefaultResilienceConfig()
	if cfg.MaxJSONBodyBytes != jenkins.DefaultMaxJSONBodyBytes {
		t.Fatalf("DefaultResilienceConfig.MaxJSONBodyBytes=%d", cfg.MaxJSONBodyBytes)
	}
	if cfg.MaxRetries != jenkins.DefaultMaxRetries {
		t.Fatalf("DefaultResilienceConfig.MaxRetries=%d", cfg.MaxRetries)
	}
	if cfg.CircuitFailureThreshold != jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("DefaultResilienceConfig.CircuitFailureThreshold=%d", cfg.CircuitFailureThreshold)
	}
}

// Wave 46 Track A: normalizeResilienceConfig clamps oversize MaxJSONBodyBytes
// (defense-in-depth for library callers bypassing ResolveMaxJSONBodyBytes).
func TestNormalizeResilienceConfig_MaxJSONBodyBytesAbsoluteClamp(t *testing.T) {
	t.Parallel()
	// NewResilience applies normalize; absurd oversize must clamp, not install multi-GB.
	r := jenkins.NewResilience(jenkins.ResilienceConfig{
		MaxJSONBodyBytes: jenkins.AbsoluteMaxJSONBodyBytes + (1 << 30),
	})
	got := r.Config().MaxJSONBodyBytes
	if got != jenkins.AbsoluteMaxJSONBodyBytes {
		t.Fatalf("oversize clamp: got %d want absolute %d", got, jenkins.AbsoluteMaxJSONBodyBytes)
	}
	// At cap preserved.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		MaxJSONBodyBytes: jenkins.AbsoluteMaxJSONBodyBytes,
	})
	if r.Config().MaxJSONBodyBytes != jenkins.AbsoluteMaxJSONBodyBytes {
		t.Fatalf("at cap: got %d", r.Config().MaxJSONBodyBytes)
	}
	// Non-positive → default.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{MaxJSONBodyBytes: 0})
	if r.Config().MaxJSONBodyBytes != jenkins.DefaultMaxJSONBodyBytes {
		t.Fatalf("zero → default: got %d", r.Config().MaxJSONBodyBytes)
	}
}
