package mcpserver_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
)

// Wave 44 Track C: ResolveHTTPMaxBodyBytes precedence default → env → flag (flag wins).
func TestResolveHTTPMaxBodyBytes_Precedence(t *testing.T) {
	t.Parallel()

	n, err := mcpserver.ResolveHTTPMaxBodyBytes("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != mcpserver.DefaultMaxBodyBytes {
		t.Fatalf("default: got %d want %d", n, mcpserver.DefaultMaxBodyBytes)
	}

	n, err = mcpserver.ResolveHTTPMaxBodyBytes("", "8388608") // 8 MiB
	if err != nil {
		t.Fatal(err)
	}
	if n != 8<<20 {
		t.Fatalf("env: got %d want 8MiB", n)
	}

	n, err = mcpserver.ResolveHTTPMaxBodyBytes("6291456", "") // 6 MiB
	if err != nil {
		t.Fatal(err)
	}
	if n != 6<<20 {
		t.Fatalf("flag: got %d want 6MiB", n)
	}

	// Flag wins over env.
	n, err = mcpserver.ResolveHTTPMaxBodyBytes("2097152", "8388608")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2<<20 {
		t.Fatalf("flag wins: got %d want 2MiB", n)
	}

	// Whitespace treated as unset.
	n, err = mcpserver.ResolveHTTPMaxBodyBytes("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if n != mcpserver.DefaultMaxBodyBytes {
		t.Fatalf("whitespace: got %d", n)
	}
}

func TestResolveHTTPMaxBodyBytes_ZeroMeansDefault(t *testing.T) {
	t.Parallel()
	n, err := mcpserver.ResolveHTTPMaxBodyBytes("0", "8388608")
	if err != nil {
		t.Fatal(err)
	}
	// Explicit flag "0" wins and means default (not keep env).
	if n != mcpserver.DefaultMaxBodyBytes {
		t.Fatalf("flag 0: got %d want default %d", n, mcpserver.DefaultMaxBodyBytes)
	}
	n, err = mcpserver.ResolveHTTPMaxBodyBytes("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != mcpserver.DefaultMaxBodyBytes {
		t.Fatalf("env 0: got %d", n)
	}
}

func TestResolveHTTPMaxBodyBytes_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-number"},
		{"bad flag", "2MiB", ""},
		{"negative env", "", "-1"},
		{"negative flag", "-10", "4194304"},
		{"float", "", "1.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := mcpserver.ResolveHTTPMaxBodyBytes(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "http") && !strings.Contains(msg, "invalid") && !strings.Contains(msg, "body") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// Wave 44 Track C: absolute process fail-closed ceiling (AbsoluteMaxBodyBytes).
func TestResolveHTTPMaxBodyBytes_AbsoluteCap(t *testing.T) {
	t.Parallel()
	capStr := strconv.FormatInt(mcpserver.AbsoluteMaxBodyBytes, 10)
	overFlag := strconv.FormatInt(mcpserver.AbsoluteMaxBodyBytes+1, 10)
	overEnv := strconv.FormatInt(mcpserver.AbsoluteMaxBodyBytes*2, 10)
	absurd := "1073741824" // 1 GiB

	// At absolute cap: ok.
	n, err := mcpserver.ResolveHTTPMaxBodyBytes(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if n != mcpserver.AbsoluteMaxBodyBytes {
		t.Fatalf("at cap: got %d want %d", n, mcpserver.AbsoluteMaxBodyBytes)
	}
	n, err = mcpserver.ResolveHTTPMaxBodyBytes("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if n != mcpserver.AbsoluteMaxBodyBytes {
		t.Fatalf("at cap env: got %d", n)
	}

	// Default under absolute cap.
	n, err = mcpserver.ResolveHTTPMaxBodyBytes("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != mcpserver.DefaultMaxBodyBytes {
		t.Fatalf("default: got %d want %d", n, mcpserver.DefaultMaxBodyBytes)
	}
	if n > mcpserver.AbsoluteMaxBodyBytes {
		t.Fatalf("default %d exceeds absolute max %d", n, mcpserver.AbsoluteMaxBodyBytes)
	}

	// Flag above cap fails closed.
	_, err = mcpserver.ResolveHTTPMaxBodyBytes(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "body") ||
		(!strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute")) {
		t.Fatalf("over-cap flag error should mention body / maximum / bound: %v", err)
	}
	// Non-secret: must not look like a credential dump.
	if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
		t.Fatalf("error must not mention secrets: %v", err)
	}

	// Env above cap fails closed.
	_, err = mcpserver.ResolveHTTPMaxBodyBytes("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}

	// Absurd multi-GB values fail closed.
	_, err = mcpserver.ResolveHTTPMaxBodyBytes(absurd, "")
	if err == nil {
		t.Fatal("absurd body bytes must fail closed under AbsoluteMax")
	}

	// Flag under cap wins even when env is over cap.
	n, err = mcpserver.ResolveHTTPMaxBodyBytes(strconv.FormatInt(mcpserver.DefaultMaxBodyBytes, 10), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if n != mcpserver.DefaultMaxBodyBytes {
		t.Fatalf("got %d", n)
	}
	// Flag over cap fails even when env is sane.
	_, err = mcpserver.ResolveHTTPMaxBodyBytes(overFlag, strconv.FormatInt(mcpserver.DefaultMaxBodyBytes, 10))
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

func TestResolveHTTPMaxBodyBytes_EnvName(t *testing.T) {
	t.Parallel()
	if mcpserver.EnvHTTPMaxBodyBytes != "JENKINS_MCP_HTTP_MAX_BODY_BYTES" {
		t.Fatalf("env name drift: %q", mcpserver.EnvHTTPMaxBodyBytes)
	}
	if mcpserver.AbsoluteMaxBodyBytes != 16<<20 {
		t.Fatalf("absolute max drift: %d want 16MiB", mcpserver.AbsoluteMaxBodyBytes)
	}
	if mcpserver.DefaultMaxBodyBytes != 4<<20 {
		t.Fatalf("default drift: %d want 4MiB", mcpserver.DefaultMaxBodyBytes)
	}
}

// Wave 44: ValidateHTTPConfig rejects MaxBodyBytes above AbsoluteMaxBodyBytes
// (defense-in-depth for library callers bypassing ResolveHTTPMaxBodyBytes).
func TestValidateHTTPConfig_MaxBodyBytesAbsolute(t *testing.T) {
	t.Parallel()
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.MaxBodyBytes = mcpserver.AbsoluteMaxBodyBytes + 1
	if err := mcpserver.ValidateHTTPConfig(cfg); err == nil {
		t.Fatal("MaxBodyBytes above AbsoluteMaxBodyBytes must fail closed")
	}
	cfg.MaxBodyBytes = mcpserver.AbsoluteMaxBodyBytes
	if err := mcpserver.ValidateHTTPConfig(cfg); err != nil {
		t.Fatalf("at absolute cap must accept: %v", err)
	}
	cfg.MaxBodyBytes = 0 // default
	if err := mcpserver.ValidateHTTPConfig(cfg); err != nil {
		t.Fatalf("zero MaxBodyBytes must accept: %v", err)
	}
}
