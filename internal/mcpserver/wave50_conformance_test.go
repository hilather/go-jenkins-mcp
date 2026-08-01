package mcpserver

import (
	"testing"
)

// Wave 50 / KD-008 + MCP-001 conformance (Track D):
//   - Hard-assert Wave 44/45–49 Done* HTTP MaxBody still 4 MiB default / 16 MiB absolute
//   - (Wave 50 feature tracks A/B/C live in jenkins/tools/diagnostics; Streamable
//     HTTP body stays 4/16)

// TestWave50_HTTPMaxBodyBytes_Hard hard-asserts Wave 44 Track C / Wave 45–49
// retention: default 4 MiB, absolute 16 MiB fail-closed, env name, resolve
// precedence. Must remain true after Wave 50 parallel tracks merge.
func TestWave50_HTTPMaxBodyBytes_Hard(t *testing.T) {
	t.Parallel()

	if DefaultMaxBodyBytes != 4<<20 {
		t.Fatalf("DefaultMaxBodyBytes=%d want 4MiB", DefaultMaxBodyBytes)
	}
	if AbsoluteMaxBodyBytes != 16<<20 {
		t.Fatalf("AbsoluteMaxBodyBytes=%d want 16MiB", AbsoluteMaxBodyBytes)
	}
	if AbsoluteMaxBodyBytes <= DefaultMaxBodyBytes {
		t.Fatalf("absolute %d must exceed default %d", AbsoluteMaxBodyBytes, DefaultMaxBodyBytes)
	}
	if EnvHTTPMaxBodyBytes != "JENKINS_MCP_HTTP_MAX_BODY_BYTES" {
		t.Fatalf("env name drift: %q", EnvHTTPMaxBodyBytes)
	}

	cfg := DefaultHTTPConfig()
	if cfg.MaxBodyBytes != DefaultMaxBodyBytes {
		t.Fatalf("DefaultHTTPConfig.MaxBodyBytes=%d want %d", cfg.MaxBodyBytes, DefaultMaxBodyBytes)
	}

	n, err := ResolveHTTPMaxBodyBytes("", "")
	if err != nil || n != DefaultMaxBodyBytes {
		t.Fatalf("default resolve: n=%d err=%v want %d", n, err, DefaultMaxBodyBytes)
	}
	n, err = ResolveHTTPMaxBodyBytes("", "8388608")
	if err != nil || n != 8<<20 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	n, err = ResolveHTTPMaxBodyBytes("6291456", "8388608")
	if err != nil || n != 6<<20 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = ResolveHTTPMaxBodyBytes("0", "8388608")
	if err != nil || n != DefaultMaxBodyBytes {
		t.Fatalf("flag 0 → default: n=%d err=%v", n, err)
	}
	n, err = ResolveHTTPMaxBodyBytes("16777216", "")
	if err != nil || n != AbsoluteMaxBodyBytes {
		t.Fatalf("at absolute: n=%d err=%v want %d", n, err, AbsoluteMaxBodyBytes)
	}
	if _, err := ResolveHTTPMaxBodyBytes("16777217", ""); err == nil {
		t.Fatal("above AbsoluteMaxBodyBytes must fail closed")
	}
	if _, err := ResolveHTTPMaxBodyBytes("nope", ""); err == nil {
		t.Fatal("invalid parse must fail closed")
	}
}
