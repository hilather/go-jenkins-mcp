package tools_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// Wave 41: ResolveListJobsCollectMaxPages precedence default → env → flag (flag wins).
func TestResolveListJobsCollectMaxPages_Precedence(t *testing.T) {
	t.Parallel()

	n, err := tools.ResolveListJobsCollectMaxPages("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != tools.DefaultListJobsCollectMaxPages {
		t.Fatalf("default: got %d want %d", n, tools.DefaultListJobsCollectMaxPages)
	}

	n, err = tools.ResolveListJobsCollectMaxPages("", "100")
	if err != nil {
		t.Fatal(err)
	}
	if n != 100 {
		t.Fatalf("env: got %d want 100", n)
	}

	n, err = tools.ResolveListJobsCollectMaxPages("75", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 75 {
		t.Fatalf("flag: got %d want 75", n)
	}

	// Flag wins over env.
	n, err = tools.ResolveListJobsCollectMaxPages("60", "150")
	if err != nil {
		t.Fatal(err)
	}
	if n != 60 {
		t.Fatalf("flag wins: got %d want 60", n)
	}

	// Whitespace treated as unset.
	n, err = tools.ResolveListJobsCollectMaxPages("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if n != tools.DefaultListJobsCollectMaxPages {
		t.Fatalf("whitespace: got %d", n)
	}
}

func TestResolveListJobsCollectMaxPages_ZeroMeansDefault(t *testing.T) {
	t.Parallel()
	n, err := tools.ResolveListJobsCollectMaxPages("0", "100")
	if err != nil {
		t.Fatal(err)
	}
	// Explicit flag "0" wins and means default (not keep env).
	if n != tools.DefaultListJobsCollectMaxPages {
		t.Fatalf("flag 0: got %d want default %d", n, tools.DefaultListJobsCollectMaxPages)
	}
	n, err = tools.ResolveListJobsCollectMaxPages("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != tools.DefaultListJobsCollectMaxPages {
		t.Fatalf("env 0: got %d", n)
	}
}

func TestResolveListJobsCollectMaxPages_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-number"},
		{"bad flag", "50pages", ""},
		{"negative env", "", "-1"},
		{"negative flag", "-10", "50"},
		{"float", "", "1.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tools.ResolveListJobsCollectMaxPages(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "collect") && !strings.Contains(msg, "invalid") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// Wave 41: absolute process fail-closed ceiling (AbsoluteMaxListJobsCollectMaxPages).
func TestResolveListJobsCollectMaxPages_AbsoluteCap(t *testing.T) {
	t.Parallel()
	capStr := strconv.Itoa(tools.AbsoluteMaxListJobsCollectMaxPages)
	overFlag := strconv.Itoa(tools.AbsoluteMaxListJobsCollectMaxPages + 1)
	overEnv := strconv.Itoa(tools.AbsoluteMaxListJobsCollectMaxPages * 2)
	absurd := "10000"

	// At absolute cap: ok.
	n, err := tools.ResolveListJobsCollectMaxPages(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if n != tools.AbsoluteMaxListJobsCollectMaxPages {
		t.Fatalf("at cap: got %d want %d", n, tools.AbsoluteMaxListJobsCollectMaxPages)
	}
	n, err = tools.ResolveListJobsCollectMaxPages("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if n != tools.AbsoluteMaxListJobsCollectMaxPages {
		t.Fatalf("at cap env: got %d", n)
	}

	// Default under absolute cap.
	n, err = tools.ResolveListJobsCollectMaxPages("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != tools.DefaultListJobsCollectMaxPages {
		t.Fatalf("default: got %d want %d", n, tools.DefaultListJobsCollectMaxPages)
	}
	if n > tools.AbsoluteMaxListJobsCollectMaxPages {
		t.Fatalf("default %d exceeds absolute max %d", n, tools.AbsoluteMaxListJobsCollectMaxPages)
	}

	// Flag above cap fails closed.
	_, err = tools.ResolveListJobsCollectMaxPages(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "collect") ||
		(!strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute")) {
		t.Fatalf("over-cap flag error should mention collect / maximum / bound: %v", err)
	}

	// Env above cap fails closed.
	_, err = tools.ResolveListJobsCollectMaxPages("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}

	// Absurd multi-thousand page values fail closed.
	_, err = tools.ResolveListJobsCollectMaxPages(absurd, "")
	if err == nil {
		t.Fatal("absurd collect max pages must fail closed under AbsoluteMax")
	}

	// Flag under cap wins even when env is over cap.
	n, err = tools.ResolveListJobsCollectMaxPages(strconv.Itoa(tools.DefaultListJobsCollectMaxPages), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if n != tools.DefaultListJobsCollectMaxPages {
		t.Fatalf("got %d", n)
	}
	// Flag over cap fails even when env is sane.
	_, err = tools.ResolveListJobsCollectMaxPages(overFlag, strconv.Itoa(tools.DefaultListJobsCollectMaxPages))
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

func TestResolveListJobsCollectMaxPages_EnvName(t *testing.T) {
	t.Parallel()
	if tools.EnvListJobsCollectMaxPages != "JENKINS_MCP_LIST_JOBS_COLLECT_MAX_PAGES" {
		t.Fatalf("env name drift: %q", tools.EnvListJobsCollectMaxPages)
	}
}

// Wave 41: SetListJobsCollectMaxPages applies resolved value used by collect path.
func TestSetListJobsCollectMaxPages_AppliesLiveCap(t *testing.T) {
	// Not parallel: mutates package-level maxJobsCollectPages.
	prev := tools.ListJobsCollectMaxPages()
	defer tools.SetListJobsCollectMaxPages(prev)

	tools.SetListJobsCollectMaxPages(1)
	if tools.ListJobsCollectMaxPages() != 1 {
		t.Fatalf("set 1: got %d", tools.ListJobsCollectMaxPages())
	}
	tools.SetListJobsCollectMaxPages(0) // non-positive → default
	if tools.ListJobsCollectMaxPages() != tools.DefaultListJobsCollectMaxPages {
		t.Fatalf("set 0: got %d want default %d", tools.ListJobsCollectMaxPages(), tools.DefaultListJobsCollectMaxPages)
	}
	// Belt-and-suspenders: oversize clamped (resolve should already reject).
	tools.SetListJobsCollectMaxPages(tools.AbsoluteMaxListJobsCollectMaxPages + 50)
	if tools.ListJobsCollectMaxPages() != tools.AbsoluteMaxListJobsCollectMaxPages {
		t.Fatalf("oversize set: got %d want absolute %d", tools.ListJobsCollectMaxPages(), tools.AbsoluteMaxListJobsCollectMaxPages)
	}
}
