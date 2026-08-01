package tools_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// Wave 42: shared ResolveCollectMaxPages precedence default → env → flag.
func TestResolveCollectMaxPages_Precedence(t *testing.T) {
	t.Parallel()
	const def, abs = 50, 200
	n, err := tools.ResolveCollectMaxPages("", "", def, abs, "ENV", "--flag", "shared")
	if err != nil {
		t.Fatal(err)
	}
	if n != def {
		t.Fatalf("default: got %d want %d", n, def)
	}
	n, err = tools.ResolveCollectMaxPages("", "100", def, abs, "ENV", "--flag", "shared")
	if err != nil || n != 100 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveCollectMaxPages("75", "150", def, abs, "ENV", "--flag", "shared")
	if err != nil || n != 75 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveCollectMaxPages("0", "100", def, abs, "ENV", "--flag", "shared")
	if err != nil || n != def {
		t.Fatalf("flag 0 → default: n=%d err=%v", n, err)
	}
}

func TestResolveCollectMaxPages_FailClosed(t *testing.T) {
	t.Parallel()
	const def, abs = 50, 200
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "nope"},
		{"negative", "-1", ""},
		{"over abs flag", "201", ""},
		{"over abs env", "", "999"},
		{"float", "", "1.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tools.ResolveCollectMaxPages(tc.flag, tc.env, def, abs, "ENV_X", "--x", "shared")
			if err == nil {
				t.Fatal("expected error")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "collect") && !strings.Contains(msg, "invalid") {
				t.Fatalf("unexpected: %v", err)
			}
		})
	}
	// At absolute cap: ok.
	n, err := tools.ResolveCollectMaxPages(strconv.Itoa(abs), "", def, abs, "ENV", "--flag", "shared")
	if err != nil || n != abs {
		t.Fatalf("at cap: n=%d err=%v", n, err)
	}
}

// Wave 42: ResolveNodesCollectMaxPages + SetNodesCollectMaxPages.
func TestResolveNodesCollectMaxPages_PrecedenceAndSet(t *testing.T) {
	// Not fully parallel: Set mutates package var.
	n, err := tools.ResolveNodesCollectMaxPages("", "")
	if err != nil || n != tools.DefaultNodesCollectMaxPages {
		t.Fatalf("default: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveNodesCollectMaxPages("60", "150")
	if err != nil || n != 60 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveNodesCollectMaxPages("", "100")
	if err != nil || n != 100 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	_, err = tools.ResolveNodesCollectMaxPages(strconv.Itoa(tools.AbsoluteMaxNodesCollectMaxPages+1), "")
	if err == nil {
		t.Fatal("over absolute must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "collect") ||
		(!strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute")) {
		t.Fatalf("over-cap error: %v", err)
	}
	if tools.EnvNodesCollectMaxPages != "JENKINS_MCP_NODES_COLLECT_MAX_PAGES" {
		t.Fatalf("env drift: %q", tools.EnvNodesCollectMaxPages)
	}

	prev := tools.NodesCollectMaxPages()
	defer tools.SetNodesCollectMaxPages(prev)
	tools.SetNodesCollectMaxPages(1)
	if tools.NodesCollectMaxPages() != 1 {
		t.Fatalf("set 1: got %d", tools.NodesCollectMaxPages())
	}
	tools.SetNodesCollectMaxPages(0)
	if tools.NodesCollectMaxPages() != tools.DefaultNodesCollectMaxPages {
		t.Fatalf("set 0 → default: got %d", tools.NodesCollectMaxPages())
	}
	tools.SetNodesCollectMaxPages(tools.AbsoluteMaxNodesCollectMaxPages + 50)
	if tools.NodesCollectMaxPages() != tools.AbsoluteMaxNodesCollectMaxPages {
		t.Fatalf("oversize clamp: got %d", tools.NodesCollectMaxPages())
	}
}

// Wave 42: ResolveViewsCollectMaxPages + SetViewsCollectMaxPages.
func TestResolveViewsCollectMaxPages_PrecedenceAndSet(t *testing.T) {
	n, err := tools.ResolveViewsCollectMaxPages("", "")
	if err != nil || n != tools.DefaultViewsCollectMaxPages {
		t.Fatalf("default: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveViewsCollectMaxPages("55", "180")
	if err != nil || n != 55 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveViewsCollectMaxPages("", "90")
	if err != nil || n != 90 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	_, err = tools.ResolveViewsCollectMaxPages("", "nope")
	if err == nil {
		t.Fatal("invalid env must fail closed")
	}
	if !strings.Contains(err.Error(), tools.EnvViewsCollectMaxPages) && !strings.Contains(err.Error(), "collect") {
		t.Fatalf("error should name source: %v", err)
	}
	_, err = tools.ResolveViewsCollectMaxPages(strconv.Itoa(tools.AbsoluteMaxViewsCollectMaxPages+1), "")
	if err == nil {
		t.Fatal("over absolute must fail closed")
	}
	if tools.EnvViewsCollectMaxPages != "JENKINS_MCP_VIEWS_COLLECT_MAX_PAGES" {
		t.Fatalf("env drift: %q", tools.EnvViewsCollectMaxPages)
	}

	prev := tools.ViewsCollectMaxPages()
	defer tools.SetViewsCollectMaxPages(prev)
	tools.SetViewsCollectMaxPages(1)
	if tools.ViewsCollectMaxPages() != 1 {
		t.Fatalf("set 1: got %d", tools.ViewsCollectMaxPages())
	}
	tools.SetViewsCollectMaxPages(0)
	if tools.ViewsCollectMaxPages() != tools.DefaultViewsCollectMaxPages {
		t.Fatalf("set 0 → default: got %d", tools.ViewsCollectMaxPages())
	}
	tools.SetViewsCollectMaxPages(tools.AbsoluteMaxViewsCollectMaxPages + 10)
	if tools.ViewsCollectMaxPages() != tools.AbsoluteMaxViewsCollectMaxPages {
		t.Fatalf("oversize clamp: got %d", tools.ViewsCollectMaxPages())
	}
}
