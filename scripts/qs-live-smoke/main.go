// Command qs-live-smoke exercises first-run MCP discovery + a secret-free RO
// Jenkins tool call against a disposable live Jenkins (free lab).
//
// Prerequisites (caller plants these):
//   - jenkins-mcp binary on BIN (default: bin/jenkins-mcp)
//   - Profile already logged in (file keyring OK via JENKINS_MCP_KEYRING_FILE)
//   - Profile id in PROFILE (default: lab)
//
// Does not print tokens. Fails if ListTools lacks jenkins_* or CallTool fails.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "qs-live-smoke FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("qs-live-smoke PASS: Initialize + ListTools + jenkins_list_jobs RO")
}

func run() error {
	root, err := findRepoRoot()
	if err != nil {
		return err
	}
	bin := os.Getenv("BIN")
	if bin == "" {
		bin = filepath.Join(root, "bin", "jenkins-mcp")
	}
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("binary missing: %s (%w)", bin, err)
	}
	profile := os.Getenv("PROFILE")
	if profile == "" {
		profile = "lab"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "serve", "--profile", profile, "--stdio", "--read-only")
	cmd.Dir = root
	// Inherit env (XDG_*, JENKINS_MCP_KEYRING_FILE, etc.)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env,
		"JENKINS_MCP_READ_ONLY=true",
		"JENKINS_MCP_NO_CACHE_MAINTENANCE=1",
	)

	transport := &mcp.CommandTransport{Command: cmd}
	client := mcp.NewClient(&mcp.Implementation{Name: "qs-live-smoke", Version: "dev"}, nil)
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = cs.Close() }()

	initRes := cs.InitializeResult()
	if initRes == nil || initRes.ServerInfo == nil {
		return fmt.Errorf("InitializeResult missing")
	}
	fmt.Printf("SUCCESS_SIGNAL: Initialize protocol=%s server=%s\n",
		initRes.ProtocolVersion, initRes.ServerInfo.Name)

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("ListTools: %w", err)
	}
	if list == nil || len(list.Tools) == 0 {
		return fmt.Errorf("ListTools empty")
	}
	var names []string
	hasJobs := false
	for _, t := range list.Tools {
		names = append(names, t.Name)
		if t.Name == "jenkins_list_jobs" || t.Name == "jenkins_get_jobs" {
			hasJobs = true
		}
		if strings.HasPrefix(t.Name, "jenkins_start") {
			return fmt.Errorf("mutation tool present under --read-only: %s", t.Name)
		}
	}
	if !hasJobs {
		return fmt.Errorf("expected jenkins_list_jobs or jenkins_get_jobs in %v", names)
	}
	fmt.Printf("SUCCESS_SIGNAL: ListTools count=%d sample=%v\n", len(names), trimNames(names, 8))

	toolName := "jenkins_list_jobs"
	if !contains(names, toolName) {
		toolName = "jenkins_get_jobs"
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: map[string]any{},
	})
	if err != nil {
		return fmt.Errorf("CallTool %s: %w", toolName, err)
	}
	payload := toolPayload(res)
	if strings.Contains(strings.ToLower(payload), "authorization") ||
		strings.Contains(payload, "Bearer ") ||
		strings.Contains(payload, "api_token") {
		return fmt.Errorf("possible secret-shaped leak in tool result")
	}
	// Expect some job-ish content from disposable lab (sample-* or mock-inv-*)
	low := strings.ToLower(payload)
	if !strings.Contains(low, "sample") && !strings.Contains(low, "mock") &&
		!strings.Contains(low, "job") && !strings.Contains(low, "name") {
		return fmt.Errorf("RO tool result missing job-like content: %s", truncate(payload, 300))
	}
	fmt.Printf("SUCCESS_SIGNAL: CallTool %s RO ok (secret-free; len=%d)\n", toolName, len(payload))
	fmt.Printf("RESULT_PREVIEW: %s\n", truncate(payload, 240))
	return nil
}

func contains(ss []string, x string) bool {
	for _, s := range ss {
		if s == x {
			return true
		}
	}
	return false
}

func trimNames(ss []string, n int) []string {
	if len(ss) <= n {
		return ss
	}
	return ss[:n]
}

func toolPayload(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			b.WriteString(t.Text)
		}
	}
	if res.StructuredContent != nil {
		b.WriteString(fmt.Sprintf("%v", res.StructuredContent))
	}
	return b.String()
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("go.mod not found from %s", wd)
}
