// Command mcpstdiosmoke is an offline MCP stdio binary host-lifecycle smoke
// (FND-006 Wave 25 + Wave 33 expansion).
//
// It starts a fixture Jenkins (httptest), spawns the real jenkins-mcp binary over
// stdio (mcp.CommandTransport), and asserts a host-lifecycle matrix (still no
// real Cursor product binary):
//
//  1. Initialize (protocol version + server name)
//  2. ListTools — RO mutations absent; sample reads present
//  3. CallTool success jenkins_get_jobs
//  4. CallTool invalid args → error, no canary leak
//  5. CallTool unknown tool → fail closed, no canary
//  6. CallTool cancel mid-flight (hanging Jenkins fixture + client cancel)
//  7. ListTools again after calls (session still healthy)
//  8. Clean shutdown; stderr/stdout canary scrub
//
// Auth uses deprecated JENKINS_MCP_AUTH bootstrap (KD-003) so headless CI does
// not require Secret Service. Pilot path remains profile + keyring login.
//
// Residual: real Cursor host / product-binary stdio CI remains open.
// Offline host-lifecycle matrix is Done* (this smoke + unit protocol matrix).
//
// Usage:
//
//	make stdio-smoke
//	BIN=bin/jenkins-mcp go run ./scripts/mcpstdiosmoke
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Declared MCP protocol versions for go-sdk v1.1.0 (ADR 0006). Keep in sync.
var declaredProtocolVersions = map[string]struct{}{
	"2025-06-18": {},
	"2025-03-26": {},
	"2024-11-05": {},
}

// Sample read-only seed tools expected under --read-only / JENKINS_MCP_READ_ONLY.
// jenkins_doctor is not asserted: serve does not always wire Doctor into Register.
var requiredReadTools = []string{
	"jenkins_get_jobs",
	"jenkins_get_job",
	"jenkins_get_build",
	"jenkins_get_nodes",
	"jenkins_get_node",
	"jenkins_list_views",
}

// Mutation tools must be omitted under read-only (POL-001).
var mutationTools = []string{
	"jenkins_start_job",
	"jenkins_stop_build",
	"jenkins_cancel_queue_item",
}

const (
	// canaryToken is the API token used for deprecated JENKINS_MCP_AUTH bootstrap.
	// It must never appear in MCP model-visible results/errors or server logs that
	// are not mere protocol wire dumps of client-supplied arguments.
	canaryToken = "CANARY_stdio_smoke_token_must_not_appear_xyz"
	// plantCanary is planted only in invalid CallTool arguments (not used as auth).
	// Model-visible tool errors must not echo it. Distinct from canaryToken so MCP
	// protocol debug lines that echo client args do not false-positive auth scrub.
	plantCanary = "CANARY_plant_invalid_arg_must_not_appear_xyz"
	smokeUser   = "smoke"
	// serverName matches mcpserver.DefaultServerName.
	serverName = "jenkins-mcp-go"
	// hangJob is a fixture job name that blocks until the HTTP request context ends.
	// Used for CallTool cancel mid-flight (mirrors tools cancel smoke patterns).
	hangJob = "slow-hang"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "stdio-smoke FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("stdio-smoke PASS: host-lifecycle matrix (Initialize + ListTools + CallTool success/invalid/unknown/cancel + ListTools + shutdown)")
}

func run() error {
	root, err := findRepoRoot()
	if err != nil {
		return err
	}

	// hangStarted signals the fixture has entered the blocking job path.
	hangStarted := make(chan struct{}, 1)
	var hangOnce sync.Once
	fix := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixtureJenkins(w, r, hangStarted, &hangOnce)
	}))
	defer fix.Close()

	bin, cleanup, err := resolveBinary(root)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}

	work, err := os.MkdirTemp("", "jenkins-mcp-stdio-smoke-*")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(work)

	xdgConfig := filepath.Join(work, "config")
	xdgData := filepath.Join(work, "data")
	xdgCache := filepath.Join(work, "cache")
	for _, d := range []string{xdgConfig, xdgData, xdgCache} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}

	// Capture server stderr for canary checks (LoggingTransport + app logs).
	var stderr strings.Builder

	cmd := exec.Command(bin,
		"serve",
		"--url", fix.URL,
		"--stdio",
		"--read-only",
		"--no-cache-maintenance",
	)
	cmd.Dir = root
	cmd.Env = childEnv(work, xdgConfig, xdgData, xdgCache)
	cmd.Stderr = &stderr

	// Host-lifecycle budget: cancel hang + several CallTools need headroom.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "jenkins-mcp-stdio-smoke-client",
		Version: "test",
	}, nil)

	transport := &mcp.CommandTransport{
		Command:           cmd,
		TerminateDuration: 3 * time.Second,
	}

	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return fmt.Errorf("MCP client Connect (binary stdio): %w\n--- server stderr ---\n%s", err, stderr.String())
	}
	defer func() { _ = cs.Close() }()

	// 1. Initialize (protocol version)
	initRes := cs.InitializeResult()
	if initRes == nil {
		return fmt.Errorf("InitializeResult is nil")
	}
	if initRes.ProtocolVersion == "" {
		return fmt.Errorf("negotiated protocol version is empty")
	}
	if _, ok := declaredProtocolVersions[initRes.ProtocolVersion]; !ok {
		return fmt.Errorf("protocol version %q not in declared set", initRes.ProtocolVersion)
	}
	if initRes.ServerInfo == nil || initRes.ServerInfo.Name != serverName {
		name := ""
		if initRes.ServerInfo != nil {
			name = initRes.ServerInfo.Name
		}
		return fmt.Errorf("ServerInfo.Name = %q, want %q", name, serverName)
	}
	fmt.Printf("PASS: Initialize protocol=%s server=%s\n", initRes.ProtocolVersion, initRes.ServerInfo.Name)

	// 2. ListTools — RO mutations absent; sample reads present
	if err := assertListToolsRO(ctx, cs); err != nil {
		return err
	}
	fmt.Println("PASS: ListTools (RO seed present; mutations omitted)")

	// 3. CallTool success jenkins_get_jobs
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_jobs",
		Arguments: map[string]any{},
	})
	if err != nil {
		return fmt.Errorf("CallTool transport: %w", err)
	}
	if res == nil || res.IsError {
		return fmt.Errorf("jenkins_get_jobs failed: isError=%v text=%q",
			res != nil && res.IsError, toolErrorText(res))
	}
	payload := toolTextAndStructured(res)
	if !strings.Contains(payload, "demo") {
		return fmt.Errorf("expected demo job in CallTool result, got %s", truncate(payload, 400))
	}
	if err := assertNoCanaries("CallTool jenkins_get_jobs result", payload); err != nil {
		return err
	}
	fmt.Println("PASS: CallTool jenkins_get_jobs (fixture job present; no canary)")

	// 4. CallTool invalid args → error, no canary leak
	// Typed-ref invalid_argument: absolute job URL rejected before Jenkins I/O.
	// Plant a distinct secret-shaped token in the bad URL (not the auth canary).
	resInv, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_get_job",
		Arguments: map[string]any{
			"name": "https://jenkins.example/job/x?token=" + plantCanary,
		},
	})
	if err != nil {
		// Transport-level error is also fail-closed if no canary.
		if err := assertNoCanaries("CallTool invalid-args transport err", err.Error()); err != nil {
			return err
		}
		fmt.Println("PASS: CallTool invalid args (transport error; no canary)")
	} else {
		if resInv == nil || !resInv.IsError {
			return fmt.Errorf("want tool error for invalid job URL, got %#v", resInv)
		}
		text := toolErrorText(resInv)
		low := strings.ToLower(text)
		if !strings.Contains(low, "invalid") && !strings.Contains(text, "invalid_argument") {
			return fmt.Errorf("expected invalid_argument-ish error, got %q", text)
		}
		// Model-visible error must not echo the planted secret or the auth token.
		if err := assertNoCanaries("CallTool invalid-args tool error", text); err != nil {
			return err
		}
		if strings.Contains(text, "Bearer ") || strings.Contains(text, "api_token") {
			return fmt.Errorf("credential-shaped leak in invalid-args error: %q", text)
		}
		fmt.Println("PASS: CallTool invalid args (tool error; no canary)")
	}

	// 5. CallTool unknown tool → fail closed, no canary
	resUnk, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_definitely_not_a_tool",
		Arguments: map[string]any{},
	})
	if err == nil {
		if resUnk != nil && resUnk.IsError {
			text := toolErrorText(resUnk)
			low := strings.ToLower(text)
			if !strings.Contains(low, "unknown") && !strings.Contains(low, "not found") &&
				!strings.Contains(low, "invalid") {
				return fmt.Errorf("tool error without unknown/not-found marker: %q", text)
			}
			if err := assertNoCanaries("CallTool unknown tool-error", text); err != nil {
				return err
			}
			fmt.Println("PASS: CallTool unknown tool (tool error; no canary)")
		} else {
			return fmt.Errorf("unknown tool must fail closed, got res=%#v err=nil", resUnk)
		}
	} else {
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "unknown") && !strings.Contains(low, "not found") &&
			!strings.Contains(low, "invalid") {
			return fmt.Errorf("unknown tool err = %v, want fail-closed marker", err)
		}
		if err2 := assertNoCanaries("CallTool unknown transport err", err.Error()); err2 != nil {
			return err2
		}
		fmt.Println("PASS: CallTool unknown tool (transport error; no canary)")
	}

	// 6. CallTool cancel mid-flight (hanging fixture job + client cancel)
	if err := callToolCancelMidFlight(cs, hangStarted); err != nil {
		return err
	}
	fmt.Println("PASS: CallTool cancel mid-flight (no canary)")

	// 7. ListTools again after calls (session still healthy)
	if err := assertListToolsRO(ctx, cs); err != nil {
		return fmt.Errorf("post-call ListTools (session unhealthy?): %w", err)
	}
	fmt.Println("PASS: ListTools after calls (session healthy)")

	// 8. Clean shutdown; stderr/stdout canary scrub
	if err := cs.Close(); err != nil {
		// Some SDK versions return wait errors on clean SIGTERM; treat canary as hard fail only.
		if strings.Contains(err.Error(), canaryToken) || strings.Contains(err.Error(), plantCanary) {
			return fmt.Errorf("canary in close error: %w", err)
		}
		// Soft: process exit after close is still success if protocol steps passed.
		fmt.Printf("NOTE: session close: %v\n", err)
	}
	fmt.Println("PASS: session close (stdio shutdown)")

	// Server application logs must not echo the API token canary (KD-004).
	// Note: serve may dump raw JSON-RPC on stderr (protocol wire); client-supplied
	// plant tokens in arguments can appear there — that is not an auth-token leak.
	if strings.Contains(stderr.String(), canaryToken) {
		return fmt.Errorf("auth token canary leaked on server stderr:\n%s", truncate(stderr.String(), 800))
	}
	fmt.Println("PASS: stderr auth-token canary scrub")

	return nil
}

// assertListToolsRO checks sample read tools present and mutations omitted.
func assertListToolsRO(ctx context.Context, cs *mcp.ClientSession) error {
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("ListTools: %w", err)
	}
	if list == nil || len(list.Tools) == 0 {
		return fmt.Errorf("ListTools returned no tools")
	}
	got := make(map[string]struct{}, len(list.Tools))
	for _, tool := range list.Tools {
		if tool == nil || tool.Name == "" {
			return fmt.Errorf("tool entry missing name: %#v", tool)
		}
		got[tool.Name] = struct{}{}
		if strings.Contains(tool.Name, canaryToken) || strings.Contains(tool.Description, canaryToken) ||
			strings.Contains(tool.Name, plantCanary) || strings.Contains(tool.Description, plantCanary) {
			return fmt.Errorf("canary leaked in tool metadata")
		}
	}
	for _, name := range requiredReadTools {
		if _, ok := got[name]; !ok {
			return fmt.Errorf("missing read tool %q (have %d tools)", name, len(got))
		}
	}
	for _, name := range mutationTools {
		if _, ok := got[name]; ok {
			return fmt.Errorf("mutation tool %q must be omitted under --read-only", name)
		}
	}
	return nil
}

// callToolCancelMidFlight starts jenkins_get_job against the hanging fixture,
// cancels the client CallTool context after the hang is observed, and asserts
// a cancel-related error without canary leak. Pattern mirrors
// internal/tools/cancel_smoke_test.go and mcp_protocol_matrix_test.go.
func callToolCancelMidFlight(cs *mcp.ClientSession, hangStarted <-chan struct{}) error {
	callCtx, callCancel := context.WithCancel(context.Background())
	defer callCancel()

	var (
		callWG  sync.WaitGroup
		callErr error
		callRes *mcp.CallToolResult
	)
	callWG.Add(1)
	go func() {
		defer callWG.Done()
		callRes, callErr = cs.CallTool(callCtx, &mcp.CallToolParams{
			Name: "jenkins_get_job",
			Arguments: map[string]any{
				"name": hangJob,
			},
		})
	}()

	select {
	case <-hangStarted:
		// Fixture accepted the hanging job request; cancel client CallTool.
	case <-time.After(5 * time.Second):
		callCancel()
		callWG.Wait()
		return fmt.Errorf("hanging job handler never started (cancel mid-flight not exercised)")
	}
	callCancel()
	callWG.Wait()

	// Client must surface cancel (transport err preferred; tool error also accepted).
	if callErr == nil {
		if callRes != nil && callRes.IsError {
			text := toolErrorText(callRes)
			if err := assertNoCanaries("CallTool cancel tool-error", text); err != nil {
				return err
			}
			// Tool error after cancel is acceptable only if cancel/context-shaped
			// (Wave 33 review: do not accept arbitrary non-empty tool errors).
			low := strings.ToLower(text)
			if strings.Contains(low, "cancel") || strings.Contains(low, "context") ||
				strings.Contains(low, "aborted") || strings.Contains(low, "deadline") {
				return nil
			}
		}
		return fmt.Errorf("expected cancel-related CallTool error, got res=%#v err=nil", callRes)
	}
	if !errors.Is(callErr, context.Canceled) &&
		!strings.Contains(strings.ToLower(callErr.Error()), "cancel") &&
		!errors.Is(callErr, context.DeadlineExceeded) {
		// Some SDK/stdio paths wrap cancel as connection/request failed; still fail closed
		// as long as the canary is absent and the call did not succeed with data.
		low := strings.ToLower(callErr.Error())
		if !strings.Contains(low, "context") && !strings.Contains(low, "deadline") &&
			!strings.Contains(low, "aborted") && !strings.Contains(low, "closed") &&
			!strings.Contains(low, "eof") {
			return fmt.Errorf("CallTool after cancel: %v (want cancel-related)", callErr)
		}
	}
	if err := assertNoCanaries("CallTool cancel transport err", callErr.Error()); err != nil {
		return err
	}
	if callRes != nil {
		if err := assertNoCanaries("CallTool cancel result", toolTextAndStructured(callRes)); err != nil {
			return err
		}
	}
	return nil
}

func fixtureJenkins(w http.ResponseWriter, r *http.Request, hangStarted chan<- struct{}, hangOnce *sync.Once) {
	// Auth check for whoAmI and API paths (Basic user:token).
	if u, p, ok := r.BasicAuth(); !ok || u != smokeUser || p != canaryToken {
		// Allow unauthenticated only for nothing — fail closed like Jenkins with auth.
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := r.URL.Path
	// Hang path for cancel mid-flight: /job/slow-hang/... blocks until request ctx ends.
	if strings.Contains(path, "/job/"+hangJob) {
		hangOnce.Do(func() {
			select {
			case hangStarted <- struct{}{}:
			default:
			}
		})
		// Block until client cancels the HTTP request (tool ctx → NewRequestWithContext).
		select {
		case <-r.Context().Done():
			return
		case <-time.After(30 * time.Second):
			// Safety: do not hang the smoke forever if cancel fails to propagate.
			http.Error(w, "hang timeout", http.StatusGatewayTimeout)
			return
		}
	}
	switch {
	case path == "/whoAmI/api/json":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"smoke","name":"smoke","fullName":"Smoke User","anonymous":false,"authenticated":true}`))
	case path == "/api/json" || strings.HasPrefix(path, "/api/json"):
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jobs": []map[string]any{
				{
					"name":      "demo",
					"url":       "http://example/job/demo/",
					"color":     "blue",
					"buildable": true,
				},
			},
		})
	default:
		http.NotFound(w, r)
	}
}

func resolveBinary(root string) (bin string, cleanup func(), err error) {
	if b := strings.TrimSpace(os.Getenv("BIN")); b != "" {
		if !filepath.IsAbs(b) {
			b = filepath.Join(root, b)
		}
		if st, e := os.Stat(b); e != nil || st.IsDir() {
			return "", nil, fmt.Errorf("BIN=%s is not a file", b)
		}
		return b, nil, nil
	}
	// Prefer already-built bin/jenkins-mcp when present (make stdio-smoke: build first).
	defaultBin := filepath.Join(root, "bin", "jenkins-mcp")
	if st, e := os.Stat(defaultBin); e == nil && !st.IsDir() {
		return defaultBin, nil, nil
	}
	// Build into a temp file so smoke does not require a prior make build.
	tmp, err := os.MkdirTemp("", "jenkins-mcp-stdio-bin-*")
	if err != nil {
		return "", nil, err
	}
	out := filepath.Join(tmp, "jenkins-mcp")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/jenkins-mcp")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PATH="+os.Getenv("PATH"))
	if outBytes, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(tmp)
		return "", nil, fmt.Errorf("go build ./cmd/jenkins-mcp: %w\n%s", err, outBytes)
	}
	return out, func() { _ = os.RemoveAll(tmp) }, nil
}

func childEnv(home, xdgConfig, xdgData, xdgCache string) []string {
	// Filter parent env: drop legacy auth / login secrets so only our canary is set.
	skip := map[string]struct{}{
		"JENKINS_MCP_AUTH":        {},
		"JENKINS_MCP_LOGIN_TOKEN": {},
		"JENKINS_MCP_LOGIN_USER":  {},
		"HOME":                    {},
		"XDG_CONFIG_HOME":         {},
		"XDG_DATA_HOME":           {},
		"XDG_CACHE_HOME":          {},
	}
	var env []string
	for _, e := range os.Environ() {
		key, _, _ := strings.Cut(e, "=")
		if _, drop := skip[key]; drop {
			continue
		}
		env = append(env, e)
	}
	auth := smokeUser + ":" + canaryToken
	env = append(env,
		"HOME="+home,
		"XDG_CONFIG_HOME="+xdgConfig,
		"XDG_DATA_HOME="+xdgData,
		"XDG_CACHE_HOME="+xdgCache,
		// Deprecated bootstrap (KD-003): headless CI without Secret Service.
		"JENKINS_MCP_AUTH="+auth,
		"JENKINS_MCP_READ_ONLY=true",
		"JENKINS_MCP_NO_CACHE_MAINTENANCE=1",
		// Bound identity re-verify so short smoke is stable.
		"JENKINS_MCP_IDENTITY_REVERIFY_TTL=30m",
	)
	return env
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			// Prefer module root that contains cmd/jenkins-mcp.
			if st, err := os.Stat(filepath.Join(dir, "cmd", "jenkins-mcp")); err == nil && st.IsDir() {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("could not find repo root (go.mod + cmd/jenkins-mcp) from %s", wd)
}

func toolErrorText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func toolTextAndStructured(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(toolErrorText(res))
	if res.StructuredContent != nil {
		raw, err := json.Marshal(res.StructuredContent)
		if err == nil {
			b.Write(raw)
		}
	}
	return b.String()
}

func assertNoCanaries(where, s string) error {
	if strings.Contains(s, canaryToken) {
		return fmt.Errorf("auth token canary leaked in %s: %s", where, truncate(s, 400))
	}
	if strings.Contains(s, plantCanary) {
		return fmt.Errorf("plant canary leaked in %s: %s", where, truncate(s, 400))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
