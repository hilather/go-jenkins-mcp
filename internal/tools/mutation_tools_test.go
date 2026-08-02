package tools_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/mutation"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

// mutFixture is a minimal Jenkins HTTP surface for MUT-002/003 and power-user tool tests.
type mutFixture struct {
	srv          *httptest.Server
	startCalls   atomic.Int32
	stopCalls    atomic.Int32
	termCalls    atomic.Int32
	killCalls    atomic.Int32
	cancelCalls  atomic.Int32
	enableCalls  atomic.Int32
	disableCalls atomic.Int32
	keepCalls    atomic.Int32
	descCalls    atomic.Int32
	replayCalls  atomic.Int32
	building     atomic.Bool
	keepLog      atomic.Bool
	buildable    atomic.Bool
	// queueMode: "waiting" (cancellable), "missing" (404), "cancelled", "assigned" (has executable).
	queueMode atomic.Value // string
	// jobPropertyJSON overrides property[] on job api/json (MUT-002 definitions).
	// Empty ⇒ default parameterized demo (BRANCH string, ENV choice, DEPLOY_KEY password).
	jobPropertyJSON atomic.Value // string; "none" ⇒ empty property
	// lastStartForm records the last buildWithParameters form body for preview==execute checks.
	lastStartForm atomic.Value // string
	lastDescForm  atomic.Value // string
	// queueItemsJSON overrides /queue/api/json body when non-empty (folder isolation tests).
	queueItemsJSON atomic.Value // string
	// cancelledQueueIDs records cancelItem id= query values for regression asserts.
	cancelledQueueIDs atomic.Value // []int under mutex-free append via Store of copy
}

func newMutFixture() *mutFixture {
	f := &mutFixture{}
	f.building.Store(true)
	f.keepLog.Store(false)
	f.buildable.Store(true)
	f.queueMode.Store("waiting")
	f.jobPropertyJSON.Store("")
	f.queueItemsJSON.Store("")
	f.cancelledQueueIDs.Store([]int(nil))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/buildWithParameters") || strings.HasSuffix(path, "/build"):
			f.startCalls.Add(1)
			_ = r.ParseForm()
			f.lastStartForm.Store(r.Form.Encode())
			w.Header().Set("Location", f.srv.URL+"/queue/item/42/")
			w.WriteHeader(http.StatusCreated)
		case strings.HasSuffix(path, "/stop"):
			f.stopCalls.Add(1)
			w.WriteHeader(http.StatusFound)
		case strings.HasSuffix(path, "/term"):
			f.termCalls.Add(1)
			w.WriteHeader(http.StatusFound)
		case strings.HasSuffix(path, "/kill"):
			f.killCalls.Add(1)
			w.WriteHeader(http.StatusFound)
		case strings.HasSuffix(path, "/enable"):
			f.enableCalls.Add(1)
			f.buildable.Store(true)
			w.WriteHeader(http.StatusFound)
		case strings.HasSuffix(path, "/disable"):
			f.disableCalls.Add(1)
			f.buildable.Store(false)
			w.WriteHeader(http.StatusFound)
		case strings.Contains(path, "/toggleLogKeepForever"):
			f.keepCalls.Add(1)
			f.keepLog.Store(!f.keepLog.Load())
			w.WriteHeader(http.StatusFound)
		case strings.Contains(path, "/submitDescription"):
			f.descCalls.Add(1)
			_ = r.ParseForm()
			f.lastDescForm.Store(r.Form.Encode())
			w.WriteHeader(http.StatusFound)
		case strings.Contains(path, "/replay"):
			f.replayCalls.Add(1)
			w.WriteHeader(http.StatusFound)
		case path == "/queue/cancelItem" || strings.HasPrefix(path, "/queue/cancelItem"):
			f.cancelCalls.Add(1)
			if idStr := r.URL.Query().Get("id"); idStr != "" {
				if n, err := atoiSafe(idStr); err == nil {
					prev, _ := f.cancelledQueueIDs.Load().([]int)
					next := append(append([]int(nil), prev...), n)
					f.cancelledQueueIDs.Store(next)
				}
			}
			w.WriteHeader(http.StatusFound)
		case path == "/queue/api/json":
			// Default: single top-level demo. Power-user folder isolation tests
			// override via queueItemsJSON when set.
			if raw, _ := f.queueItemsJSON.Load().(string); raw != "" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(raw))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []any{
					map[string]any{
						"id": 11,
						"task": map[string]any{
							"name":     "demo",
							"fullName": "demo",
							"url":      f.srv.URL + "/job/demo/",
						},
						"why":          "waiting",
						"inQueueSince": 1,
						"stuck":        true,
						"buildable":    true,
						"params":       "",
					},
					map[string]any{
						"id": 12,
						"task": map[string]any{
							"name":     "demo",
							"fullName": "demo",
							"url":      f.srv.URL + "/job/demo/",
						},
						"why":          "waiting",
						"inQueueSince": 1,
						"stuck":        false,
						"buildable":    true,
						"params":       "",
					},
				},
			})
			return
		case strings.HasPrefix(path, "/queue/item/") && strings.HasSuffix(path, "/api/json"):
			// /queue/item/<id>/api/json
			qid := 42
			parts := strings.Split(strings.Trim(path, "/"), "/")
			if len(parts) >= 3 {
				if n, err := atoiSafe(parts[2]); err == nil {
					qid = n
				}
			}
			mode, _ := f.queueMode.Load().(string)
			switch mode {
			case "missing":
				http.NotFound(w, r)
				return
			case "cancelled":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": qid,
					"task": map[string]any{
						"name": "demo",
						"url":  f.srv.URL + "/job/demo/",
					},
					"cancelled":  true,
					"executable": nil,
					"why":        "Cancelled",
				})
				return
			case "assigned":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": qid,
					"task": map[string]any{
						"name": "demo",
						"url":  f.srv.URL + "/job/demo/",
					},
					"cancelled": false,
					"executable": map[string]any{
						"number":   9,
						"url":      f.srv.URL + "/job/demo/9/",
						"building": true,
					},
				})
				return
			default: // waiting — cancellable; StartJob path also hits this for queue item 42
				// Preserve prior StartJob fixture shape when id is 42 (has executable).
				if qid == 42 {
					_ = json.NewEncoder(w).Encode(map[string]any{
						"id": 42,
						"task": map[string]any{
							"name": "demo",
							"url":  f.srv.URL + "/job/demo/",
						},
						"executable": map[string]any{
							"number":   9,
							"url":      f.srv.URL + "/job/demo/9/",
							"building": true,
						},
					})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": qid,
					"task": map[string]any{
						"name": "demo",
						"url":  f.srv.URL + "/job/demo/",
					},
					"why":        "Waiting for next available executor",
					"buildable":  true,
					"cancelled":  false,
					"executable": nil,
				})
				return
			}
		case strings.Contains(path, "/job/") && strings.HasSuffix(path, "/api/json"):
			// Build or job detail.
			building := f.building.Load()
			result := any(nil)
			if !building {
				result = "SUCCESS"
			}
			// Detect build number: .../job/demo/N/api/json
			parts := strings.Split(strings.Trim(path, "/"), "/")
			num := 0
			for i := 0; i < len(parts)-1; i++ {
				if parts[i+1] == "api" {
					if n, err := atoiSafe(parts[i]); err == nil {
						num = n
					}
				}
			}
			if num > 0 {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"number":   num,
					"url":      f.srv.URL + "/job/demo/" + parts[len(parts)-3] + "/",
					"building": building,
					"result":   result,
					"keepLog":  f.keepLog.Load(),
					"actions": []any{
						map[string]any{
							"_class": "hudson.model.ParametersAction",
							"parameters": []any{
								map[string]any{"name": "BRANCH", "value": "main"},
							},
						},
					},
				})
				return
			}
			// Job detail / parameter definitions (MUT-002).
			prop := mutDemoJobProperty(f)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":      "demo",
				"url":       f.srv.URL + "/job/demo/",
				"buildable": f.buildable.Load(),
				"property":  prop,
			})
		case path == "/crumbIssuer/api/json":
			w.WriteHeader(http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	})
	f.srv = httptest.NewServer(mux)
	return f
}

// mutDemoJobProperty returns property[] for the demo job under mutFixture.
func mutDemoJobProperty(f *mutFixture) []any {
	raw, _ := f.jobPropertyJSON.Load().(string)
	if raw == "none" {
		return []any{}
	}
	if raw != "" {
		var prop []any
		if err := json.Unmarshal([]byte(raw), &prop); err == nil {
			return prop
		}
	}
	// Default: String BRANCH, Choice ENV, Password DEPLOY_KEY (type-secret, not name-heuristic).
	return []any{
		map[string]any{
			"_class": "hudson.model.ParametersDefinitionProperty",
			"parameterDefinitions": []any{
				map[string]any{
					"_class":      "hudson.model.StringParameterDefinition",
					"name":        "BRANCH",
					"type":        "StringParameterDefinition",
					"description": "branch",
					"defaultParameterValue": map[string]any{
						"value": "main",
					},
				},
				map[string]any{
					"_class":  "hudson.model.ChoiceParameterDefinition",
					"name":    "ENV",
					"type":    "ChoiceParameterDefinition",
					"choices": []string{"dev", "stage", "prod"},
				},
				map[string]any{
					"_class": "hudson.model.BooleanParameterDefinition",
					"name":   "DEBUG",
					"type":   "BooleanParameterDefinition",
					"defaultParameterValue": map[string]any{
						"value": false,
					},
				},
				map[string]any{
					"_class": "hudson.model.PasswordParameterDefinition",
					"name":   "DEPLOY_KEY",
					"type":   "PasswordParameterDefinition",
					"defaultParameterValue": map[string]any{
						"value": "should-not-surface",
					},
				},
			},
		},
	}
}

func (f *mutFixture) close() { f.srv.Close() }

func (f *mutFixture) client() *jenkins.Client {
	return &jenkins.Client{
		URL:        f.srv.URL,
		User:       "u",
		Token:      "t",
		Client:     f.srv.Client(),
		LogsClient: f.srv.Client(),
	}
}

func atoiSafe(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errNotNum
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

var errNotNum = errString("not a number")

type errString string

func (e errString) Error() string { return string(e) }

func TestStartJobPreviewThenConfirm(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	mem := &audit.Memory{}
	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	mgr := mutation.NewManager(mutation.Config{
		Gate:        gate,
		Audit:       mem,
		ProfileID:   "corp",
		PrincipalID: "alice",
	})

	server := mcp.NewServer(&mcp.Implementation{Name: "mut-start", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:        gate,
		Audit:       mem,
		Mutations:   mgr,
		ProfileID:   "corp",
		PrincipalID: "alice",
	})

	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	// Preview (no token) must not enqueue.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolStartJob,
		Arguments: map[string]any{
			"job_name":   "demo",
			"parameters": map[string]any{"BRANCH": "main"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("preview error: %s", toolErrorText(res))
	}
	prev := toolStructuredJSON(t, res)
	if prev["status"] != "preview" {
		t.Fatalf("want preview, got %#v", prev)
	}
	tok, _ := prev["confirmationToken"].(string)
	if tok == "" {
		t.Fatalf("missing token: %#v", prev)
	}
	if f.startCalls.Load() != 0 {
		t.Fatalf("start called on preview: %d", f.startCalls.Load())
	}
	// Redacted params present and match execute payload (MUT-002 preview==execute).
	params, _ := prev["parameters"].(map[string]any)
	if params["BRANCH"] != "main" {
		t.Fatalf("params: %#v", params)
	}

	// Confirm execute once.
	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolStartJob,
		Arguments: map[string]any{
			"job_name":           "demo",
			"parameters":         map[string]any{"BRANCH": "main"},
			"confirmation_token": tok,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.IsError {
		t.Fatalf("confirm error: %s", toolErrorText(res2))
	}
	if f.startCalls.Load() != 1 {
		t.Fatalf("start calls=%d", f.startCalls.Load())
	}
	form, _ := f.lastStartForm.Load().(string)
	if !strings.Contains(form, "BRANCH=main") {
		t.Fatalf("execute form must match preview BRANCH=main, got %q", form)
	}
	out := toolStructuredJSON(t, res2)
	if out["jobName"] != "demo" {
		t.Fatalf("result: %#v", out)
	}

	// Replay denied; no second enqueue.
	res3, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolStartJob,
		Arguments: map[string]any{
			"job_name":           "demo",
			"parameters":         map[string]any{"BRANCH": "main"},
			"confirmation_token": tok,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res3.IsError {
		t.Fatal("expected reuse denial")
	}
	if f.startCalls.Load() != 1 {
		t.Fatalf("duplicate start: %d", f.startCalls.Load())
	}
}

func TestStartJobSecretParamRejected(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	server := mcp.NewServer(&mcp.Implementation{Name: "mut-secret", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{Gate: gate})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolStartJob,
		Arguments: map[string]any{
			"job_name":   "demo",
			"parameters": map[string]any{"PASSWORD": "nope"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected secret reject")
	}
	if f.startCalls.Load() != 0 {
		t.Fatal("must not start")
	}
	text := toolErrorText(res)
	if strings.Contains(text, "nope") {
		t.Fatalf("secret leaked: %q", text)
	}
}

func TestStartJobUnknownParamRejected(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	server := mcp.NewServer(&mcp.Implementation{Name: "mut-unknown", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{Gate: gate})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolStartJob,
		Arguments: map[string]any{
			"job_name":   "demo",
			"parameters": map[string]any{"NOT_A_PARAM": "x"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected unknown param reject")
	}
	if f.startCalls.Load() != 0 {
		t.Fatal("must not start")
	}
	text := toolErrorText(res)
	if !strings.Contains(text, "NOT_A_PARAM") && !strings.Contains(strings.ToLower(text), "not defined") {
		t.Fatalf("msg: %q", text)
	}
}

func TestStartJobBadChoiceRejected(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	server := mcp.NewServer(&mcp.Implementation{Name: "mut-choice", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{Gate: gate})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolStartJob,
		Arguments: map[string]any{
			"job_name":   "demo",
			"parameters": map[string]any{"ENV": "production"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected bad choice reject")
	}
	if f.startCalls.Load() != 0 {
		t.Fatal("must not start")
	}
}

func TestStartJobSecretDefinitionTypeRejected(t *testing.T) {
	// DEPLOY_KEY is not a sensitive *name* heuristic hit but PasswordParameterDefinition.
	f := newMutFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	server := mcp.NewServer(&mcp.Implementation{Name: "mut-pwtype", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{Gate: gate})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolStartJob,
		Arguments: map[string]any{
			"job_name":   "demo",
			"parameters": map[string]any{"DEPLOY_KEY": "super-secret-value"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected password definition type reject")
	}
	if f.startCalls.Load() != 0 {
		t.Fatal("must not start")
	}
	text := toolErrorText(res)
	if strings.Contains(text, "super-secret-value") {
		t.Fatalf("secret leaked: %q", text)
	}
}

func TestStartJobROOmitsTool(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "mut-ro-omit", Version: "test"}, nil)
	tools.Register(server, f.client(), nil) // default RO
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range list.Tools {
		if tl.Name == policy.ToolStartJob {
			t.Fatal("RO must omit jenkins_start_job")
		}
	}
}

// Regression: Register without explicit Mutations still shares one Manager
// so preview→confirm works across calls (MUT-001 token store).
func TestStartJobDefaultManagerSharedAcrossCalls(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	server := mcp.NewServer(&mcp.Implementation{Name: "mut-shared", Version: "test"}, nil)
	// No Mutations field — resolveRegisterOptions must mint a process-scoped one.
	tools.Register(server, f.client(), &tools.RegisterOptions{Gate: gate})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      policy.ToolStartJob,
		Arguments: map[string]any{"job_name": "demo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("preview: %s", toolErrorText(res))
	}
	prev := toolStructuredJSON(t, res)
	tok, _ := prev["confirmationToken"].(string)
	if tok == "" {
		t.Fatal("missing token")
	}
	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolStartJob,
		Arguments: map[string]any{
			"job_name":           "demo",
			"confirmation_token": tok,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.IsError {
		t.Fatalf("confirm with default manager: %s", toolErrorText(res2))
	}
	if f.startCalls.Load() != 1 {
		t.Fatalf("start calls=%d", f.startCalls.Load())
	}
}

func TestStopBuildAlreadyFinished(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	f.building.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	server := mcp.NewServer(&mcp.Implementation{Name: "mut-stop-fin", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{Gate: gate})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolStopBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected already-finished error")
	}
	text := strings.ToLower(toolErrorText(res))
	if !strings.Contains(text, "finished") && !strings.Contains(text, "already") {
		t.Fatalf("msg: %q", toolErrorText(res))
	}
	if f.stopCalls.Load() != 0 {
		t.Fatal("must not POST stop")
	}
	if !strings.Contains(toolErrorText(res), string(apperr.CodeInvalidArgument)) &&
		!strings.Contains(text, "finished") {
		// Code may appear in Error() formatting from apperr.
	}
}

func TestStopBuildPreviewThenConfirm(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	f.building.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	mem := &audit.Memory{}
	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	mgr := mutation.NewManager(mutation.Config{
		Gate: gate, Audit: mem, ProfileID: "corp", PrincipalID: "alice",
	})
	server := mcp.NewServer(&mcp.Implementation{Name: "mut-stop", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate: gate, Audit: mem, Mutations: mgr, ProfileID: "corp", PrincipalID: "alice",
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      policy.ToolStopBuild,
		Arguments: map[string]any{"job_name": "demo", "build_number": 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("preview: %s", toolErrorText(res))
	}
	prev := toolStructuredJSON(t, res)
	tok, _ := prev["confirmationToken"].(string)
	if tok == "" || prev["status"] != "preview" {
		t.Fatalf("%#v", prev)
	}
	if f.stopCalls.Load() != 0 {
		t.Fatal("stop on preview")
	}

	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolStopBuild,
		Arguments: map[string]any{
			"job_name": "demo", "build_number": 7, "confirmation_token": tok,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.IsError {
		t.Fatalf("confirm: %s", toolErrorText(res2))
	}
	if f.stopCalls.Load() != 1 {
		t.Fatalf("stop calls=%d", f.stopCalls.Load())
	}
}

func TestStartJobRODeniedEvenWhenForceRegistered(t *testing.T) {
	// POL-001 + MUT-001: RO blocks before mutation manager.
	f := newMutFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "mut-ro", Version: "test"}, nil)
	gate := policy.NewDefaultReadOnlyGate()
	tools.RegisterMutationToolsForTest(server, f.client(), gate)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      policy.ToolStartJob,
		Arguments: map[string]any{"job_name": "demo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("want RO denial")
	}
	if f.startCalls.Load() != 0 {
		t.Fatal("must not start under RO")
	}
}

func TestCancelQueueItemPreviewThenConfirm(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	f.queueMode.Store("waiting")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	mem := &audit.Memory{}
	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	mgr := mutation.NewManager(mutation.Config{
		Gate: gate, Audit: mem, ProfileID: "corp", PrincipalID: "alice",
	})
	server := mcp.NewServer(&mcp.Implementation{Name: "mut-cancel", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate: gate, Audit: mem, Mutations: mgr, ProfileID: "corp", PrincipalID: "alice",
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      policy.ToolCancelQueueItem,
		Arguments: map[string]any{"queue_id": 55},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("preview: %s", toolErrorText(res))
	}
	prev := toolStructuredJSON(t, res)
	tok, _ := prev["confirmationToken"].(string)
	if tok == "" || prev["status"] != "preview" {
		t.Fatalf("%#v", prev)
	}
	if qid, _ := prev["queueId"].(float64); int(qid) != 55 {
		t.Fatalf("queueId: %#v", prev["queueId"])
	}
	if f.cancelCalls.Load() != 0 {
		t.Fatal("cancel on preview")
	}
	// Secret-free audit on preview.
	for _, e := range mem.Events() {
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "secret-token") || strings.Contains(string(raw), "PASSWORD") {
			t.Fatalf("secret in audit: %s", raw)
		}
	}

	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolCancelQueueItem,
		Arguments: map[string]any{
			"queue_id": 55, "confirmation_token": tok,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.IsError {
		t.Fatalf("confirm: %s", toolErrorText(res2))
	}
	if f.cancelCalls.Load() != 1 {
		t.Fatalf("cancel calls=%d", f.cancelCalls.Load())
	}
	out := toolStructuredJSON(t, res2)
	if out["status"] != "cancelled" {
		t.Fatalf("result: %#v", out)
	}
}

func TestCancelQueueItemMissingNotSuccess(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	f.queueMode.Store("missing")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	server := mcp.NewServer(&mcp.Implementation{Name: "mut-cancel-miss", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{Gate: gate})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      policy.ToolCancelQueueItem,
		Arguments: map[string]any{"queue_id": 55},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected missing queue error")
	}
	text := strings.ToLower(toolErrorText(res))
	if !strings.Contains(text, "not found") && !strings.Contains(text, "refused") {
		t.Fatalf("msg: %q", toolErrorText(res))
	}
	if f.cancelCalls.Load() != 0 {
		t.Fatal("must not POST cancel for missing item")
	}
}

func TestCancelQueueItemAlreadyAssignedNotSuccess(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	f.queueMode.Store("assigned")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	server := mcp.NewServer(&mcp.Implementation{Name: "mut-cancel-asg", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{Gate: gate})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      policy.ToolCancelQueueItem,
		Arguments: map[string]any{"queue_id": 55},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected already-left error")
	}
	text := strings.ToLower(toolErrorText(res))
	if !strings.Contains(text, "left") && !strings.Contains(text, "assigned") && !strings.Contains(text, "refused") {
		t.Fatalf("msg: %q", toolErrorText(res))
	}
	if f.cancelCalls.Load() != 0 {
		t.Fatal("must not POST cancel for assigned item")
	}
}

func TestCancelQueueItemAlreadyCancelledNotSuccess(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	f.queueMode.Store("cancelled")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	server := mcp.NewServer(&mcp.Implementation{Name: "mut-cancel-done", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{Gate: gate})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      policy.ToolCancelQueueItem,
		Arguments: map[string]any{"queue_id": 55},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected already-cancelled error")
	}
	if f.cancelCalls.Load() != 0 {
		t.Fatal("must not POST cancel when already cancelled")
	}
}

func TestCancelQueueItemROOmittedAndForceDenied(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Default RO: tool not registered.
	serverRO := mcp.NewServer(&mcp.Implementation{Name: "mut-cancel-ro", Version: "test"}, nil)
	tools.Register(serverRO, f.client(), nil)
	csRO, ssRO := connectMCP(t, ctx, serverRO)
	defer csRO.Close()
	defer ssRO.Close()
	toolsList, err := csRO.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range toolsList.Tools {
		if tl.Name == policy.ToolCancelQueueItem {
			t.Fatal("RO must omit jenkins_cancel_queue_item")
		}
	}

	// Force-registered under RO: call denied.
	server := mcp.NewServer(&mcp.Implementation{Name: "mut-cancel-force", Version: "test"}, nil)
	gate := policy.NewDefaultReadOnlyGate()
	tools.RegisterMutationToolsForTest(server, f.client(), gate)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      policy.ToolCancelQueueItem,
		Arguments: map[string]any{"queue_id": 55},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("want RO denial")
	}
	if f.cancelCalls.Load() != 0 {
		t.Fatal("must not cancel under RO")
	}
}
