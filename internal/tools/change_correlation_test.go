package tools_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type corrFixture struct {
	srv *httptest.Server
}

func newCorrFixture() *corrFixture {
	f := &corrFixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if !(strings.Contains(path, "/api/json") && strings.Contains(path, "/job/")) {
			http.NotFound(w, r)
			return
		}
		// SCM-001 tree includes changeSet/changeSets; build details does not.
		if strings.Contains(r.URL.RawQuery, "changeSet") || strings.Contains(r.URL.RawQuery, "changeSets") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"number": 7,
				"result": "FAILURE",
				"changeSet": map[string]any{
					"kind": "git",
					"items": []map[string]any{
						{
							"commitId": "4bf92f3577b34da6a3ce929d0e0e4736a3ce929d",
							"msg":      "fix PROJ-99 see https://github.com/acme/demo/issues/12",
							"author":   map[string]string{"fullName": "dev"},
						},
					},
				},
				"actions": []map[string]any{
					{
						"_class":     "hudson.plugins.git.util.BuildData",
						"remoteUrls": []string{"https://github.com/acme/demo.git"},
					},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"number":      7,
			"url":         "http://example/job/demo/7/",
			"building":    false,
			"result":      "FAILURE",
			"timestamp":   1_700_000_000_000,
			"duration":    1000,
			"displayName": "#7",
			"actions": []map[string]any{
				{
					"_class": "hudson.model.ParametersAction",
					"parameters": []map[string]any{
						{"name": "JIRA_KEY", "value": "PROJ-42"},
						{"name": "API_TOKEN", "value": "super-secret-token-value"},
						{"name": "NOTES", "value": "related https://github.com/acme/demo/pull/3"},
					},
				},
			},
		})
	}))
	return f
}

func (f *corrFixture) close() { f.srv.Close() }

func (f *corrFixture) client() *jenkins.Client {
	return &jenkins.Client{
		URL:        f.srv.URL,
		User:       "u",
		Token:      "t",
		Client:     f.srv.Client(),
		LogsClient: f.srv.Client(),
	}
}

func TestChangeCorrelation_DisabledByDefault(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	names := listToolNames(t, ctx, nil)
	if _, ok := names[tools.ToolGetChangeCorrelation]; ok {
		t.Fatalf("%s registered when EnableChangeCorrelation=false", tools.ToolGetChangeCorrelation)
	}
}

func TestChangeCorrelation_EnabledRegistersTool(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	names := listToolNames(t, ctx, &tools.RegisterOptions{EnableChangeCorrelation: true})
	if _, ok := names[tools.ToolGetChangeCorrelation]; !ok {
		t.Fatalf("%s not registered", tools.ToolGetChangeCorrelation)
	}
}

func TestChangeCorrelation_ExtractsWorkItemsNoSecrets(t *testing.T) {
	t.Parallel()
	f := newCorrFixture()
	defer f.close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{EnableChangeCorrelation: true})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolGetChangeCorrelation,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	raw, _ := json.Marshal(payload)
	s := string(raw)
	if strings.Contains(s, "super-secret-token-value") {
		t.Fatal("secret leaked")
	}
	if !strings.Contains(s, "PROJ-42") {
		t.Fatalf("missing jira key in %s", s)
	}
	if !strings.Contains(s, "acme/demo#3") && !strings.Contains(s, "github") {
		// PR from NOTES parameter
		t.Fatalf("missing github pr correlation in %s", s)
	}
	if !strings.Contains(s, "residual") {
		t.Fatalf("want ticket API residual in %s", s)
	}
	if payload["freshness"] != "live" {
		t.Fatalf("freshness=%v", payload["freshness"])
	}
}

type stubLookup struct {
	ids []string
}

func (s *stubLookup) LookupWorkItemRefs(ctx context.Context, ids []string) ([]string, error) {
	s.ids = append([]string(nil), ids...)
	return ids, nil
}

func TestChangeCorrelation_AdapterStubOptional(t *testing.T) {
	t.Parallel()
	f := newCorrFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	stub := &stubLookup{}
	tools.Register(server, f.client(), &tools.RegisterOptions{
		EnableChangeCorrelation: true,
		WorkItemLookup:          stub,
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolGetChangeCorrelation,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := toolStructuredJSON(t, res)
	stubArr, _ := payload["adapter_stub"].([]any)
	if len(stubArr) == 0 {
		t.Fatalf("want adapter_stub, got %v", payload)
	}
	if len(stub.ids) == 0 {
		t.Fatal("lookup not called")
	}
}
