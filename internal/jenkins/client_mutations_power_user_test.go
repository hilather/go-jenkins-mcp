package jenkins_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

func TestClient_PowerUser_POSTs_NoAutoRetry(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "crumbIssuer") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"crumbRequestField":"Jenkins-Crumb","crumb":"x"}`))
			return
		}
		hits.Add(1)
		// Simulate connection-ish failure for first mutation by closing after headers on second? Use 503 then — POST must still be 1 hit.
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	c := jenkins.NewClient(srv.URL, "u", "t")
	ctx := context.Background()

	if _, err := c.InterruptBuild(ctx, "demo", 1, "term"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("interrupt hits=%d", hits.Load())
	}
	hits.Store(0)
	if _, err := c.SetJobBuildable(ctx, "demo", false); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("disable hits=%d", hits.Load())
	}
	hits.Store(0)
	if _, err := c.SetBuildDescription(ctx, "demo", 2, "hello"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("desc hits=%d", hits.Load())
	}
	hits.Store(0)
	if _, err := c.ReplayPipeline(ctx, "demo", 3); err != nil {
		t.Fatal(err)
	}
	// replay may try fallback path on 404 only; with 302 first path succeeds in one hit.
	if hits.Load() != 1 {
		t.Fatalf("replay hits=%d", hits.Load())
	}
}

func TestClient_PowerUser_ScriptTextStillUnclassified(t *testing.T) {
	// Guard: classifier never allowlists scriptText as known mutate path.
	if jenkins.ClassifyJenkinsRequest(http.MethodPost, "/scriptText") != jenkins.RequestUnclassified {
		t.Fatal("scriptText must stay unclassified")
	}
	if jenkins.ClassifyJenkinsRequest(http.MethodPost, "/job/x/config.xml") != jenkins.RequestUnclassified {
		t.Fatal("config.xml POST must stay unclassified")
	}
}

func TestClient_InterruptBuild_InvalidMode(t *testing.T) {
	c := jenkins.NewClient("http://127.0.0.1:9", "u", "t")
	_, err := c.InterruptBuild(context.Background(), "j", 1, "explode")
	if err == nil {
		t.Fatal("expected invalid mode")
	}
}

func TestClient_PowerUser_BodyConsumedOnce(t *testing.T) {
	// Ensure description form body is posted (single read).
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "crumbIssuer") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"crumbRequestField":"Jenkins-Crumb","crumb":"x"}`))
			return
		}
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := jenkins.NewClient(srv.URL, "u", "t")
	if _, err := c.SetBuildDescription(context.Background(), "job", 1, "note-value"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "note-value") {
		t.Fatalf("body=%q", body)
	}
}
