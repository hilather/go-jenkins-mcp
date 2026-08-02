package jenkins_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

func TestClient_SetBuildKeepForever_NoToggleWhenMatching(t *testing.T) {
	var keep atomic.Bool
	keep.Store(true)
	var toggles atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/api/json") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"number": 2, "url": "/job/demo/2/", "building": false, "result": "SUCCESS",
				"timestamp": 1, "duration": 1, "estimatedDuration": 1, "displayName": "#2",
				"keepLog": keep.Load(), "actions": []any{},
			})
			return
		}
		if strings.Contains(r.URL.Path, "toggleLogKeepForever") {
			toggles.Add(1)
			keep.Store(!keep.Load())
			w.WriteHeader(http.StatusFound)
			return
		}
		if strings.Contains(r.URL.Path, "crumbIssuer") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := jenkins.NewClient(srv.URL, "u", "t")
	// Already true → no toggle
	res, err := c.SetBuildKeepForever(context.Background(), "demo", 2, true)
	if err != nil {
		t.Fatal(err)
	}
	if toggles.Load() != 0 || res.Status != "unchanged" || !res.KeepForever {
		t.Fatalf("res=%+v toggles=%d", res, toggles.Load())
	}
	// Want false → one toggle
	res2, err := c.SetBuildKeepForever(context.Background(), "demo", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if toggles.Load() != 1 || res2.Status != "toggled" || res2.KeepForever {
		t.Fatalf("res2=%+v toggles=%d", res2, toggles.Load())
	}
}
