package jenkins

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression: Jenkins LTS returns HTTP 500 for GET /api/json?tree= (empty tree).
// Version probe must use a non-empty tree field (nodeName) and read X-Jenkins.
func TestProbeJenkinsVersion_EmptyTreeRejectedByServer_UsesNodeName(t *testing.T) {
	t.Parallel()
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		// Simulate modern LTS: empty tree → 500
		if strings.Contains(gotPath, "tree=") && !strings.Contains(gotPath, "tree=nodeName") {
			if strings.HasSuffix(gotPath, "tree=") || strings.Contains(gotPath, "tree=&") {
				http.Error(w, "empty tree", http.StatusInternalServerError)
				return
			}
		}
		if r.URL.Path != "/api/json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Jenkins", "2.541.3")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"_class":"hudson.model.Hudson","nodeName":""}`))
	}))
	t.Cleanup(srv.Close)

	c := &Client{URL: srv.URL, User: "admin", Token: "tok", Client: srv.Client()}
	v, err := c.probeJenkinsVersion(context.Background())
	if err != nil {
		t.Fatalf("probeJenkinsVersion: %v (path=%q)", err, gotPath)
	}
	if v != "2.541.3" {
		t.Fatalf("version = %q want 2.541.3 (path=%q)", v, gotPath)
	}
	if !strings.Contains(gotPath, "tree=nodeName") {
		t.Fatalf("expected tree=nodeName probe, got %q", gotPath)
	}
	if strings.HasSuffix(gotPath, "tree=") {
		t.Fatalf("must not use empty tree=: %q", gotPath)
	}
}
