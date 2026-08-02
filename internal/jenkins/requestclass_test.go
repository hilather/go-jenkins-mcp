package jenkins_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

func TestClassifyJenkinsRequest(t *testing.T) {
	t.Parallel()
	cases := []struct {
		method, path string
		want         jenkins.RequestClass
	}{
		{"GET", "/api/json", jenkins.RequestRead},
		{"HEAD", "/job/x/1/api/json", jenkins.RequestRead},
		{"OPTIONS", "/", jenkins.RequestRead},
		{"GET", "/crumbIssuer/api/json", jenkins.RequestAuth},
		{"POST", "/crumbIssuer/api/json", jenkins.RequestAuth},
		{"POST", "/job/foo/build", jenkins.RequestMutate},
		{"POST", "/job/foo/buildWithParameters", jenkins.RequestMutate},
		{"POST", "/job/a/job/b/buildWithParameters?x=1", jenkins.RequestMutate},
		{"POST", "/job/foo/1/stop", jenkins.RequestMutate},
		{"POST", "/job/foo/1/kill", jenkins.RequestMutate},
		{"POST", "/job/foo/1/term", jenkins.RequestMutate},
		{"POST", "/queue/cancelItem?id=1", jenkins.RequestMutate},
		{"POST", "/job/foo/doDelete", jenkins.RequestMutate},
		// Unclassified write → fail closed class.
		{"POST", "/scriptText", jenkins.RequestUnclassified},
		{"PUT", "/job/foo/config.xml", jenkins.RequestUnclassified},
		{"DELETE", "/job/foo", jenkins.RequestUnclassified},
		{"", "/api/json", jenkins.RequestUnclassified},
		// Absolute same-origin path still classifies.
		{"POST", "https://jenkins.example.com/job/x/build", jenkins.RequestMutate},
		{"GET", "https://jenkins.example.com/api/json", jenkins.RequestRead},
	}
	for _, tc := range cases {
		got := jenkins.ClassifyJenkinsRequest(tc.method, tc.path)
		if got != tc.want {
			t.Errorf("Classify(%q,%q)=%q want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestRequiresMutationPermission(t *testing.T) {
	t.Parallel()
	if jenkins.RequiresMutationPermission(jenkins.RequestRead) {
		t.Fatal("read")
	}
	if jenkins.RequiresMutationPermission(jenkins.RequestAuth) {
		t.Fatal("auth")
	}
	if !jenkins.RequiresMutationPermission(jenkins.RequestMutate) {
		t.Fatal("mutate")
	}
	if !jenkins.RequiresMutationPermission(jenkins.RequestUnclassified) {
		t.Fatal("unclassified must fail closed")
	}
	if !jenkins.RequiresMutationPermission(jenkins.RequestClass("future")) {
		t.Fatal("unknown class must fail closed")
	}
}

// blockingGuard denies mutate/unclassified for unit tests without policy import.
type blockingGuard struct {
	deny bool
}

func (g blockingGuard) CheckRequest(ctx context.Context, class jenkins.RequestClass, method, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if g.deny && jenkins.RequiresMutationPermission(class) {
		return errors.New("blocked by test guard")
	}
	return nil
}

func TestCallJenkins_MutationGuardBlocksPOST(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := jenkins.NewClient(srv.URL, "u", "t")
	c.WithMutationGuard(blockingGuard{deny: true})

	_, err := c.CallJenkins(context.Background(), c.Client, http.MethodPost, "/job/x/build", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("want guard deny, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("network must not be hit when guard denies")
	}

	// GET still allowed.
	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("GET hits=%d", hits.Load())
	}
}

func TestCallJenkins_NilGuardUnchanged(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := jenkins.NewClient(srv.URL, "u", "t")
	// No guard: POST proceeds (handler/registry still enforce in production).
	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodPost, "/job/x/build", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestCallJenkins_MutationGuardRespectsCancel(t *testing.T) {
	t.Parallel()
	c := jenkins.NewClient("http://127.0.0.1:1", "u", "t")
	c.WithMutationGuard(blockingGuard{deny: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.CallJenkins(ctx, c.Client, http.MethodPost, "/job/x/build", nil, nil)
	if err == nil {
		t.Fatal("want cancel error")
	}
}
