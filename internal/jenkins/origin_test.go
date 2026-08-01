package jenkins

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string // String() form
		wantErr bool
	}{
		{name: "trailing slash", in: "https://jenkins.example.com/", want: "https://jenkins.example.com"},
		{name: "path prefix", in: "https://jenkins.example.com/ci/", want: "https://jenkins.example.com/ci"},
		{name: "http with port", in: "http://127.0.0.1:8080/", want: "http://127.0.0.1:8080"},
		{name: "strip query", in: "https://j.example/jenkins?x=1", want: "https://j.example/jenkins"},
		{name: "strip fragment", in: "https://j.example/jenkins#frag", want: "https://j.example/jenkins"},
		{name: "userinfo rejected", in: "https://user:token@j.example/", wantErr: true},
		{name: "ftp rejected", in: "ftp://j.example/", wantErr: true},
		{name: "empty rejected", in: "", wantErr: true},
		{name: "no host", in: "https:///path", wantErr: true},
		{name: "dot segments cleaned", in: "https://j.example/a/./b/../c/", want: "https://j.example/a/c"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeBaseURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.want {
				t.Fatalf("NormalizeBaseURL(%q) = %q, want %q", tc.in, got.String(), tc.want)
			}
		})
	}
}

func TestSameOrigin_PathPrefix(t *testing.T) {
	base, err := NormalizeBaseURL("https://j.example/ci")
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := url.Parse("https://j.example/ci/job/demo/1/")
	if !SameOrigin(base, ok) {
		t.Fatal("expected same origin for subpath")
	}
	otherPath, _ := url.Parse("https://j.example/other/job/demo/")
	if SameOrigin(base, otherPath) {
		t.Fatal("path outside prefix must not match")
	}
	evil, _ := url.Parse("https://evil.com/ci/job/demo/")
	if SameOrigin(base, evil) {
		t.Fatal("cross-host must not match")
	}
	// scheme mismatch
	httpU, _ := url.Parse("http://j.example/ci/job/demo/")
	if SameOrigin(base, httpU) {
		t.Fatal("scheme mismatch must not match")
	}
	// alternate port
	port, _ := url.Parse("https://j.example:8443/ci/job/demo/")
	if SameOrigin(base, port) {
		t.Fatal("port mismatch must not match")
	}
}

func TestResolveRequestURL_RelativeAndAbsolute(t *testing.T) {
	c := &Client{URL: "https://jenkins.example.com/ci/"}

	rel, err := c.resolveRequestURL("/job/demo/1/api/json")
	if err != nil {
		t.Fatal(err)
	}
	if rel != "https://jenkins.example.com/ci/job/demo/1/api/json" {
		t.Fatalf("relative join = %q", rel)
	}

	// trailing-slash normalization on base
	same, err := c.resolveRequestURL("https://jenkins.example.com/ci/job/demo/1/api/json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(same, "https://jenkins.example.com/ci/") {
		t.Fatalf("same-origin absolute = %q", same)
	}

	_, err = c.resolveRequestURL("https://evil.com/steal")
	if !errors.Is(err, ErrCrossOrigin) {
		t.Fatalf("expected ErrCrossOrigin, got %v", err)
	}

	_, err = c.resolveRequestURL("//evil.com/steal")
	if err == nil {
		t.Fatal("expected protocol-relative rejection")
	}
}

func TestCallJenkins_RejectsCrossOriginAbsolute(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	opts := f.opts()

	// Absolute URL to a different origin must not be fetched with credentials.
	_, err := opts.CallJenkins(context.Background(), opts.Client, http.MethodGet,
		"https://evil.example/secret", nil, nil)
	if !errors.Is(err, ErrCrossOrigin) {
		t.Fatalf("err = %v, want ErrCrossOrigin", err)
	}
}

func TestCallJenkins_AcceptsSameOriginAbsolute(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	opts := f.opts()

	// Same origin absolute (fixture root jobs list).
	full := strings.TrimRight(f.Server.URL, "/") + "/api/json"
	resp, err := opts.CallJenkins(context.Background(), opts.Client, http.MethodGet, full, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestCallJenkins_RefusesCrossOriginRedirect(t *testing.T) {
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("evil server should not receive authenticated redirect")
		w.WriteHeader(http.StatusOK)
	}))
	defer evil.Close()

	var sawAuth bool
	mux := http.NewServeMux()
	mux.HandleFunc("/bounce", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); ok {
			sawAuth = true
		}
		http.Redirect(w, r, evil.URL+"/sink", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	opts := &Client{
		URL:    srv.URL,
		User:   "u",
		Token:  "secret-token-value",
		Client: srv.Client(),
	}
	// Disable default client redirect following so our CheckRedirect runs;
	// srv.Client() follows redirects — CallJenkins wraps with pin.
	_, err := opts.CallJenkins(context.Background(), opts.Client, http.MethodGet, "/bounce", nil, nil)
	if err == nil {
		t.Fatal("expected cross-origin redirect error")
	}
	if !errors.Is(err, ErrCrossOrigin) && !strings.Contains(err.Error(), "cross-origin") {
		t.Fatalf("err = %v", err)
	}
	if !sawAuth {
		t.Log("note: initial bounce may still see auth (same-origin); evil must not")
	}
	// Ensure secret not in error
	if strings.Contains(err.Error(), "secret-token-value") {
		t.Fatalf("token leaked in error: %v", err)
	}
}

func TestBuildJobPath_EscapeAndNested(t *testing.T) {
	got := BuildJobPath("folder/sub/demo")
	if got != "/job/folder/job/sub/job/demo" {
		t.Fatalf("got %q", got)
	}
	// Spaces and special chars are path-escaped — not open URL injection.
	got = BuildJobPath("a b/c")
	if !strings.Contains(got, "a%20b") {
		t.Fatalf("expected path escape, got %q", got)
	}
	// Absolute-looking job name is treated as a single segment, not a URL.
	got = BuildJobPath("http://evil.com")
	if strings.HasPrefix(got, "http") {
		t.Fatalf("job path must not stay absolute URL: %q", got)
	}
	if !strings.HasPrefix(got, "/job/") {
		t.Fatalf("got %q", got)
	}
}

func TestGetBuildDetails_RejectsEvilAbsoluteURL(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	opts := f.opts()
	_, err := opts.GetBuildDetails(context.Background(), "https://evil.com/job/x/1/")
	if err == nil {
		t.Fatal("expected error for cross-origin build URL")
	}
	if !errors.Is(err, ErrCrossOrigin) && !strings.Contains(err.Error(), "cross-origin") {
		t.Fatalf("err = %v", err)
	}
}
