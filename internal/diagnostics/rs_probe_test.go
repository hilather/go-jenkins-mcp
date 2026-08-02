package diagnostics_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/auth"
	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

const rsProbeCanary = "RS_PROBE_CANARY_bearer_must_not_leak_xyz"

func TestProbeInvalidBearerFallthrough_QualifiedFilter(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			tok := strings.TrimSpace(authz[len("Bearer "):])
			if tok != "good" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"alice","anonymous":false,"authenticated":true}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	c := &jenkins.Client{URL: srv.URL, Client: srv.Client()}
	res, err := diagnostics.ProbeInvalidBearerFallthrough(context.Background(), diagnostics.RSProbeOptions{
		Client:        c,
		InvalidBearer: "bad-token",
		Paths: []string{
			"/whoAmI/api/json",
			"/job/demo/1/logText/progressiveText?start=0",
			"/job/demo/1/artifact/x",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.AllDenied || res.Fallthrough != 0 {
		t.Fatalf("%+v", res)
	}
	if res.PathsProbed != 3 {
		t.Fatalf("paths: %d", res.PathsProbed)
	}
}

func TestProbeInvalidBearerFallthrough_DetectsFallthrough(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"bob","anonymous":false,"authenticated":true}`))
	}))
	t.Cleanup(srv.Close)

	c := &jenkins.Client{URL: srv.URL, Client: srv.Client()}
	res, err := diagnostics.ProbeInvalidBearerFallthrough(context.Background(), diagnostics.RSProbeOptions{
		Client: c,
		Paths:  []string{"/whoAmI/api/json"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Fallthrough != 1 || res.AllDenied {
		t.Fatalf("expected fallthrough: %+v", res)
	}
	eval := auth.EvaluateInvalidBearerResponse(res.Results[0].StatusCode, true, false)
	if !eval.FallthroughDetected {
		t.Fatal(eval)
	}
}

func TestProbeBearerWhoAmI_OKAndCanary(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+rsProbeCanary {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("bad " + rsProbeCanary))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice","fullName":"Alice","anonymous":false,"authenticated":true}`))
	}))
	t.Cleanup(srv.Close)

	c := &jenkins.Client{
		URL:        srv.URL,
		Token:      rsProbeCanary,
		AuthScheme: jenkins.AuthSchemeBearer,
		Client:     srv.Client(),
	}
	who, err := diagnostics.ProbeBearerWhoAmI(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if who.ID != "alice" {
		t.Fatalf("%+v", who)
	}

	c.Token = "wrong-" + rsProbeCanary
	_, err = diagnostics.ProbeBearerWhoAmI(context.Background(), c)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), rsProbeCanary) {
		t.Fatalf("canary leaked: %v", err)
	}
}

func TestFormatRSOnlineProbeText_NoSecret(t *testing.T) {
	t.Parallel()
	text := diagnostics.FormatRSOnlineProbeText(diagnostics.RSOnlineProbeResult{
		PathsProbed: 1,
		Denied:      1,
		AllDenied:   true,
		Results: []diagnostics.RSPathProbe{{
			Path: "/whoAmI/api/json", StatusCode: 401, Denied: true, Reason: "denied",
		}},
		BearerWhoAmIOK: true,
		PrincipalID:    "alice",
	})
	if !strings.Contains(text, "all_denied=true") {
		t.Fatal(text)
	}
	if strings.Contains(text, rsProbeCanary) {
		t.Fatal("canary in text")
	}
}

// Wave 33: probe uses WWW-Authenticate + body class classifier (empty body + Bearer challenge).
func TestProbeInvalidBearerFallthrough_WWWAuthenticateAndBodyClass(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="Jenkins", error="invalid_token"`)
			w.WriteHeader(http.StatusUnauthorized)
			// empty body
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	c := &jenkins.Client{URL: srv.URL, Client: srv.Client()}
	res, err := diagnostics.ProbeInvalidBearerFallthrough(context.Background(), diagnostics.RSProbeOptions{
		Client:        c,
		InvalidBearer: rsProbeCanary,
		Paths:         []string{"/whoAmI/api/json", "/job/demo/1/logText/progressiveText?start=0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.AllDenied || res.Fallthrough != 0 {
		t.Fatalf("%+v", res)
	}
	for _, p := range res.Results {
		if !p.Denied {
			t.Fatalf("path %s not denied: %+v", p.Path, p)
		}
		if strings.Contains(p.Reason, rsProbeCanary) {
			t.Fatalf("canary leaked in reason: %q", p.Reason)
		}
		if !strings.Contains(p.Reason, "Bearer") && !strings.Contains(p.Reason, "denied") {
			t.Fatalf("expected Bearer/denied reason, got %q", p.Reason)
		}
	}
	// Fallthrough with HTML error body + 200 must be detected.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><title>Error 500</title><h1>Internal Server Error</h1></html>`))
	}))
	t.Cleanup(srv2.Close)
	c2 := &jenkins.Client{URL: srv2.URL, Client: srv2.Client()}
	res2, err := diagnostics.ProbeInvalidBearerFallthrough(context.Background(), diagnostics.RSProbeOptions{
		Client: c2,
		Paths:  []string{"/whoAmI/api/json"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Fallthrough != 1 || res2.AllDenied {
		t.Fatalf("expected HTML error fallthrough: %+v", res2)
	}
}
