package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
)

func TestFetchJWKS_Good(t *testing.T) {
	t.Parallel()
	_, jwksDoc := testRSAJWKS(t, "k1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksDoc)
	}))
	t.Cleanup(srv.Close)

	got, err := auth.FetchJWKS(context.Background(), srv.Client(), srv.URL+"/jwks")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Keys) != 1 || got.Keys[0].Kid != "k1" {
		t.Fatalf("%+v", got)
	}
	pub, err := got.KeyByID("k1")
	if err != nil || pub == nil {
		t.Fatal(err)
	}
}

func TestFetchJWKSFromDiscovery(t *testing.T) {
	t.Parallel()
	_, jwksDoc := testRSAJWKS(t, "k1")
	var jwksURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDoc)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	jwksURL = srv.URL + "/jwks"

	doc := &auth.DiscoveryDocument{JWKSURI: jwksURL}
	got, err := auth.FetchJWKSFromDiscovery(context.Background(), srv.Client(), doc)
	if err != nil || len(got.Keys) != 1 {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestFetchJWKS_Errors(t *testing.T) {
	t.Parallel()
	if _, err := auth.FetchJWKS(context.Background(), nil, "https://x"); err == nil {
		t.Fatal("nil client")
	}
	if _, err := auth.FetchJWKS(context.Background(), http.DefaultClient, ""); err == nil {
		t.Fatal("empty uri")
	}
	if _, err := auth.FetchJWKS(context.Background(), http.DefaultClient, "not-a-url"); err == nil {
		t.Fatal("bad uri")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("nope"))
	}))
	t.Cleanup(srv.Close)
	_, err := auth.FetchJWKS(context.Background(), srv.Client(), srv.URL)
	if err == nil || apperr.CodeOf(err) != apperr.CodeUpstreamProtocol {
		t.Fatalf("got %v", err)
	}

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	}))
	t.Cleanup(empty.Close)
	_, err = auth.FetchJWKS(context.Background(), empty.Client(), empty.URL)
	if err == nil || !strings.Contains(err.Error(), "no keys") {
		t.Fatalf("got %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = auth.FetchJWKS(ctx, srv.Client(), srv.URL)
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("cancel: %v", err)
	}
}

func TestJWKS_KeyByID_AmbiguousWithoutKid(t *testing.T) {
	t.Parallel()
	_, j1 := testRSAJWKS(t, "a")
	_, j2 := testRSAJWKS(t, "b")
	combined := &auth.JWKS{Keys: append(append([]auth.JWK{}, j1.Keys...), j2.Keys...)}
	_, err := combined.KeyByID("")
	if err == nil {
		t.Fatal("multi-key without kid must fail closed")
	}
}
