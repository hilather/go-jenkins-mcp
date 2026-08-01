package jenkins

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression: real Jenkins LTS WhoAmI JSON uses "name" for the login principal,
// not "id". Live smoke against jenkins/jenkins:lts failed with empty WhoAmI.ID.
func TestWhoAmI_NameFieldMapsToID(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Shape matches Jenkins 2.541.x /whoAmI/api/json
		_, _ = w.Write([]byte(`{"_class":"hudson.security.WhoAmI","anonymous":false,"authenticated":true,"authorities":["authenticated"],"name":"admin"}`))
	}))
	t.Cleanup(srv.Close)

	c := &Client{URL: srv.URL, User: "admin", Token: "tok", Client: srv.Client()}
	who, err := c.WhoAmI(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if who.ID != "admin" {
		t.Fatalf("ID = %q want admin (mapped from name)", who.ID)
	}
	if who.Anonymous || !who.Authenticated {
		t.Fatalf("%+v", who)
	}
}

func TestWhoAmI_IDFieldStillPreferred(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WhoAmIPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice","name":"other","fullName":"Alice","anonymous":false,"authenticated":true}`))
	}))
	t.Cleanup(srv.Close)

	c := &Client{URL: srv.URL, User: "alice", Token: "tok", Client: srv.Client()}
	who, err := c.WhoAmI(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if who.ID != "alice" {
		t.Fatalf("ID = %q want alice (id preferred over name)", who.ID)
	}
	if who.FullName != "Alice" {
		t.Fatalf("FullName = %q", who.FullName)
	}
}

func TestWhoAmI_RejectsTokenInErrorPaths(t *testing.T) {
	t.Parallel()
	canary := "CANARY_whoami_token_xyz"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope "+canary, http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	c := &Client{URL: srv.URL, User: "u", Token: canary, Client: srv.Client()}
	_, err := c.WhoAmI(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("token leaked in error: %v", err)
	}
}
