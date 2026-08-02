package authlab_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/auth"
	"github.com/hilather/go-jenkins-mcp/internal/authlab"
)

// OAUTH-009 offline bridge: mock RS (HOST-013) responses classify under
// OfflineFallthroughFixtures / ClassifyFallthroughProbe.
// Invalid Bearer must never succeed as Basic/anonymous on OAuth-required routes.
// Live jwt-auth-filter pin remains residual — do not claim live Entra Done.
func TestMockRS_ResponsesClassifyWithAuthFallthroughProbe(t *testing.T) {
	t.Parallel()
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := key.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	const iss = "http://127.0.0.1:18081"
	now := time.Unix(1_700_300_000, 0)
	rs, err := authlab.NewRSServer(authlab.RSConfig{
		Issuer:   iss,
		Audience: authlab.DefaultAudience,
		JWKS:     jwks,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(rs.Handler())
	t.Cleanup(ts.Close)

	// Invalid bearer → 401 + Bearer WWW-Authenticate → classifier Denied.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/whoAmI", nil)
	req.Header.Set("Authorization", "Bearer not-valid-jwt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
	eval := auth.ClassifyFallthroughProbe(auth.FallthroughProbeInput{
		StatusCode:      resp.StatusCode,
		WWWAuthenticate: resp.Header.Get("WWW-Authenticate"),
		BodyClass:       auth.ClassifyResponseBodyClass(body),
	})
	if !eval.Denied || eval.FallthroughDetected {
		t.Fatalf("mock RS invalid bearer must classify Denied: %+v", eval)
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "bearer") {
		t.Fatalf("WWW-Authenticate: %q", resp.Header.Get("WWW-Authenticate"))
	}

	// Wrong aud mint → 401 → Denied (no Basic fallthrough).
	badAud, err := key.MintAccessToken(authlab.MintParams{
		Issuer: iss, Subject: "alice", Audience: "https://graph.microsoft.com",
		TTL: time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/whoAmI", nil)
	req2.Header.Set("Authorization", "Bearer "+badAud)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	eval2 := auth.ClassifyFallthroughProbe(auth.FallthroughProbeInput{
		StatusCode:      resp2.StatusCode,
		WWWAuthenticate: resp2.Header.Get("WWW-Authenticate"),
		BodyClass:       auth.ClassifyResponseBodyClass(b2),
	})
	if !eval2.Denied {
		t.Fatalf("wrong aud must Denied: status=%d eval=%+v", resp2.StatusCode, eval2)
	}

	// Basic alone → 401 (no fallthrough) → Denied.
	req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/mcp-rs/check", nil)
	req3.Header.Set("Authorization", "Basic YWRtaW46dGVzdA==")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	b3, _ := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()
	eval3 := auth.ClassifyFallthroughProbe(auth.FallthroughProbeInput{
		StatusCode:      resp3.StatusCode,
		WWWAuthenticate: resp3.Header.Get("WWW-Authenticate"),
		BodyClass:       auth.ClassifyResponseBodyClass(b3),
	})
	if !eval3.Denied {
		t.Fatalf("Basic alone must not succeed: status=%d eval=%+v", resp3.StatusCode, eval3)
	}
}

// OAUTH-009 expand: table-driven mock RS classifier matrix on OAuth-required
// routes. Invalid Bearer / Basic / anonymous never classify as success.
// Cross-check OfflineFallthroughFixtures self-consistency.
func TestMockRS_OAuthRequiredRouteFallthroughMatrix(t *testing.T) {
	t.Parallel()
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := key.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	const iss = "http://127.0.0.1:18081"
	now := time.Unix(1_700_301_000, 0)
	rs, err := authlab.NewRSServer(authlab.RSConfig{
		Issuer:   iss,
		Audience: authlab.DefaultAudience,
		JWKS:     jwks,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(rs.Handler())
	t.Cleanup(ts.Close)

	good, err := key.MintAccessToken(authlab.MintParams{
		Issuer: iss, Subject: "alice", Audience: authlab.DefaultAudience,
		TTL: time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := key.MintAccessToken(authlab.MintParams{
		Issuer: iss, Subject: "alice", Audience: authlab.DefaultAudience,
		ExpOffset: -time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongIss, err := key.MintAccessToken(authlab.MintParams{
		Issuer: "https://evil.example", Subject: "alice", Audience: authlab.DefaultAudience,
		TTL: time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mock RS OAuth-required paths (whoAmI + mcp-rs check).
	routes := []string{"/api/whoAmI", "/mcp-rs/check"}

	type row struct {
		name       string
		authz      string
		wantStatus int
		wantDenied bool
		// wantOK is true when a valid Bearer should authenticate (not fallthrough).
		wantOK bool
	}
	rows := []row{
		{name: "invalid_bearer", authz: "Bearer not-a-jwt", wantStatus: http.StatusUnauthorized, wantDenied: true},
		{name: "empty_bearer", authz: "Bearer ", wantStatus: http.StatusUnauthorized, wantDenied: true},
		{name: "basic_alone", authz: "Basic YWRtaW46dGVzdA==", wantStatus: http.StatusUnauthorized, wantDenied: true},
		{name: "none", authz: "", wantStatus: http.StatusUnauthorized, wantDenied: true},
		{name: "expired_bearer", authz: "Bearer " + expired, wantStatus: http.StatusUnauthorized, wantDenied: true},
		{name: "wrong_iss_bearer", authz: "Bearer " + wrongIss, wantStatus: http.StatusUnauthorized, wantDenied: true},
		{name: "valid_bearer", authz: "Bearer " + good, wantStatus: http.StatusOK, wantOK: true},
	}

	client := ts.Client()
	for _, route := range routes {
		route := route
		for _, r := range rows {
			r := r
			t.Run(strings.TrimPrefix(route, "/")+"_"+r.name, func(t *testing.T) {
				t.Parallel()
				req, err := http.NewRequest(http.MethodGet, ts.URL+route, nil)
				if err != nil {
					t.Fatal(err)
				}
				if r.authz != "" {
					req.Header.Set("Authorization", r.authz)
				}
				// Tempt session fallthrough (mock RS must ignore cookies).
				req.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: "ui-session"})
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				if resp.StatusCode != r.wantStatus {
					t.Fatalf("status %d want %d body=%q", resp.StatusCode, r.wantStatus, string(body))
				}
				// Canary: never echo bearer material.
				if strings.Contains(string(body), good) || (len(expired) > 16 && strings.Contains(string(body), expired[:16])) {
					t.Fatal("token material leaked in response body")
				}
				eval := auth.ClassifyFallthroughProbe(auth.FallthroughProbeInput{
					StatusCode:      resp.StatusCode,
					WWWAuthenticate: resp.Header.Get("WWW-Authenticate"),
					BodyClass:       auth.ClassifyResponseBodyClass(body),
				})
				if r.wantDenied {
					if !eval.Denied || eval.FallthroughDetected {
						t.Fatalf("Regression: invalid Bearer/Basic/anon must classify Denied (no success fallthrough): %+v", eval)
					}
					return
				}
				if r.wantOK {
					// Valid path is 200 authenticated — not a fallthrough probe failure
					// (fallthrough probes only apply to invalid Bearer). Ensure we got
					// authenticated shape and not anonymous.
					bc := auth.ClassifyResponseBodyClass(body)
					if bc != auth.BodyClassWhoAmIAuthenticated && !strings.Contains(string(body), `"authenticated":true`) {
						// mock RS writes authenticated:true
						if !strings.Contains(string(body), "alice") && !strings.Contains(string(body), `"ok":true`) {
							t.Fatalf("valid bearer body unexpected: %s bc=%s", body, bc)
						}
					}
					if eval.Denied {
						t.Fatalf("valid bearer must not classify Denied: %+v", eval)
					}
					// 2xx with authenticated is FallthroughDetected by design of the
					// invalid-bearer classifier — callers only use it after invalid Bearer.
					// Here we only assert the HTTP contract (200 + principal).
					return
				}
			})
		}
	}

	// OfflineFallthroughFixtures remain self-consistent and include Basic/anon rows.
	fixtures := auth.OfflineFallthroughFixtures()
	if len(fixtures) < 12 {
		t.Fatalf("fixture floor: %d", len(fixtures))
	}
	var sawBasicAuthn, sawAnon bool
	for _, f := range fixtures {
		got := auth.ClassifyFallthroughProbe(f.Input)
		if got.Denied != f.WantDenied || got.FallthroughDetected != f.WantFallthrough {
			t.Errorf("fixture %s mismatch: got denied=%v fall=%v", f.ID, got.Denied, got.FallthroughDetected)
		}
		if f.ID == "200_whoami_authenticated_basic_www" {
			sawBasicAuthn = true
		}
		if f.ID == "200_whoami_anonymous" || f.ID == "200_whoami_anonymous_bearer_www" {
			sawAnon = true
		}
	}
	if !sawBasicAuthn || !sawAnon {
		t.Fatalf("OfflineFallthroughFixtures missing Basic/anon expand rows basic=%v anon=%v", sawBasicAuthn, sawAnon)
	}
}
