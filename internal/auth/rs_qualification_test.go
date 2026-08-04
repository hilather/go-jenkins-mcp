package auth_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
)

// OAUTH-009: named contract constants must stay fail-closed.
func TestRSQualificationConstants(t *testing.T) {
	t.Parallel()
	if !auth.FallthroughMustDeny {
		t.Fatal("FallthroughMustDeny must be true")
	}
	if auth.RequiredJWKSOutageBehavior != auth.JWKSOutageFailClosed {
		t.Fatalf("JWKS outage: %q", auth.RequiredJWKSOutageBehavior)
	}
	if auth.JWKSOutageFailOpen == auth.JWKSOutageFailClosed {
		t.Fatal("outage labels must differ")
	}
	if len(auth.RequiredMCPRoutes) < 8 {
		t.Fatalf("required routes too small: %d", len(auth.RequiredMCPRoutes))
	}
	outside := auth.RequiredOutsideAPIGlobRoutes()
	if len(outside) < 3 {
		t.Fatalf("expected progressive/artifact/wfapi outside api glob, got %d", len(outside))
	}
	// Inventory must include progressive log + artifact (acceptance).
	ids := map[string]bool{}
	for _, r := range auth.RequiredMCPRoutes {
		ids[r.ID] = true
		if r.ExamplePath == "" || r.PathPattern == "" {
			t.Fatalf("route %s incomplete", r.ID)
		}
	}
	for _, want := range []string{"whoami", "progressive_text", "artifact_download", "wfapi_describe", "queue_item"} {
		if !ids[want] {
			t.Errorf("missing required route id %q", want)
		}
	}
}

func TestEvaluateInvalidBearerResponse(t *testing.T) {
	t.Parallel()
	pass := auth.EvaluateInvalidBearerResponse(http.StatusUnauthorized, false, false)
	if !pass.Denied || pass.FallthroughDetected {
		t.Fatalf("%+v", pass)
	}
	pass403 := auth.EvaluateInvalidBearerResponse(http.StatusForbidden, false, false)
	if !pass403.Denied {
		t.Fatalf("%+v", pass403)
	}

	// Regression: invalid bearer must not succeed via session/anonymous.
	fall := auth.EvaluateInvalidBearerResponse(http.StatusOK, true, false)
	if !fall.FallthroughDetected || fall.Denied {
		t.Fatalf("authenticated fallthrough: %+v", fall)
	}
	anon := auth.EvaluateInvalidBearerResponse(http.StatusOK, false, true)
	if !anon.FallthroughDetected {
		t.Fatalf("anon fallthrough: %+v", anon)
	}
	okBare := auth.EvaluateInvalidBearerResponse(http.StatusOK, false, false)
	if !okBare.FallthroughDetected {
		t.Fatalf("2xx still fallthrough: %+v", okBare)
	}
	inc := auth.EvaluateInvalidBearerResponse(http.StatusBadGateway, false, false)
	if inc.Denied || inc.FallthroughDetected {
		t.Fatalf("5xx inconclusive: %+v", inc)
	}
}

// Table-driven FallthroughMustDeny pure scenarios (status + WWW-Authenticate + body class).
func TestClassifyFallthroughProbe_Scenarios(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		in         auth.FallthroughProbeInput
		wantDenied bool
		wantFall   bool
		reasonSub  string
	}{
		{
			name: "401_bearer_challenge",
			in: auth.FallthroughProbeInput{
				StatusCode:      http.StatusUnauthorized,
				WWWAuthenticate: `Bearer realm="Jenkins", error="invalid_token"`,
				BodyClass:       auth.BodyClassErrorJSON,
			},
			wantDenied: true,
			reasonSub:  "Bearer WWW-Authenticate",
		},
		{
			name: "403_no_www",
			in: auth.FallthroughProbeInput{
				StatusCode: http.StatusForbidden,
				BodyClass:  auth.BodyClassEmpty,
			},
			wantDenied: true,
			reasonSub:  "denied",
		},
		{
			name: "401_basic_challenge_still_deny",
			in: auth.FallthroughProbeInput{
				StatusCode:      http.StatusUnauthorized,
				WWWAuthenticate: `Basic realm="Jenkins"`,
				BodyClass:       auth.BodyClassEmpty,
			},
			wantDenied: true,
			reasonSub:  "non-Bearer",
		},
		{
			name: "200_whoami_authenticated",
			in: auth.FallthroughProbeInput{
				StatusCode: http.StatusOK,
				BodyClass:  auth.BodyClassWhoAmIAuthenticated,
			},
			wantFall:  true,
			reasonSub: "authenticated",
		},
		{
			name: "200_whoami_anonymous",
			in: auth.FallthroughProbeInput{
				StatusCode: http.StatusOK,
				BodyClass:  auth.BodyClassWhoAmIAnonymous,
			},
			wantFall:  true,
			reasonSub: "anonymous",
		},
		{
			name: "200_html_login",
			in: auth.FallthroughProbeInput{
				StatusCode: http.StatusOK,
				BodyClass:  auth.BodyClassHTMLLogin,
			},
			wantFall:  true,
			reasonSub: "HTML login",
		},
		{
			name: "200_html_error",
			in: auth.FallthroughProbeInput{
				StatusCode: http.StatusOK,
				BodyClass:  auth.BodyClassHTMLError,
			},
			wantFall:  true,
			reasonSub: "HTML error",
		},
		{
			name: "200_empty_body",
			in: auth.FallthroughProbeInput{
				StatusCode: http.StatusOK,
				BodyClass:  auth.BodyClassEmpty,
			},
			wantFall:  true,
			reasonSub: "empty body",
		},
		{
			name: "204_empty",
			in: auth.FallthroughProbeInput{
				StatusCode: http.StatusNoContent,
				BodyClass:  auth.BodyClassEmpty,
			},
			wantFall:  true,
			reasonSub: "empty body",
		},
		{
			name: "401_empty_bearer_www",
			in: auth.FallthroughProbeInput{
				StatusCode:      http.StatusUnauthorized,
				WWWAuthenticate: `Bearer realm="Jenkins", error="invalid_token"`,
				BodyClass:       auth.BodyClassEmpty,
			},
			wantDenied: true,
			reasonSub:  "Bearer WWW-Authenticate",
		},
		{
			name: "401_html_error_bearer_www",
			in: auth.FallthroughProbeInput{
				StatusCode:      http.StatusUnauthorized,
				WWWAuthenticate: `Bearer realm="Jenkins"`,
				BodyClass:       auth.BodyClassHTMLError,
			},
			wantDenied: true,
			reasonSub:  "Bearer",
		},
		{
			name: "200_error_json_still_fail",
			in: auth.FallthroughProbeInput{
				StatusCode: http.StatusOK,
				BodyClass:  auth.BodyClassErrorJSON,
			},
			wantFall:  true,
			reasonSub: "error JSON",
		},
		{
			name: "200_unknown_body",
			in: auth.FallthroughProbeInput{
				StatusCode: http.StatusOK,
				BodyClass:  auth.BodyClassUnknown,
			},
			wantFall:  true,
			reasonSub: "possible fallthrough",
		},
		{
			name: "502_inconclusive",
			in: auth.FallthroughProbeInput{
				StatusCode: http.StatusBadGateway,
				BodyClass:  auth.BodyClassEmpty,
			},
			reasonSub: "inconclusive",
		},
		{
			name: "status_0_transport",
			in: auth.FallthroughProbeInput{
				StatusCode: 0,
			},
			reasonSub: "transport",
		},
		{
			name: "flags_only_authenticated",
			in: auth.FallthroughProbeInput{
				StatusCode:          http.StatusOK,
				WhoAmIAuthenticated: true,
			},
			wantFall:  true,
			reasonSub: "authenticated",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := auth.ClassifyFallthroughProbe(tc.in)
			if got.Denied != tc.wantDenied || got.FallthroughDetected != tc.wantFall {
				t.Fatalf("denied=%v fall=%v want denied=%v fall=%v (%+v)",
					got.Denied, got.FallthroughDetected, tc.wantDenied, tc.wantFall, got)
			}
			if tc.reasonSub != "" && !strings.Contains(got.Reason, tc.reasonSub) {
				t.Fatalf("reason %q missing %q", got.Reason, tc.reasonSub)
			}
		})
	}
}

func TestClassifyResponseBodyClass(t *testing.T) {
	t.Parallel()
	if auth.ClassifyResponseBodyClass(nil) != auth.BodyClassEmpty {
		t.Fatal("nil")
	}
	if auth.ClassifyResponseBodyClass([]byte("   \n\t  ")) != auth.BodyClassEmpty {
		t.Fatal("whitespace empty")
	}
	if auth.ClassifyResponseBodyClass([]byte(`{"authenticated":true,"anonymous":false}`)) != auth.BodyClassWhoAmIAuthenticated {
		t.Fatal("authn")
	}
	if auth.ClassifyResponseBodyClass([]byte(`{"authenticated":false,"anonymous":true}`)) != auth.BodyClassWhoAmIAnonymous {
		t.Fatal("anon")
	}
	if auth.ClassifyResponseBodyClass([]byte(`{"error":"invalid_token"}`)) != auth.BodyClassErrorJSON {
		t.Fatal("err")
	}
	html := []byte(`<!DOCTYPE html><html><form><input type="password" name="j_password"></form>`)
	if auth.ClassifyResponseBodyClass(html) != auth.BodyClassHTMLLogin {
		t.Fatal("html login")
	}
	// Wave 33: HTML error page (Stapler/404) without login form.
	htmlErr := []byte(`<!DOCTYPE html><html><head><title>Error 404 Not Found</title></head><body><h1>Not Found</h1><p>Stapler</p></body></html>`)
	if auth.ClassifyResponseBodyClass(htmlErr) != auth.BodyClassHTMLError {
		t.Fatalf("html error: got %q", auth.ClassifyResponseBodyClass(htmlErr))
	}
	html500 := []byte(`<!DOCTYPE html><html><body><h1>Oops!</h1><p>Something went wrong</p><pre>javax.servlet.ServletException</pre></body></html>`)
	if auth.ClassifyResponseBodyClass(html500) != auth.BodyClassHTMLError {
		t.Fatalf("html 500: got %q", auth.ClassifyResponseBodyClass(html500))
	}
	if auth.ClassifyResponseBodyClass([]byte("not json")) != auth.BodyClassUnknown {
		t.Fatal("unknown")
	}
}

// Wave 33 + OAUTH-009 expand: OfflineFallthroughFixtures matrix is self-consistent
// and covers empty body, HTML error, WWW-Authenticate Bearer, Basic/anonymous
// fallthrough fail-closed, and 401 status-wins rows.
func TestOfflineFallthroughFixtures_Matrix(t *testing.T) {
	t.Parallel()
	fixtures := auth.OfflineFallthroughFixtures()
	if len(fixtures) < 12 {
		t.Fatalf("expected expanded fixture matrix, got %d", len(fixtures))
	}
	seen := map[string]bool{}
	var hasEmpty, hasHTMLErr, hasBearerWWW, hasAuthnFailClosed bool
	var hasBasicAuthnFall, hasAnonFall, has401StatusWins bool
	for _, f := range fixtures {
		if f.ID == "" || seen[f.ID] {
			t.Fatalf("bad/duplicate fixture id %q", f.ID)
		}
		seen[f.ID] = true
		got := auth.ClassifyFallthroughProbe(f.Input)
		if got.Denied != f.WantDenied || got.FallthroughDetected != f.WantFallthrough {
			t.Errorf("%s: denied=%v fall=%v want denied=%v fall=%v reason=%q",
				f.ID, got.Denied, got.FallthroughDetected, f.WantDenied, f.WantFallthrough, got.Reason)
		}
		if f.Input.BodyClass == auth.BodyClassEmpty {
			hasEmpty = true
		}
		if f.Input.BodyClass == auth.BodyClassHTMLError {
			hasHTMLErr = true
		}
		if strings.Contains(strings.ToLower(f.Input.WWWAuthenticate), "bearer") {
			hasBearerWWW = true
		}
		if f.WantFallthrough && (f.Input.BodyClass == auth.BodyClassWhoAmIAuthenticated || f.Input.WhoAmIAuthenticated) {
			hasAuthnFailClosed = true
		}
		if f.ID == "200_whoami_authenticated_basic_www" {
			hasBasicAuthnFall = true
			if !f.WantFallthrough {
				t.Fatal("Basic+authn 200 must be FallthroughDetected")
			}
		}
		if f.ID == "200_whoami_anonymous" || f.ID == "200_whoami_anonymous_bearer_www" {
			hasAnonFall = true
		}
		if f.ID == "401_whoami_authn_body_still_deny" || f.ID == "401_whoami_anon_body_still_deny" {
			has401StatusWins = true
			if !f.WantDenied || f.WantFallthrough {
				t.Fatalf("%s must be Denied only", f.ID)
			}
		}
	}
	if !hasEmpty || !hasHTMLErr || !hasBearerWWW || !hasAuthnFailClosed {
		t.Fatalf("matrix incomplete empty=%v htmlErr=%v bearerWWW=%v authnFail=%v",
			hasEmpty, hasHTMLErr, hasBearerWWW, hasAuthnFailClosed)
	}
	if !hasBasicAuthnFall || !hasAnonFall || !has401StatusWins {
		t.Fatalf("OAUTH-009 Basic/anon expand missing basicAuthn=%v anon=%v statusWins=%v",
			hasBasicAuthnFall, hasAnonFall, has401StatusWins)
	}
	// Format is secret-free and mentions live lab residual.
	text := auth.FormatFallthroughClassifierMatrix()
	if !strings.Contains(text, "401_empty_bearer_www") || !strings.Contains(text, "live jwt-auth-filter") {
		t.Fatalf("format matrix: %s", text)
	}
	if !strings.Contains(text, "200_whoami_authenticated_basic_www") {
		t.Fatalf("format matrix missing Basic fallthrough row: %s", text)
	}
	canary := "CANARY_secret_bearer_must_not_appear_xyz"
	if strings.Contains(text, canary) || strings.Contains(text, "password=") {
		t.Fatal("matrix looks secret-bearing")
	}
}

// Regression: invalid-bearer 200 authenticated is always FallthroughDetected (fail closed).
func TestInvalidBearerAuthenticatedSuccess_FailClosed(t *testing.T) {
	t.Parallel()
	eval := auth.ClassifyFallthroughProbe(auth.FallthroughProbeInput{
		StatusCode:          http.StatusOK,
		BodyClass:           auth.BodyClassWhoAmIAuthenticated,
		WhoAmIAuthenticated: true,
		WWWAuthenticate:     "", // no challenge on success path
	})
	if !eval.FallthroughDetected || eval.Denied {
		t.Fatalf("Regression: invalid bearer authenticated success must fail closed: %+v", eval)
	}
	if !strings.Contains(eval.Reason, "authenticated") {
		t.Fatalf("reason: %q", eval.Reason)
	}
}

func TestJWKSOutageFailClosedContracts(t *testing.T) {
	t.Parallel()
	ok := auth.EvaluateJWKSOutageBehavior(auth.JWKSOutageFailClosed)
	if !ok.Acceptable || ok.Behavior != auth.JWKSOutageFailClosed {
		t.Fatalf("%+v", ok)
	}
	bad := auth.EvaluateJWKSOutageBehavior(auth.JWKSOutageFailOpen)
	if bad.Acceptable {
		t.Fatalf("fail_open must be unacceptable: %+v", bad)
	}
	empty := auth.EvaluateJWKSOutageBehavior("")
	if empty.Acceptable {
		t.Fatal("unset unacceptable")
	}
	weird := auth.EvaluateJWKSOutageBehavior("cache_forever")
	if weird.Acceptable {
		t.Fatal("unknown unacceptable")
	}

	// Pure availability → may-verify matrix.
	for _, avail := range []auth.JWKSAvailability{
		auth.JWKSUnreachable, auth.JWKSEmpty, auth.JWKSNil, auth.JWKSAvailability("bogus"),
	} {
		r := auth.EvaluateJWKSOutageForVerification(avail)
		if r.MayVerify || !r.FailClosed {
			t.Fatalf("%s: %+v", avail, r)
		}
	}
	avail := auth.EvaluateJWKSOutageForVerification(auth.JWKSAvailable)
	if !avail.MayVerify || avail.FailClosed {
		t.Fatalf("available: %+v", avail)
	}
}

func TestJWKSOutage_ValidateAccessTokenFailClosed(t *testing.T) {
	t.Parallel()
	priv, jwks := testRSAJWKS(t, "k-outage")
	now := time.Unix(1_700_000_000, 0)
	tok := mustSignRS256(t, priv, "k-outage", map[string]any{
		"iss":       "https://issuer.example.com",
		"sub":       "u1",
		"aud":       "https://jenkins.example.com",
		"exp":       now.Add(time.Hour).Unix(),
		"token_use": "access_token",
	})
	params := auth.AccessTokenParams{
		Issuer:   "https://issuer.example.com",
		Audience: "https://jenkins.example.com",
		Now:      func() time.Time { return now },
	}
	// Good path control.
	if _, err := auth.ValidateAccessToken(tok, jwks, params); err != nil {
		t.Fatalf("control: %v", err)
	}
	// Regression: nil JWKS → fail closed (outage / never fetched).
	if _, err := auth.ValidateAccessToken(tok, nil, params); err == nil {
		t.Fatal("nil JWKS must fail closed")
	} else if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code: %v", apperr.CodeOf(err))
	}
	// Empty key set.
	if _, err := auth.ValidateAccessToken(tok, &auth.JWKS{}, params); err == nil {
		t.Fatal("empty JWKS must fail closed")
	}
	// FetchJWKS HTTP failure must not yield keys for verification.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	got, err := auth.FetchJWKS(context.Background(), srv.Client(), srv.URL)
	if err == nil || got != nil {
		t.Fatalf("fetch outage must error: got=%v err=%v", got, err)
	}
	// Contract: outage behavior constant is fail_closed only.
	if !auth.EvaluateJWKSOutageBehavior(auth.RequiredJWKSOutageBehavior).Acceptable {
		t.Fatal("RequiredJWKSOutageBehavior must be acceptable")
	}
}

func TestRequiredMCPRoutesInventoryCompleteness(t *testing.T) {
	t.Parallel()
	issues := auth.ValidateRequiredMCPRoutesInventory()
	if len(issues) != 0 {
		t.Fatalf("inventory issues: %+v", issues)
	}
	// IDs unique (explicit assertion for test name clarity).
	seen := map[string]bool{}
	var progressiveOutside bool
	for _, r := range auth.RequiredMCPRoutes {
		if seen[r.ID] {
			t.Fatalf("duplicate id %q", r.ID)
		}
		seen[r.ID] = true
		if r.ID == "progressive_text" {
			if !r.OutsideAPIGlob {
				t.Fatal("progressive_text must be OutsideAPIGlob")
			}
			if r.Category != auth.RSRouteProgressive {
				t.Fatalf("category %q", r.Category)
			}
			progressiveOutside = true
		}
	}
	if !progressiveOutside {
		t.Fatal("progressive_text missing or unmarked")
	}
	for _, id := range []string{"artifact_download", "wfapi_describe", "wfapi_node_log"} {
		if !seen[id] {
			t.Errorf("missing %s", id)
		}
	}
}

func TestParseProtectedResourceMetadata_RFC9728(t *testing.T) {
	t.Parallel()
	good := []byte(`{
		"resource": "https://jenkins.example.com/",
		"authorization_servers": ["https://login.example.com/tenant/v2.0"],
		"bearer_methods_supported": ["header"],
		"scopes_supported": ["jenkins.read"],
		"resource_name": "Corp Jenkins"
	}`)
	m, err := auth.ParseProtectedResourceMetadata(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateProtectedResourceMetadata(m); err != nil {
		t.Fatal(err)
	}
	if m.Resource != "https://jenkins.example.com/" || len(m.AuthorizationServers) != 1 {
		t.Fatalf("%+v", m)
	}

	// Missing resource fails validation.
	noRes, err := auth.ParseProtectedResourceMetadata([]byte(`{"authorization_servers":["https://a.example"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateProtectedResourceMetadata(noRes); err == nil {
		t.Fatal("resource required")
	}

	// Empty / invalid parse.
	if _, err := auth.ParseProtectedResourceMetadata(nil); err == nil {
		t.Fatal("empty")
	}
	if _, err := auth.ParseProtectedResourceMetadata([]byte(`{`)); err == nil {
		t.Fatal("bad json")
	}
	// Credential embedding rejected.
	bad, err := auth.ParseProtectedResourceMetadata([]byte(`{"resource":"https://user:pass@jenkins.example.com/"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateProtectedResourceMetadata(bad); err == nil {
		t.Fatal("embedded credentials")
	}
	if err := auth.ValidateProtectedResourceMetadata(nil); err == nil {
		t.Fatal("nil")
	}

	// Wave 33 PRM edge cases.
	rel, err := auth.ParseProtectedResourceMetadata([]byte(`{"resource":"/relative"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateProtectedResourceMetadata(rel); err == nil {
		t.Fatal("relative resource must fail")
	}
	ftp, err := auth.ParseProtectedResourceMetadata([]byte(`{"resource":"ftp://jenkins.example.com/"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateProtectedResourceMetadata(ftp); err == nil {
		t.Fatal("ftp scheme must fail")
	}
	emptyAS, err := auth.ParseProtectedResourceMetadata([]byte(`{"resource":"https://jenkins.example.com/","authorization_servers":[""]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateProtectedResourceMetadata(emptyAS); err == nil {
		t.Fatal("empty authorization_servers entry")
	}
	jwksCred, err := auth.ParseProtectedResourceMetadata([]byte(`{
		"resource":"https://jenkins.example.com/",
		"jwks_uri":"https://user:secret@idp.example.com/jwks"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateProtectedResourceMetadata(jwksCred); err == nil {
		t.Fatal("jwks_uri embedded credentials")
	}
	emptyScope, err := auth.ParseProtectedResourceMetadata([]byte(`{
		"resource":"https://jenkins.example.com/",
		"scopes_supported":["jenkins.read",""]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateProtectedResourceMetadata(emptyScope); err == nil {
		t.Fatal("empty scopes_supported entry")
	}
	// Minimal valid: resource only.
	min, err := auth.ParseProtectedResourceMetadata([]byte(`{"resource":"http://jenkins.lab.local/"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateProtectedResourceMetadata(min); err != nil {
		t.Fatalf("minimal resource-only: %v", err)
	}
}

// Simulated Jenkins RS: when Authorization Bearer is invalid → 401, even if a
// session cookie is present (no fallthrough). Models qualified jwt-auth-filter.
func TestSimulatedJenkinsRS_InvalidBearerNoFallthrough(t *testing.T) {
	t.Parallel()
	const validTok = "valid-lab-bearer-token"
	mux := http.NewServeMux()
	// Handler models fail-closed RS for any path under /.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			tok := strings.TrimSpace(authz[len("Bearer "):])
			if tok == "" || tok != validTok {
				// Qualified filter: deny; do not consult Cookie/JSESSIONID.
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
				return
			}
			// Valid bearer — ignore session cookie entirely.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"alice","fullName":"Alice","anonymous":false,"authenticated":true}`))
			return
		}
		// No bearer: optional session path (UI) — not used for MCP OAuth-required.
		if c, err := r.Cookie("JSESSIONID"); err == nil && c.Value == "ui-session" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"bob-ui","fullName":"Bob","anonymous":false,"authenticated":true}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"anonymous","anonymous":true,"authenticated":false}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Critical: invalid bearer + session cookie must still 401 (not 200 as bob-ui).
	paths := []string{
		"/whoAmI/api/json",
		"/job/demo/1/logText/progressiveText?start=0",
		"/job/demo/1/artifact/report.txt",
		"/job/demo/1/wfapi/describe",
		"/queue/item/1/api/json",
	}
	client := srv.Client()
	for _, p := range paths {
		p := p
		t.Run("deny_"+strings.ReplaceAll(p, "/", "_"), func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequest(http.MethodGet, srv.URL+p, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer totally-invalid")
			req.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: "ui-session"})
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			eval := auth.EvaluateInvalidBearerResponse(resp.StatusCode, false, false)
			if !eval.Denied {
				t.Fatalf("path %s status %d eval=%+v (must deny invalid bearer; no session fallthrough)",
					p, resp.StatusCode, eval)
			}
			if resp.StatusCode == http.StatusOK {
				t.Fatal("Regression: invalid bearer must not return 200 with session cookie fallthrough")
			}
		})
	}

	// Contrast: session alone (no bearer) may authenticate UI user — but MCP OAuth
	// path always sends bearer, so this path is not a substitute for RS.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/whoAmI/api/json", nil)
	req.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: "ui-session"})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session-only fixture: %d", resp.StatusCode)
	}

	// Valid bearer works without cookie.
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/whoAmI/api/json", nil)
	req2.Header.Set("Authorization", "Bearer "+validTok)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("valid bearer: %d", resp2.StatusCode)
	}
}

// Unqualified filter anti-pattern: invalid bearer falls through to session → 200.
// Documented so probes detect FallthroughDetected.
func TestSimulatedJenkinsRS_UnqualifiedFallthroughDetected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Anti-pattern: ignore failed bearer and use session.
		if c, err := r.Cookie("JSESSIONID"); err == nil && c.Value != "" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"bob","anonymous":false,"authenticated":true}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/whoAmI/api/json", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	req.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: "ui-session"})
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var who struct {
		Authenticated bool `json:"authenticated"`
		Anonymous     bool `json:"anonymous"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&who)
	eval := auth.EvaluateInvalidBearerResponse(resp.StatusCode, who.Authenticated, who.Anonymous)
	if !eval.FallthroughDetected {
		t.Fatalf("expected fallthrough detection: %+v who=%+v status=%d", eval, who, resp.StatusCode)
	}
}

// Multi-issuer: wrong iss fail closed even if signature verifies under a key present in JWKS.
func TestValidateAccessToken_MultiIssuerWrongIssuerFailClosed(t *testing.T) {
	t.Parallel()
	privA, jwksA := testRSAJWKS(t, "kid-a")
	privB, jwksB := testRSAJWKS(t, "kid-b")
	// Combined multi-issuer JWKS (rotation / multi-tenant anti-pattern without iss binding).
	combined := &auth.JWKS{Keys: append(append([]auth.JWK{}, jwksA.Keys...), jwksB.Keys...)}
	now := time.Unix(1_700_000_000, 0)

	// Token claims iss=A but signed with B's key — must fail (sig or iss depending on kid).
	tokWrongKey := mustSignRS256(t, privB, "kid-b", map[string]any{
		"iss":       "https://issuer-a.example.com",
		"sub":       "user-1",
		"aud":       "https://jenkins.example.com",
		"exp":       now.Add(time.Hour).Unix(),
		"token_use": "access_token",
	})
	// Even if signature verifies under kid-b, profile expects issuer-a — wait, sig verifies
	// and iss matches profile if we set issuer-a. The multi-issuer threat is: accept
	// iss from A when profile is B, or accept foreign iss when key is in shared JWKS.
	_, err := auth.ValidateAccessToken(tokWrongKey, combined, auth.AccessTokenParams{
		Issuer:   "https://issuer-b.example.com", // profile is B
		Audience: "https://jenkins.example.com",
		Now:      func() time.Time { return now },
	})
	if err == nil {
		t.Fatal("token iss=A against profile iss=B must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}

	// Correct iss=A signed by A against profile A — pass.
	tokGood := mustSignRS256(t, privA, "kid-a", map[string]any{
		"iss":       "https://issuer-a.example.com",
		"sub":       "user-1",
		"aud":       "https://jenkins.example.com",
		"exp":       now.Add(time.Hour).Unix(),
		"token_use": "access_token",
	})
	if _, err := auth.ValidateAccessToken(tokGood, combined, auth.AccessTokenParams{
		Issuer:   "https://issuer-a.example.com",
		Audience: "https://jenkins.example.com",
		Now:      func() time.Time { return now },
	}); err != nil {
		t.Fatalf("good multi-key set: %v", err)
	}

	// iss=B signed by A key (kid-a) — signature may verify under wrong issuer keys;
	// still must fail closed on iss mismatch when profile expects B... actually signed
	// by A with kid-a, claims iss=B: signature OK, iss matches profile B → this is a
	// lab mis-issue. Profile issuer match alone is the contract we enforce offline;
	// kid belongs to A. Signature verifies. That would pass JWT validation —
	// production RS must pin issuer↔JWKS. We document residual: use issuer-specific JWKS.
	// Explicit wrong-iss case already covered. Add: claims iss=B, signed A, profile A → fail.
	tokForeignIss := mustSignRS256(t, privA, "kid-a", map[string]any{
		"iss":       "https://issuer-b.example.com",
		"sub":       "user-1",
		"aud":       "https://jenkins.example.com",
		"exp":       now.Add(time.Hour).Unix(),
		"token_use": "access_token",
	})
	_, err = auth.ValidateAccessToken(tokForeignIss, jwksA, auth.AccessTokenParams{
		Issuer:   "https://issuer-a.example.com",
		Audience: "https://jenkins.example.com",
		Now:      func() time.Time { return now },
	})
	if err == nil {
		t.Fatal("foreign iss must fail closed")
	}
}

func TestBuildOfflineRSProbe(t *testing.T) {
	t.Parallel()
	oidc := auth.BuildOfflineRSProbe("oidc_bearer")
	if !oidc.FallthroughMustDeny || oidc.RequiredRouteCount != len(auth.RequiredMCPRoutes) {
		t.Fatalf("%+v", oidc)
	}
	if len(oidc.Warnings) == 0 {
		t.Fatal("oidc_bearer should warn about RS qualification")
	}
	if oidc.PathLevel != auth.CapLevelConditional {
		t.Fatalf("path level %q", oidc.PathLevel)
	}
	if !oidc.InventoryOK || !oidc.JWKSOutageAcceptable {
		t.Fatalf("inventory/jwks: %+v", oidc)
	}
	if oidc.ThreatsContractTested < 4 {
		t.Fatalf("expected mostly contract_tested threats, got %d", oidc.ThreatsContractTested)
	}
	if len(oidc.OfflineAutomated) < 4 {
		t.Fatalf("offline automated list thin: %v", oidc.OfflineAutomated)
	}
	text := auth.FormatRSProbeText(oidc)
	if !strings.Contains(text, "fallthrough_must_deny") {
		t.Fatalf("format missing fallthrough: %s", text)
	}
	if !strings.Contains(text, auth.ThreatInvalidBearerFallthrough) {
		t.Fatalf("format missing threat id: %s", text)
	}
	if !strings.Contains(text, "offline_automated") {
		t.Fatalf("format missing offline_automated: %s", text)
	}
	if !strings.Contains(text, "inventory_ok") {
		t.Fatalf("format missing inventory_ok: %s", text)
	}

	sum := auth.BuildOfflineRSQualificationSummary("oidc_bearer")
	if !sum.InventoryOK || sum.RequiredRouteCount != len(auth.RequiredMCPRoutes) {
		t.Fatalf("%+v", sum)
	}
	if len(sum.LiveLabResiduals) == 0 || sum.Doc == "" {
		t.Fatalf("summary residuals/doc: %+v", sum)
	}
	if sum.FallthroughFixtureCount < 12 || !sum.ClassifierMatrixDoneStar || !sum.LiveLabStillRequired {
		t.Fatalf("Wave 33 summary fields: %+v", sum)
	}
	if !strings.Contains(text, "classifier_fixtures") {
		t.Fatalf("format missing classifier_fixtures: %s", text)
	}
	// JSON-safe (no secrets): marshal for self-check embedding.
	b, err := json.Marshal(sum)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "Bearer ey") || strings.Contains(string(b), "password") {
		t.Fatal("summary looks secret-bearing")
	}

	api := auth.BuildOfflineRSProbe(string(auth.MethodAPIToken))
	if len(api.Notes) == 0 {
		t.Fatal("api_token notes")
	}
	// oic-auth warning constant used by doctor.
	if !strings.Contains(auth.WarnOnlyOICAuthWithoutRS, "oic-auth") {
		t.Fatal("oic-auth warn constant")
	}
}

func TestDefaultRSThreatChecklist(t *testing.T) {
	t.Parallel()
	cl := auth.DefaultRSThreatChecklist()
	if len(cl) < 5 {
		t.Fatal(len(cl))
	}
	found := map[string]auth.RSThreatStatus{}
	for _, th := range cl {
		found[th.ID] = th.Status
	}
	if found[auth.ThreatInvalidBearerFallthrough] != auth.RSThreatContractTested {
		t.Fatal("fallthrough should be contract_tested offline")
	}
	// MCP-side JWKS outage fail-closed is offline contract_tested; live RS cache residual in Residuals.
	if found[auth.ThreatJWKSOutage] != auth.RSThreatContractTested {
		t.Fatal("jwks outage MCP contract should be contract_tested")
	}
	if found[auth.ThreatAlgNone] != auth.RSThreatContractTested {
		t.Fatal("alg none contract tested")
	}
	if found[auth.ThreatMultiIssuer] != auth.RSThreatContractTested {
		t.Fatal("multi issuer contract tested")
	}
}

func TestRSQualificationDocPresent(t *testing.T) {
	t.Parallel()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "docs", "auth", "jwt-auth-filter-qualification.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("qualification doc missing: %v", err)
	}
	text := string(data)
	for _, s := range []string{
		"invalid_bearer_fallthrough",
		"incomplete_route_coverage",
		"jwks_outage",
		"multi_issuer",
		"alg_none",
		"progressiveText",
		"FallthroughMustDeny",
		"oauth probe-rs",
		"TBD",
		"offline-automated",
		"ClassifyFallthroughProbe",
		"RFC 9728",
		"html_error",
		"OfflineFallthroughFixtures",
		"implemented",
		"free-lab",
		"live lab",
		"wrong_aud",
		"live-oauth",
		"GWY-003",
		"Mode B",
	} {
		if !strings.Contains(text, s) {
			t.Errorf("qualification doc missing %q", s)
		}
	}
}

// OAUTH-009 expand: offline fail-closed Bearer claim matrix on Jenkins-shaped
// paths (RequiredMCPRoutes). Wrong aud / exp / iss rejected; ID token never
// accepted as API credential; invalid Bearer does not fall through to session.
// Live jwt-auth-filter / Entra pin remains residual — this does not claim Done.
func TestOAUTH009_OfflineBearerClaimMatrix_JenkinsShapedPaths(t *testing.T) {
	t.Parallel()
	priv, jwks := testRSAJWKS(t, "oauth009-kid")
	now := time.Unix(1_700_100_000, 0)
	const (
		issuer = "https://idp.example.com/oauth009"
		aud    = "api://jenkins-corp-resource"
	)
	params := auth.AccessTokenParams{
		Issuer:   issuer,
		Audience: aud,
		Now:      func() time.Time { return now },
	}
	goodClaims := func(mut func(map[string]any)) string {
		c := map[string]any{
			"iss":       issuer,
			"sub":       "alice-oauth009",
			"aud":       aud,
			"exp":       now.Add(time.Hour).Unix(),
			"token_use": "access_token",
		}
		if mut != nil {
			mut(c)
		}
		return mustSignRS256(t, priv, "oauth009-kid", c)
	}
	goodTok := goodClaims(nil)

	// Claim-level fail-closed (MCP ValidateAccessToken for JWT-shaped tokens).
	// Note: non-JWT "opaque" strings are intentionally accepted at MCP layer
	// (whoAmI residual); simulated RS below still rejects non-JWT Bearer.
	claimCases := []struct {
		name string
		tok  string
	}{
		{"wrong_aud", goodClaims(func(m map[string]any) { m["aud"] = "https://graph.microsoft.com" })},
		{"wrong_iss", goodClaims(func(m map[string]any) { m["iss"] = "https://evil.example.com" })},
		{"expired", goodClaims(func(m map[string]any) { m["exp"] = now.Add(-time.Hour).Unix() })},
		{"id_token_use", goodClaims(func(m map[string]any) { m["token_use"] = "id_token" })},
		{"empty", ""},
		// Three-segment JWT shape with garbage signature/payload.
		{"malformed_jwt", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.not-a-real-sig"},
	}
	for _, tc := range claimCases {
		tc := tc
		t.Run("validate_"+tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := auth.ValidateAccessToken(tc.tok, jwks, params)
			if err == nil {
				t.Fatalf("%s must fail closed", tc.name)
			}
			if strings.Contains(err.Error(), goodTok) || (tc.tok != "" && len(tc.tok) > 24 && strings.Contains(err.Error(), tc.tok[:24])) {
				t.Fatalf("%s error leaked token material", tc.name)
			}
		})
	}
	// Good token accepted offline.
	if _, err := auth.ValidateAccessToken(goodTok, jwks, params); err != nil {
		t.Fatalf("good token: %v", err)
	}

	// Simulated JWT RS: only valid Jenkins-audience JWTs succeed; when Bearer is
	// present and invalid/opaque/wrong-claim → 401 even with JSESSIONID (no fallthrough).
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			tok := strings.TrimSpace(authz[len("Bearer "):])
			// jwt-auth-filter-shaped RS: Bearer present must be JWT and validate;
			// opaque/garbage never fall through to session/Basic.
			if auth.ClassifyAccessToken(tok) != auth.TokenFormJWT {
				w.Header().Set("WWW-Authenticate", `Bearer realm="Jenkins", error="invalid_token"`)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
				return
			}
			res, err := auth.ValidateAccessToken(tok, jwks, params)
			if err != nil || res.Form != auth.TokenFormJWT {
				// Fail closed: never consult Cookie or Basic after invalid Bearer.
				w.Header().Set("WWW-Authenticate", `Bearer realm="Jenkins", error="invalid_token"`)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"alice-oauth009","authenticated":true,"anonymous":false}`))
			return
		}
		// No Bearer: optional UI session (not MCP OAuth path).
		if c, err := r.Cookie("JSESSIONID"); err == nil && c.Value == "ui-session" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"bob-ui","authenticated":true,"anonymous":false}`))
			return
		}
		if strings.HasPrefix(strings.ToLower(authz), "basic ") {
			// Basic alone may work for non-OAuth pilot — but not as Bearer fallthrough.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"basic-user","authenticated":true,"anonymous":false}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := srv.Client()

	// Every RequiredMCPRoutes example path: invalid claim tokens → 401, classifier Denied.
	paths := make([]string, 0, len(auth.RequiredMCPRoutes))
	for _, r := range auth.RequiredMCPRoutes {
		paths = append(paths, r.ExamplePath)
	}
	// Ensure outside-api-glob routes present.
	if len(auth.RequiredOutsideAPIGlobRoutes()) < 3 {
		t.Fatal("outside api glob inventory too small")
	}

	badTokens := []struct {
		name string
		tok  string
	}{
		{"wrong_aud", goodClaims(func(m map[string]any) { m["aud"] = "https://graph.microsoft.com" })},
		{"wrong_iss", goodClaims(func(m map[string]any) { m["iss"] = "https://evil.example.com" })},
		{"expired", goodClaims(func(m map[string]any) { m["exp"] = now.Add(-time.Hour).Unix() })},
		{"id_token", goodClaims(func(m map[string]any) { m["token_use"] = "id_token" })},
		// Opaque non-JWT Bearer (RS must still 401 — no session fallthrough).
		{"opaque_garbage", "totally-invalid-bearer"},
		{"malformed_jwt", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.not-a-real-sig"},
	}

	for _, pth := range paths {
		pth := pth
		for _, bt := range badTokens {
			bt := bt
			name := "path_" + strings.ReplaceAll(strings.Trim(pth, "/"), "/", "_") + "_" + bt.name
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				req, err := http.NewRequest(http.MethodGet, srv.URL+pth, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+bt.tok)
				// Tempt fallthrough: session + Basic must not rescue invalid Bearer.
				req.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: "ui-session"})
				req.Header.Add("X-Lab-Basic-Hint", "admin:test") // not Authorization Basic
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				bc := auth.ClassifyResponseBodyClass(body)
				eval := auth.ClassifyFallthroughProbe(auth.FallthroughProbeInput{
					StatusCode:      resp.StatusCode,
					WWWAuthenticate: resp.Header.Get("WWW-Authenticate"),
					BodyClass:       bc,
				})
				if !eval.Denied || eval.FallthroughDetected {
					t.Fatalf("Regression: invalid bearer (%s) on %s must deny without fallthrough: status=%d eval=%+v",
						bt.name, pth, resp.StatusCode, eval)
				}
				if resp.StatusCode == http.StatusOK {
					t.Fatalf("Regression: invalid bearer must not return 200 (session/Basic fallthrough) on %s", pth)
				}
			})
		}
	}

	// Good token on progressive log path (outside /**/api/**) succeeds.
	prog := "/job/demo/1/logText/progressiveText?start=0"
	req, err := http.NewRequest(http.MethodGet, srv.URL+prog, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+goodTok)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("good bearer on progressive path: %d", resp.StatusCode)
	}

	// Contrast: Basic alone (no Bearer) may authenticate — proves fallthrough
	// risk if RS ignored Bearer; classifier would flag 200 on invalid Bearer.
	reqB, _ := http.NewRequest(http.MethodGet, srv.URL+"/whoAmI/api/json", nil)
	reqB.Header.Set("Authorization", "Basic YWRtaW46dGVzdA==")
	respB, err := client.Do(reqB)
	if err != nil {
		t.Fatal(err)
	}
	defer respB.Body.Close()
	if respB.StatusCode != http.StatusOK {
		t.Fatalf("basic-only fixture: %d", respB.StatusCode)
	}
}

// OfflineFallthroughFixtures rows must remain consistent with classifier (export used by doctor).
func TestOfflineFallthroughFixtures_ExportedContract(t *testing.T) {
	t.Parallel()
	// Ensure BuildOfflineRSQualificationSummary still marks live residual.
	sum := auth.BuildOfflineRSQualificationSummary("oidc_bearer")
	if !sum.LiveLabStillRequired {
		t.Fatal("offline must never clear live_lab_still_required")
	}
	foundClaim := false
	foundBasicAnon := false
	for _, line := range sum.OfflineAutomated {
		if strings.Contains(line, "wrong aud") || strings.Contains(strings.ToLower(line), "claim") {
			foundClaim = true
		}
		if strings.Contains(strings.ToLower(line), "basic") || strings.Contains(strings.ToLower(line), "anonymous") {
			foundBasicAnon = true
		}
	}
	if !foundClaim {
		t.Fatalf("offline automated must mention claim matrix: %v", sum.OfflineAutomated)
	}
	if !foundBasicAnon {
		t.Fatalf("offline automated must mention Basic/anonymous fallthrough: %v", sum.OfflineAutomated)
	}
	// Mode B residual honesty in residuals.
	joined := strings.Join(sum.LiveLabResiduals, " ")
	if !strings.Contains(joined, "Mode B") && !strings.Contains(joined, "jwt-auth-filter") {
		t.Fatalf("residuals must note Mode B / jwt-auth-filter: %v", sum.LiveLabResiduals)
	}
}

// OAUTH-009 expand: OAuth-required route fixtures — invalid Bearer must not
// succeed as Basic or anonymous. Models qualified jwt-auth-filter (fail closed)
// vs unqualified anti-pattern (FallthroughDetected). Live pin residual.
func TestOAUTH009_InvalidBearerMustNotSucceedAsBasicOrAnonymous(t *testing.T) {
	t.Parallel()

	// --- Qualified OAuth-required RS: Bearer invalid → 401; Basic alone → 401;
	// anonymous → 401. Session cookie never rescues invalid Bearer.
	qualified := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		lower := strings.ToLower(authz)
		if strings.HasPrefix(lower, "bearer ") {
			// Invalid / empty Bearer always denied (OAuth-required).
			w.Header().Set("WWW-Authenticate", `Bearer realm="Jenkins", error="invalid_token"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
			return
		}
		// OAuth-required: Basic alone and anonymous are not accepted.
		w.Header().Set("WWW-Authenticate", `Bearer realm="Jenkins"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"bearer required"}`))
	}))
	t.Cleanup(qualified.Close)

	// Paths include all RequiredMCPRoutes examples (outside-api-glob included).
	paths := make([]string, 0, len(auth.RequiredMCPRoutes))
	for _, r := range auth.RequiredMCPRoutes {
		paths = append(paths, r.ExamplePath)
	}
	if len(paths) < 8 {
		t.Fatalf("RequiredMCPRoutes too small: %d", len(paths))
	}

	authzCases := []struct {
		name  string
		authz string
		// optional session cookie to tempt session fallthrough
		session bool
	}{
		{"invalid_bearer", "Bearer totally-invalid", false},
		{"invalid_bearer_plus_session", "Bearer totally-invalid", true},
		{"empty_bearer", "Bearer ", false},
		{"basic_alone", "Basic YWRtaW46dGVzdA==", false}, // admin:test — must 401 on OAuth-required
		{"none", "", false},
		{"none_plus_session", "", true},
	}

	client := qualified.Client()
	for _, pth := range paths {
		pth := pth
		for _, ac := range authzCases {
			ac := ac
			name := "qualified_" + strings.ReplaceAll(strings.Trim(pth, "/"), "/", "_") + "_" + ac.name
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				req, err := http.NewRequest(http.MethodGet, qualified.URL+pth, nil)
				if err != nil {
					t.Fatal(err)
				}
				if ac.authz != "" {
					req.Header.Set("Authorization", ac.authz)
				}
				if ac.session {
					req.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: "ui-session"})
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				eval := auth.ClassifyFallthroughProbe(auth.FallthroughProbeInput{
					StatusCode:      resp.StatusCode,
					WWWAuthenticate: resp.Header.Get("WWW-Authenticate"),
					BodyClass:       auth.ClassifyResponseBodyClass(body),
				})
				if !eval.Denied || eval.FallthroughDetected {
					t.Fatalf("Regression: OAuth-required %s on %s must deny (no Basic/anon success): status=%d eval=%+v body=%q",
						ac.name, pth, resp.StatusCode, eval, string(body))
				}
				if resp.StatusCode == http.StatusOK {
					t.Fatalf("Regression: must not return 200 for %s on %s", ac.name, pth)
				}
			})
		}
	}

	// --- Unqualified anti-pattern: invalid Bearer falls through to Basic principal → 200.
	// Classifier must mark FallthroughDetected so probes fail closed.
	unqualified := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		// Anti-pattern: ignore failed Bearer and succeed as Basic/session/anon.
		if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			// Fall through: pretend Basic authenticated.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"basic-user","authenticated":true,"anonymous":false}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(unqualified.Close)

	req, err := http.NewRequest(http.MethodGet, unqualified.URL+"/whoAmI/api/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer invalid")
	resp, err := unqualified.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bc := auth.ClassifyResponseBodyClass(body)
	eval := auth.ClassifyFallthroughProbe(auth.FallthroughProbeInput{
		StatusCode: resp.StatusCode,
		BodyClass:  bc,
	})
	if !eval.FallthroughDetected {
		t.Fatalf("Regression: Basic fallthrough after invalid Bearer must be FallthroughDetected: status=%d bc=%s eval=%+v",
			resp.StatusCode, bc, eval)
	}
	if !strings.Contains(eval.Reason, "authenticated") {
		t.Fatalf("reason should note authenticated/Basic fallthrough: %q", eval.Reason)
	}

	// Anonymous fallthrough anti-pattern.
	anonSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Authorization")), "bearer ") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"anonymous","authenticated":false,"anonymous":true}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(anonSrv.Close)
	reqA, _ := http.NewRequest(http.MethodGet, anonSrv.URL+"/job/demo/1/logText/progressiveText?start=0", nil)
	reqA.Header.Set("Authorization", "Bearer garbage")
	respA, err := anonSrv.Client().Do(reqA)
	if err != nil {
		t.Fatal(err)
	}
	defer respA.Body.Close()
	bA, _ := io.ReadAll(io.LimitReader(respA.Body, 4096))
	evalA := auth.ClassifyFallthroughProbe(auth.FallthroughProbeInput{
		StatusCode: respA.StatusCode,
		BodyClass:  auth.ClassifyResponseBodyClass(bA),
	})
	if !evalA.FallthroughDetected {
		t.Fatalf("Regression: anonymous fallthrough after invalid Bearer must be FallthroughDetected: %+v", evalA)
	}
	if !strings.Contains(evalA.Reason, "anonymous") {
		t.Fatalf("reason should note anon fallthrough: %q", evalA.Reason)
	}
}
