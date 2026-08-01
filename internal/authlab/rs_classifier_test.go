package authlab_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/authlab"
)

// OAUTH-009 optional bridge: mock RS (HOST-013) 401 responses classify as
// Denied under OfflineFallthroughFixtures / ClassifyFallthroughProbe.
// Live jwt-auth-filter pin remains residual.
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
