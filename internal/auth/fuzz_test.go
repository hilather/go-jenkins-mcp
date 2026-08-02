package auth_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/auth"
)

// QA-001 Wave 21: OAUTH-009 pure RS fallthrough + RFC 9728 PRM parsers.
// Must never panic on garbage; error / inconclusive results are OK.

const (
	fuzzMaxAuthStr  = 8 << 10
	fuzzMaxAuthJSON = 32 << 10
)

// FuzzClassifyFallthroughProbe exercises the pure FallthroughMustDeny classifier.
func FuzzClassifyFallthroughProbe(f *testing.F) {
	// status, www, bodyClass, authN, anon as int (0/1)
	f.Add(401, "Bearer realm=\"jenkins\"", "empty", 0, 0)
	f.Add(403, "Basic realm=\"Jenkins\"", "unknown", 0, 0)
	f.Add(200, "", "whoami_authenticated", 1, 0)
	f.Add(200, "", "whoami_anonymous", 0, 1)
	f.Add(200, "", "html_login", 0, 0)
	f.Add(200, "", "error_json", 0, 0)
	f.Add(500, "", "unknown", 0, 0)
	f.Add(0, "", "empty", 0, 0)
	f.Add(404, "Bearer", "unknown", 0, 0)
	f.Add(204, "", "empty", 0, 0)
	f.Add(401, "Bearer realm=\"x\", error=\"invalid_token\"", "error_json", 0, 0)
	f.Add(200, "Bearer", "whoami_authenticated", 1, 0)
	f.Add(-1, strings.Repeat("B", 200), "unknown", 0, 0)

	f.Fuzz(func(t *testing.T, status int, www, bodyClass string, authN, anon int) {
		if len(www) > fuzzMaxAuthStr || len(bodyClass) > fuzzMaxAuthStr {
			return
		}
		in := auth.FallthroughProbeInput{
			StatusCode:          status,
			WWWAuthenticate:     www,
			BodyClass:           auth.FallthroughBodyClass(bodyClass),
			WhoAmIAuthenticated: authN != 0,
			WhoAmIAnonymous:     anon != 0,
		}
		r1 := auth.ClassifyFallthroughProbe(in)
		r2 := auth.ClassifyFallthroughProbe(in)
		if r1.Denied != r2.Denied || r1.FallthroughDetected != r2.FallthroughDetected ||
			r1.StatusCode != r2.StatusCode || r1.Reason != r2.Reason {
			t.Fatalf("non-deterministic: %+v vs %+v", r1, r2)
		}
		// Invariant: Denied and FallthroughDetected are mutually exclusive.
		if r1.Denied && r1.FallthroughDetected {
			t.Fatalf("both denied and fallthrough: %+v", r1)
		}
		// EvaluateInvalidBearerResponse path.
		_ = auth.EvaluateInvalidBearerResponse(status, authN != 0, anon != 0)
		// Body class helper from raw-ish bytes (reuse www as body sample).
		_ = auth.ClassifyResponseBodyClass([]byte(www))
		_ = auth.ClassifyResponseBodyClass([]byte(bodyClass))
		_ = auth.ClassifyResponseBodyClass(nil)
	})
}

// FuzzParseProtectedResourceMetadata feeds random JSON to the RFC 9728 subset parser.
func FuzzParseProtectedResourceMetadata(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"resource":"https://jenkins.example.com/"}`))
	f.Add([]byte(`{"resource":"https://jenkins.example.com/","authorization_servers":["https://login.example.com/"]}`))
	f.Add([]byte(`{"resource":"https://user:pass@jenkins.example.com/"}`))
	f.Add([]byte(`{"resource":"ftp://x/"}`))
	f.Add([]byte(`{"resource":"not-a-url"}`))
	f.Add([]byte(`{"resource":"","authorization_servers":[""]}`))
	f.Add([]byte(`{"authorization_servers":["https://a.example"]}`))
	f.Add([]byte(`{"resource":"https://j.example/","jwks_uri":"https://j.example/jwks","scopes_supported":["openid"],"bearer_methods_supported":["header"]}`))
	f.Add([]byte(`{"resource":"https://j.example/","jwks_uri":"javascript:alert(1)"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxAuthJSON {
			return
		}
		m, err := auth.ParseProtectedResourceMetadata(data)
		if err != nil {
			if m != nil {
				t.Fatalf("error with non-nil metadata: %v", err)
			}
			return
		}
		if m == nil {
			t.Fatal("nil metadata without error")
		}
		// Validate is separate; must not panic.
		_ = auth.ValidateProtectedResourceMetadata(m)
	})
}
