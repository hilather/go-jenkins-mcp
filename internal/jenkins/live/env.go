//go:build live_jenkins

package live

import (
	"os"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// envURL is required; when unset, all live tests skip (no docker required for default CI).
const envURL = "JENKINS_URL"

func envOr(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

// liveClient builds a jenkins.Client from process env or skips.
// Credentials must be ephemeral lab tokens — never commit them.
func liveClient(t *testing.T) *jenkins.Client {
	t.Helper()
	base := strings.TrimSpace(os.Getenv(envURL))
	if base == "" {
		t.Skip("JENKINS_URL unset; skipping live Jenkins smoke (set URL + token or run scripts/jenkins-live-smoke.sh)")
	}
	user := envOr("JENKINS_USER", "admin")
	token := strings.TrimSpace(os.Getenv("JENKINS_API_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("JENKINS_TOKEN"))
	}
	if token == "" {
		t.Skip("JENKINS_API_TOKEN (or JENKINS_TOKEN) unset; skipping live Jenkins smoke")
	}
	// Refuse accidental file:// or empty-looking schemes; NewClient normalizes http(s).
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		t.Fatalf("JENKINS_URL must be http(s)://…, got %q", redactURL(base))
	}
	c := jenkins.NewClient(base, user, token)
	if c == nil {
		t.Fatal("jenkins.NewClient returned nil")
	}
	return c
}

func liveJobName() string {
	return envOr("JENKINS_LIVE_JOB", "sample-freestyle")
}

// redactURL strips userinfo if present so failures never echo secrets in paths.
func redactURL(raw string) string {
	// Never include token; URL itself should not carry userinfo in our harness.
	if i := strings.Index(raw, "@"); i >= 0 {
		return "(redacted-userinfo)"
	}
	return raw
}

// assertNoSecret leaks a canary: errors/messages must not contain the API token.
func assertNoSecret(t *testing.T, token string, msgs ...string) {
	t.Helper()
	if token == "" {
		return
	}
	for _, m := range msgs {
		if m != "" && strings.Contains(m, token) {
			t.Fatalf("secret material appeared in output (Regression: live smoke must not leak API token)")
		}
	}
}
