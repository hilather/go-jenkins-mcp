package diagnostics

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/profile"
)

// Regression: scrubMap (support-bundle capability_summary + self-check
// Details) did not recurse into []any, so a secret-keyed map nested in a
// slice survived into shareable bundles. SanitizeCheck (all doctor output +
// bundle doctor.json) likewise passed nested maps/slices through unscrubbed.
// Both now walk slices and nested maps like the sibling sanitizeResidualValue.
func TestScrubMap_RecursesIntoSlices(t *testing.T) {
	t.Parallel()
	in := map[string]any{
		"nested": []any{
			map[string]any{"password": "hunter2", "note": "ok"},
			"plain",
		},
		"deep": map[string]any{
			"inner": []any{map[string]any{"token": "abc123"}},
		},
	}
	out := scrubMap(in)
	nested := out["nested"].([]any)
	m0 := nested[0].(map[string]any)
	if _, present := m0["password"]; present {
		t.Fatalf("secret key survived inside slice: %v", m0)
	}
	if m0["note"] != "ok" {
		t.Fatalf("non-secret key dropped: %v", m0)
	}
	deep := out["deep"].(map[string]any)["inner"].([]any)[0].(map[string]any)
	if _, present := deep["token"]; present {
		t.Fatalf("secret key survived inside nested map+slice: %v", deep)
	}
}

func TestSanitizeCheck_RecursesNestedDetails(t *testing.T) {
	t.Parallel()
	c := SanitizeCheck(Check{
		Name:    "x",
		Message: "ok",
		Details: map[string]any{
			"outer": map[string]any{"token": "hunter2", "safe": "v"},
			"list":  []any{map[string]any{"secret": "hunter2"}},
			"strs":  []string{"keep"},
		},
	})
	outer := c.Details["outer"].(map[string]any)
	if _, present := outer["token"]; present {
		t.Fatalf("nested secret key survived SanitizeCheck: %v", outer)
	}
	if outer["safe"] != "v" {
		t.Fatalf("non-secret nested key dropped: %v", outer)
	}
	list := c.Details["list"].([]any)[0].(map[string]any)
	if _, present := list["secret"]; present {
		t.Fatalf("slice-nested secret key survived SanitizeCheck: %v", list)
	}
	if c.Details["strs"].([]string)[0] != "keep" {
		t.Fatal("[]string values must be preserved")
	}
}

// Regression: the doctor proxy check emitted the raw proxyURL into Details;
// redact.Secrets provably does not mask URL userinfo. Userinfo is now stripped
// structurally before emission (defense in depth for library callers that
// skip profile.Validate, which rejects credential-bearing proxy URLs).
func TestCheckTLSPaths_ProxyURLUserinfoStripped(t *testing.T) {
	t.Parallel()
	p := &profile.Profile{
		ID:         "corp",
		JenkinsURL: "https://jenkins.example",
		ProxyURL:   "http://user:password@proxy.corp:8080",
	}
	for _, c := range checkTLSPaths(p) {
		if c.Name != "proxy" {
			continue
		}
		v, _ := c.Details["proxyURL"].(string)
		if strings.Contains(v, "password") || strings.Contains(v, "user@") {
			t.Fatalf("proxyURL userinfo leaked into doctor details: %q", v)
		}
		if !strings.Contains(v, "proxy.corp") {
			t.Fatalf("proxyURL host should survive: %q", v)
		}
		return
	}
	t.Fatal("proxy check not emitted")
}
