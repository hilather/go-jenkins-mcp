package diagnostics

import (
	"net/url"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// checkJenkinsOriginPinResidual is Wave 50 Track C / NET-001 residual honesty:
// pure offline proof of NormalizeBaseURL + SameOrigin fail-closed contracts and
// WhoAmIPath constant shape. No network, no Jenkins HTTP.
//
// Residual honesty: live reverse-proxy path-prefix matrices remain out of
// scope for this canary (residual_live_reverse_proxy=false).
//
// Fail closed if any pure contract is broken.
func checkJenkinsOriginPinResidual() SelfCheckItem {
	const (
		name    = "jenkins_origin_pin_residual"
		control = "NET-001"
	)
	fail := func(msg string) SelfCheckItem {
		return SelfCheckItem{
			Name:    name,
			Status:  SelfCheckFail,
			Message: msg,
			Control: control,
		}
	}

	// --- NormalizeBaseURL: reverse-proxy-style base with trailing slash ---
	base, err := jenkins.NormalizeBaseURL("https://j.example/ci/")
	if err != nil {
		return fail("NormalizeBaseURL(https://j.example/ci/) must succeed offline")
	}
	if base == nil {
		return fail("NormalizeBaseURL must return non-nil URL")
	}
	if !strings.EqualFold(base.Scheme, "https") {
		return fail("NormalizeBaseURL must set scheme https")
	}
	if !strings.EqualFold(base.Host, "j.example") {
		return fail("NormalizeBaseURL must set host j.example")
	}
	// Path prefix preserved without trailing slash (proxy prefix /ci).
	if strings.TrimRight(base.Path, "/") != "/ci" {
		return fail("NormalizeBaseURL must preserve reverse-proxy path prefix /ci")
	}

	// --- SameOrigin: accept path under base ---
	sameHostPath, err := url.Parse("https://j.example/ci/job/demo/1/api/json")
	if err != nil {
		return fail("fixture same-host path URL must parse")
	}
	if !jenkins.SameOrigin(base, sameHostPath) {
		return fail("SameOrigin must accept path under pinned base")
	}

	// --- SameOrigin: reject different host ---
	evil, err := url.Parse("https://evil.example/ci/job/demo/")
	if err != nil {
		return fail("fixture cross-host URL must parse")
	}
	if jenkins.SameOrigin(base, evil) {
		return fail("SameOrigin must reject different host (fail closed)")
	}

	// --- SameOrigin: reject different scheme ---
	httpU, err := url.Parse("http://j.example/ci/job/demo/")
	if err != nil {
		return fail("fixture scheme-mismatch URL must parse")
	}
	if jenkins.SameOrigin(base, httpU) {
		return fail("SameOrigin must reject different scheme (fail closed)")
	}

	// --- NormalizeBaseURL fail closed: empty / relative ---
	if _, err := jenkins.NormalizeBaseURL(""); err == nil {
		return fail("NormalizeBaseURL empty must fail closed")
	}
	if _, err := jenkins.NormalizeBaseURL("/relative/only"); err == nil {
		return fail("NormalizeBaseURL relative path must fail closed")
	}
	if _, err := jenkins.NormalizeBaseURL("not-a-url"); err == nil {
		return fail("NormalizeBaseURL host-less must fail closed")
	}

	// --- WhoAmIPath constant (AUTH-004 identity endpoint under origin pin) ---
	who := strings.TrimSpace(jenkins.WhoAmIPath)
	if who == "" {
		return fail("WhoAmIPath must be non-empty")
	}
	if !strings.HasPrefix(who, "/") {
		return fail("WhoAmIPath must be a root-absolute path")
	}

	return SelfCheckItem{
		Name:   name,
		Status: SelfCheckOK,
		// Use "and" not "+" between identifiers: bare-token redaction would
		// otherwise scrub CamelCase+CamelCase in SanitizeForModel.
		Message: "NET-001 origin pin pure offline (NormalizeBaseURL and SameOrigin); live reverse-proxy residual",
		Control: control,
		Details: map[string]any{
			"normalize_base_ok":           true,
			"same_origin_accept":          true,
			"cross_origin_reject":         true,
			"whoami_path_present":         true,
			"residual_live_reverse_proxy": false,
		},
	}
}
