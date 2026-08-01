package diagnostics

import (
	"net/http"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// checkJenkinsResilienceResidual is Wave 45 Track C / NET-003 residual honesty:
// proves offline that default resilience is constructible, the circuit starts
// closed with observable snapshot fields, GET/HEAD are retry-eligible, and
// POST is never auto-retry eligible — while documenting that live multi-
// controller chaos / network matrix remains residual.
//
// Pure offline: no network, no credentials, no keyring. Bool/int details only.
// Fail closed if POST becomes retry-eligible or circuit snapshot is missing.
func checkJenkinsResilienceResidual() SelfCheckItem {
	const (
		name    = "jenkins_resilience_residual"
		control = "NET-003"
	)
	fail := func(msg string) SelfCheckItem {
		return SelfCheckItem{
			Name:    name,
			Status:  SelfCheckFail,
			Message: msg,
			Control: control,
		}
	}

	// --- Default resilience constructible (production defaults) ---
	cfg := jenkins.DefaultResilienceConfig()
	if cfg.MaxJSONBodyBytes <= 0 {
		return fail("DefaultResilienceConfig MaxJSONBodyBytes must be positive")
	}
	if cfg.MaxRetries < 0 {
		return fail("DefaultResilienceConfig MaxRetries must be non-negative")
	}
	if cfg.CircuitFailureThreshold <= 0 {
		return fail("DefaultResilienceConfig CircuitFailureThreshold must be positive")
	}
	if cfg.CircuitOpenDuration <= 0 {
		return fail("DefaultResilienceConfig CircuitOpenDuration must be positive")
	}

	res := jenkins.NewResilience(cfg)
	if res == nil {
		return fail("NewResilience must return non-nil with defaults")
	}
	// Config round-trip: copy present, secret-free knobs only.
	gotCfg := res.Config()
	if gotCfg.CircuitFailureThreshold != cfg.CircuitFailureThreshold {
		return fail("Resilience.Config CircuitFailureThreshold mismatch after NewResilience")
	}

	// --- Circuit starts closed/healthy; expose snapshot fields (no secrets) ---
	st := res.State()
	if st.State != "closed" {
		return fail("circuit must start closed (got non-closed state)")
	}
	if st.ConsecutiveFailures != 0 {
		return fail("circuit must start with zero consecutive failures")
	}
	if st.FailureThreshold <= 0 {
		return fail("CircuitState FailureThreshold must be positive")
	}
	// State token must be one of the documented closed set (no free-form secrets).
	switch strings.ToLower(strings.TrimSpace(st.State)) {
	case "closed", "open", "half-open":
		// ok
	default:
		return fail("CircuitState.State not in closed|open|half-open")
	}

	// Client path: CircuitState() with defaults also closed (doctor-compatible).
	c := &jenkins.Client{}
	c.WithResilience(cfg)
	cst := c.CircuitState()
	if cst.State != "closed" {
		return fail("Client.CircuitState must start closed with WithResilience defaults")
	}
	if cst.FailureThreshold <= 0 {
		return fail("Client.CircuitState FailureThreshold must be positive")
	}

	// --- Retry eligibility: GET/HEAD only; POST never (fail closed if broken) ---
	if !jenkins.IsIdempotentRetryMethod(http.MethodGet) {
		return fail("IsIdempotentRetryMethod(GET) must be true (NET-003 GET retry)")
	}
	if !jenkins.IsIdempotentRetryMethod(http.MethodHead) {
		return fail("IsIdempotentRetryMethod(HEAD) must be true (NET-003 HEAD retry)")
	}
	if !jenkins.IsIdempotentRetryMethod("get") || !jenkins.IsIdempotentRetryMethod("HeAd") {
		return fail("IsIdempotentRetryMethod must be case-insensitive for GET/HEAD")
	}
	// POST and other non-idempotent methods must never auto-retry.
	for _, m := range []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		"POST",
		"post",
	} {
		if jenkins.IsIdempotentRetryMethod(m) {
			return fail("IsIdempotentRetryMethod must reject non-idempotent method (POST auto-retry break)")
		}
	}
	// RetryPolicyClassify cross-check: POST+503 never retryable; GET+503 is.
	if ok, _ := jenkins.RetryPolicyClassify(http.MethodPost, http.StatusServiceUnavailable, nil); ok {
		return fail("RetryPolicyClassify must not retry POST (duplicate build safety)")
	}
	if ok, _ := jenkins.RetryPolicyClassify(http.MethodGet, http.StatusServiceUnavailable, nil); !ok {
		return fail("RetryPolicyClassify must retry GET on 503")
	}

	// Residual honesty: live multi-controller chaos / network matrix not offline.
	return SelfCheckItem{
		Name:    name,
		Status:  SelfCheckOK,
		Message: "NET-003 resilience lite offline canary (GET/HEAD retry + circuit); live chaos matrix residual",
		Control: control,
		Details: map[string]any{
			"get_head_retry_eligible":      true,
			"post_auto_retry":              false,
			"circuit_breaker_present":      true,
			"circuit_starts_closed":        true,
			"default_resilience_ok":        true,
			"max_json_body_bytes":          cfg.MaxJSONBodyBytes,
			"circuit_failure_threshold":    cfg.CircuitFailureThreshold,
			"residual_live_chaos":          false,
			"residual_live_network_matrix": false,
		},
	}
}
