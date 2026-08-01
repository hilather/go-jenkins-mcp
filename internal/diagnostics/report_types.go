package diagnostics

import (
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

// Status is the severity of a single doctor check.
type Status string

const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusSkip Status = "skip"
)

// Check is one named diagnostic result (secret-free).
type Check struct {
	Name    string         `json:"name"`
	Status  Status         `json:"status"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// Report is the structured doctor output for CLI / MCP (OPS-001).
type Report struct {
	ProfileID string  `json:"profileId"`
	Version   string  `json:"version,omitempty"`
	Commit    string  `json:"commit,omitempty"`
	Overall   Status  `json:"overall"`
	Checks    []Check `json:"checks"`
	// GatewayResidualStatus is the unified secret-free residual snapshot
	// (same map as `gateway residual-status` / admin GET residual-status via
	// BuildGatewayResidualStatus). Informational only — does not drive Overall;
	// never claims live GO. Present on offline and online doctor runs.
	// JSON key is stable for residual-smoke / operator grepping.
	GatewayResidualStatus map[string]any `json:"gateway_residual_status,omitempty"`
}

// CacheStatus is a secret-free L1 store / data-dir summary (OPS-001).
type CacheStatus struct {
	ProfileID      string `json:"profileId"`
	DataDir        string `json:"dataDir"`
	DataDirOK      bool   `json:"dataDirOk"`
	DataDirMode    string `json:"dataDirMode,omitempty"`
	DataDirMessage string `json:"dataDirMessage,omitempty"`
	StoreOpen      bool   `json:"storeOpen"`
	SchemaVersion  int    `json:"schemaVersion,omitempty"`
	ExpectedSchema int    `json:"expectedSchema"`
	SchemaOK       bool   `json:"schemaOk"`
	Generations    int64  `json:"generations"`
	Chunks         int64  `json:"chunks"`
	StoreMessage   string `json:"storeMessage,omitempty"`
	// Metrics is an optional in-process metrics snapshot when available.
	Metrics *telemetry.Snapshot `json:"metrics,omitempty"`
}

// OverallStatus derives report severity: fail > warn > ok.
// Skip checks do not demote a healthy report (optional network/metrics).
func OverallStatus(checks []Check) Status {
	overall := StatusOK
	for _, c := range checks {
		switch c.Status {
		case StatusFail:
			return StatusFail
		case StatusWarn:
			overall = StatusWarn
		}
	}
	return overall
}

// SanitizeCheck ensures messages never carry secret material.
func SanitizeCheck(c Check) Check {
	c.Message = redact.Secrets(strings.TrimSpace(c.Message))
	if c.Details != nil {
		out := make(map[string]any, len(c.Details))
		for k, v := range c.Details {
			lk := strings.ToLower(k)
			if looksSecretKey(lk) {
				continue
			}
			switch t := v.(type) {
			case string:
				out[k] = redact.Secrets(t)
			default:
				out[k] = v
			}
		}
		c.Details = out
	}
	return c
}

// residualHonestyNonSecretKey reports residual-status / BuildGatewayResidualStatus
// keys whose names contain secret-shaped substrings (e.g. "token") but hold only
// non-secret residual honesty (bools/counts — never paths, tokens, or vault bytes).
// Regression: naive substring "token" matches must not drop shared_token_cache_file
// from doctor/support-bundle/release-evidence embeds (Wave 15 residual honesty).
func residualHonestyNonSecretKey(k string) bool {
	switch k {
	case "shared_token_cache_file",
		// Mode A vault path residual bool (contains "token"; never vault bytes/path).
		"shared_api_token_vault_file",
		// Progressive consent nest honesty (contains "token"; always false — never token values).
		// Must survive sanitizeResidualStatusMap on doctor / support-bundle embeds.
		"stores_tokens":
		return true
	default:
		return false
	}
}

// LooksSecretKey reports whether a JSON map key name looks like it may hold secret
// material and should be dropped by defense-in-depth sanitizers. Residual honesty
// keys that merely mention "token" (e.g. shared_token_cache_file bool) are allowed.
// Exported for release-evidence scrub parity with doctor/support-bundle.
func LooksSecretKey(k string) bool {
	return looksSecretKey(strings.ToLower(strings.TrimSpace(k)))
}

func looksSecretKey(k string) bool {
	if residualHonestyNonSecretKey(k) {
		return false
	}
	switch {
	case strings.Contains(k, "token"),
		strings.Contains(k, "password"),
		strings.Contains(k, "secret"),
		strings.Contains(k, "cookie"),
		strings.Contains(k, "authorization"),
		strings.Contains(k, "private_key"),
		strings.Contains(k, "privatekey"),
		k == "auth":
		return true
	default:
		return false
	}
}

// sanitizeResidualStatusMap defense-in-depth scrubs BuildGatewayResidualStatus
// output before embedding on doctor Report. Drops secret-like keys and redacts
// string values. Nested maps/slices are walked. Informational only.
func sanitizeResidualStatusMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		if looksSecretKey(lk) {
			continue
		}
		out[k] = sanitizeResidualValue(v)
	}
	return out
}

func sanitizeResidualValue(v any) any {
	switch t := v.(type) {
	case string:
		return redact.Secrets(t)
	case map[string]any:
		return sanitizeResidualStatusMap(t)
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = sanitizeResidualValue(t[i])
		}
		return out
	case []string:
		out := make([]string, len(t))
		for i := range t {
			out[i] = redact.Secrets(t[i])
		}
		return out
	default:
		return v
	}
}
