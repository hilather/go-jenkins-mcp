package mutation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
)

// Endpoint class labels for previews (non-secret, stable).
const (
	EndpointBuildWithParameters = "buildWithParameters"
	EndpointStop                = "stop"
	EndpointTerm                = "term"
	EndpointKill                = "kill"
	EndpointCancelItem          = "cancelItem"
	EndpointRebuild             = "rebuild"
	EndpointReplay              = "replay"
	EndpointEnable              = "enable"
	EndpointDisable             = "disable"
	EndpointToggleKeepForever   = "toggleLogKeepForever"
	EndpointSubmitDescription   = "submitDescription"
	EndpointCancelItemBulk      = "cancelItemBulk"
)

// NormalizeParams copies and normalizes a parameter map for binding and
// execution. Rejects sensitive parameter names (secret/password/token keys)
// so model-supplied secrets are not accepted on the mutation path (MUT-002).
// Pair with ValidateAgainstDefinitions after loading job parameter definitions
// for type/choice/unknown checks.
func NormalizeParams(in map[string]any) (map[string]any, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		name := strings.TrimSpace(k)
		if name == "" {
			return nil, apperr.New(apperr.CodeInvalidArgument, "parameter name must not be empty")
		}
		if redact.IsSensitiveFieldName(name) {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("parameter %q is classified as secret and cannot be supplied via the model mutation path", name))
		}
		// Normalize scalars to stable string form for fingerprinting/execution.
		out[name] = normalizeParamValue(v)
	}
	return out, nil
}

func normalizeParamValue(v any) any {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case bool, float64, float32, int, int32, int64, uint, uint32, uint64:
		return t
	case json.Number:
		return t.String()
	default:
		// Fall back to fmt so fingerprint remains deterministic for simple types.
		return fmt.Sprint(t)
	}
}

// ParamFingerprint returns a stable opaque hash of normalized parameters.
// Empty/nil params yield a fixed empty-params marker hash input.
func ParamFingerprint(params map[string]any) string {
	if len(params) == 0 {
		return hashBytes([]byte("params:empty"))
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("params:")
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		raw, _ := json.Marshal(params[k])
		b.Write(raw)
		b.WriteByte(';')
	}
	return hashBytes([]byte(b.String()))
}

// RedactParams returns a model-safe copy of parameters (sensitive keys fully
// redacted; values also pass RedactText). Does not mutate the input.
func RedactParams(params map[string]any) map[string]any {
	if len(params) == 0 {
		return nil
	}
	out := make(map[string]any, len(params))
	for k, v := range params {
		if redact.IsSensitiveFieldName(k) {
			out[k] = redact.Replacement
			continue
		}
		switch t := v.(type) {
		case string:
			out[k] = redact.RedactText(t)
		default:
			// Non-string leaves as-is after RedactJSON for nested shapes.
			out[k] = redact.RedactJSON(t)
		}
	}
	return out
}

// TargetHash binds action + job + optional build + optional queue id + param fingerprint
// + optional mode/extra bind material (interrupt mode, description, keep flag, bulk queue ids).
// Never includes secret values — only the fingerprint of normalized params and non-secret mode/extra.
// QueueID is required for cancel_queue binding; omitted (0) for start/stop.
func TargetHash(action Action, job string, buildNumber, queueID int, paramFP string, modeExtra ...string) string {
	job = strings.TrimSpace(job)
	var b strings.Builder
	b.WriteString("action=")
	b.WriteString(string(action))
	b.WriteString(";job=")
	b.WriteString(job)
	if buildNumber > 0 {
		b.WriteString(";build=")
		b.WriteString(fmt.Sprintf("%d", buildNumber))
	}
	if queueID > 0 {
		b.WriteString(";queue=")
		b.WriteString(fmt.Sprintf("%d", queueID))
	}
	b.WriteString(";params=")
	b.WriteString(paramFP)
	mode := ""
	extra := ""
	if len(modeExtra) > 0 {
		mode = strings.TrimSpace(modeExtra[0])
	}
	if len(modeExtra) > 1 {
		extra = strings.TrimSpace(modeExtra[1])
	}
	if mode != "" {
		b.WriteString(";mode=")
		b.WriteString(mode)
	}
	if extra != "" {
		// Hash extra so long descriptions do not bloat the target string.
		b.WriteString(";extra=")
		b.WriteString(hashBytes([]byte(extra)))
	}
	return hashBytes([]byte(b.String()))
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16]) // 128-bit binding id
}
