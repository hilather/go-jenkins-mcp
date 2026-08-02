package jenkins

import (
	"strconv"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// ResolveMaxJSONBodyBytes resolves the Jenkins API JSON/decoded body cap
// (Wave 46 Track A / NET-003).
//
// Precedence (later wins): DefaultMaxJSONBodyBytes → envVal → flagVal.
// Empty / whitespace means unset at that layer. Positive integers are accepted.
// Zero (explicit "0") at the winning layer means DefaultMaxJSONBodyBytes.
// Negative or non-integer values fail closed (error); never clamp silently.
// After resolve, n must be ≤ AbsoluteMaxJSONBodyBytes; oversize values error with
// a non-secret message citing the absolute maximum (no secrets).
//
// Progressive log paths are not wrapped by MaxJSONBodyBytes (LOG-001 caps only).
// POST is never auto-retried regardless of this bound.
func ResolveMaxJSONBodyBytes(flagVal, envVal string) (int64, error) {
	n := DefaultMaxJSONBodyBytes
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseMaxJSONBodyBytesValue(raw, "env "+EnvMaxJSONBodyBytes)
		if err != nil {
			return 0, err
		}
		n = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseMaxJSONBodyBytesValue(raw, "flag --max-json-body-bytes")
		if err != nil {
			return 0, err
		}
		n = v
	}
	if n > AbsoluteMaxJSONBodyBytes {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins max json body bytes exceeds absolute maximum bound ("+
				strconv.FormatInt(AbsoluteMaxJSONBodyBytes, 10)+" bytes)")
	}
	return n, nil
}

func parseMaxJSONBodyBytesValue(raw, source string) (int64, error) {
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid jenkins max json body bytes from "+source+" (positive integer bytes, or 0 for default): "+raw)
	}
	if v < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins max json body bytes from "+source+" must not be negative")
	}
	if v == 0 {
		return DefaultMaxJSONBodyBytes, nil
	}
	return v, nil
}
