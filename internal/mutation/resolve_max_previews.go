package mutation

import (
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Wave 52 Track C / MUT-001: operator resolve for process-local Preview rate.

const (
	// AbsoluteMaxPreviewsPerMinute is the process absolute fail-closed ceiling
	// for the Preview sliding-window rate. Operators may raise via env/flag up
	// to this bound; values above fail closed at serve resolve (not clamped).
	// Prefer 300 over higher ceilings: fail-closed operator path (library Config
	// negative still means unlimited for tests only).
	AbsoluteMaxPreviewsPerMinute = 300
	// EnvMaxPreviewsPerMinute is the serve env for the Preview rate cap.
	// CLI --mutation-max-previews-per-minute overrides when set.
	// Empty/0 → DefaultMaxPreviewsPerMinute. Invalid/negative/above absolute
	// fail closed at serve start.
	EnvMaxPreviewsPerMinute = "JENKINS_MCP_MUTATION_MAX_PREVIEWS_PER_MINUTE"
)

// processMaxPreviewsPerMinute is the live process Preview rate after serve
// SetMaxPreviewsPerMinute. 0 = unset (NewManager falls back to Default when
// Config.MaxPreviewsPerMinute is also 0). Atomic for concurrent diagnostics.
var processMaxPreviewsPerMinute atomic.Int64

// SetMaxPreviewsPerMinute sets the process Preview rate after a successful
// ResolveMaxPreviewsPerMinute (serve start). Non-positive n uses
// DefaultMaxPreviewsPerMinute. Does not re-check AbsoluteMax (resolve already
// fail-closed); oversize values are clamped to absolute max as belt-and-suspenders.
func SetMaxPreviewsPerMinute(n int) {
	if n <= 0 {
		n = DefaultMaxPreviewsPerMinute
	}
	if n > AbsoluteMaxPreviewsPerMinute {
		n = AbsoluteMaxPreviewsPerMinute
	}
	processMaxPreviewsPerMinute.Store(int64(n))
}

// MaxPreviewsPerMinute returns the live process Preview rate (for diagnostics
// and tests). Unset / non-positive → DefaultMaxPreviewsPerMinute.
func MaxPreviewsPerMinute() int {
	n := int(processMaxPreviewsPerMinute.Load())
	if n <= 0 {
		return DefaultMaxPreviewsPerMinute
	}
	if n > AbsoluteMaxPreviewsPerMinute {
		return AbsoluteMaxPreviewsPerMinute
	}
	return n
}

// ResolveMaxPreviewsPerMinute resolves the mutation Preview sliding-window rate
// (Wave 52 Track C / MUT-001).
//
// Precedence (later wins): DefaultMaxPreviewsPerMinute → envVal → flagVal.
// Empty / whitespace means unset at that layer. Positive integers are accepted.
// Explicit 0 at the winning layer means DefaultMaxPreviewsPerMinute — operators
// cannot use 0 to mean unlimited on this path (library Config negative remains
// unlimited for tests only).
// Negative or non-integer values fail closed (error); never clamp silently.
// After resolve, n must be ≤ AbsoluteMaxPreviewsPerMinute; oversize values
// error with a non-secret message citing the absolute maximum (no secrets).
func ResolveMaxPreviewsPerMinute(flagVal, envVal string) (int, error) {
	n := DefaultMaxPreviewsPerMinute
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseMaxPreviewsPerMinuteValue(raw, "env "+EnvMaxPreviewsPerMinute)
		if err != nil {
			return 0, err
		}
		n = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseMaxPreviewsPerMinuteValue(raw, "flag --mutation-max-previews-per-minute")
		if err != nil {
			return 0, err
		}
		n = v
	}
	if n > AbsoluteMaxPreviewsPerMinute {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"mutation max previews per minute exceeds absolute maximum bound ("+
				strconv.Itoa(AbsoluteMaxPreviewsPerMinute)+")")
	}
	return n, nil
}

func parseMaxPreviewsPerMinuteValue(raw, source string) (int, error) {
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid mutation max previews per minute from "+source+
				" (positive integer, or 0 for default): "+raw)
	}
	if v < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"mutation max previews per minute from "+source+" must not be negative")
	}
	// Explicit 0 means default — cannot disable / unlimited on operator path.
	if v == 0 {
		return DefaultMaxPreviewsPerMinute, nil
	}
	return v, nil
}
