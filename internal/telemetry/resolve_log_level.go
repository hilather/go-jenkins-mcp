package telemetry

import (
	"fmt"
	"strings"
)

// EnvLogLevel is the serve env for minimum structured log level
// (debug|info|warn|error). Empty → LevelInfo. Flag --log-level wins when set.
// Invalid values fail closed at serve start (pilot offline analysis hygiene).
// (Package boundary: returns plain error — cmd maps to apperr.CodeInvalidArgument.)
const EnvLogLevel = "JENKINS_MCP_LOG_LEVEL"

// ResolveLogLevel selects the minimum telemetry.Logger level.
// Precedence: non-empty flag → non-empty env → LevelInfo.
// Accepted: debug, info (default), warn/warning, error (case-insensitive).
// Whitespace-only and empty at all layers → LevelInfo. Unknown tokens fail closed.
func ResolveLogLevel(flagVal, envVal string) (Level, error) {
	raw := strings.TrimSpace(flagVal)
	layer := "flag --log-level"
	if raw == "" {
		raw = strings.TrimSpace(envVal)
		layer = "env " + EnvLogLevel
	}
	if raw == "" {
		return LevelInfo, nil
	}
	switch strings.ToLower(raw) {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("%s: invalid log level (want debug|info|warn|error)", layer)
	}
}
