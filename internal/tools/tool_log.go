package tools

import (
	"strconv"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

// effectiveLogger returns the process tool logger: RegisterOptions.Logger first,
// then telemetry.Global().Logger. Nil ⇒ no structured tool lines (unit tests).
func effectiveLogger(st regState) *telemetry.Logger {
	if st.logger != nil {
		return st.logger
	}
	if r := telemetry.Global(); r != nil {
		return r.Logger
	}
	return nil
}

// logToolDebug emits a secret-free structured debug line when enabled.
// Keys/values must be low-cardinality non-secret (tool name, codes, ms counts).
func logToolDebug(st regState, msg string, kvs ...string) {
	if lg := effectiveLogger(st); lg != nil {
		lg.Debug(msg, kvs...)
	}
}

// logToolWarn emits a secret-free structured warn line (denials, soft residual).
func logToolWarn(st regState, msg string, kvs ...string) {
	if lg := effectiveLogger(st); lg != nil {
		lg.Warn(msg, kvs...)
	}
}

// logToolError emits a secret-free structured error line for tool failures.
// err is mapped through apperr.CodeOf / ModelMessage only (never raw transport).
func logToolError(st regState, msg string, err error, kvs ...string) {
	lg := effectiveLogger(st)
	if lg == nil {
		return
	}
	code := string(apperr.CodeOf(err))
	if code == "" {
		code = "unknown"
	}
	mm := apperr.ModelMessage(err)
	fields := append([]string{"error_code", code, "error", mm}, kvs...)
	lg.Error(msg, fields...)
}

// durationMS is a non-secret duration field for structured logs.
func durationMS(start time.Time) string {
	return strconv.FormatInt(time.Since(start).Milliseconds(), 10)
}
