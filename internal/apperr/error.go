package apperr

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// Error is the stable application error type.
// Error() returns the model-visible message only (secrets redacted).
// Cause / Unwrap expose the internal chain for diagnostic mode.
type Error struct {
	Code    Code
	Message string // model-visible; must stay free of secrets
	cause   error  // internal only; not included in Error()
}

// Error implements the error interface with the model-visible message.
// It never includes the internal cause chain (diagnostic mode uses Cause).
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	msg := e.Message
	if msg == "" {
		msg = e.Code.DefaultMessage()
	}
	msg = redact.Secrets(msg)
	if e.Code == "" {
		return msg
	}
	return fmt.Sprintf("%s: %s", e.Code, msg)
}

// Unwrap returns the internal cause for errors.Is / errors.As chains.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Cause returns the internal cause (alias for diagnostics readers).
func (e *Error) Cause() error { return e.Unwrap() }

// New builds a model-visible error with no internal cause.
func New(code Code, message string) *Error {
	if message == "" {
		message = code.DefaultMessage()
	}
	return &Error{Code: code, Message: redact.Secrets(message)}
}

// Wrap attaches an internal cause while keeping message model-safe.
// The cause string is not concatenated into Error(); use Cause() in diagnostics.
func Wrap(code Code, message string, cause error) *Error {
	if message == "" {
		message = code.DefaultMessage()
	}
	return &Error{Code: code, Message: redact.Secrets(message), cause: cause}
}

// CodeOf returns the Code if err is or wraps *Error; otherwise CodeInternal
// when err != nil, or empty when err == nil.
func CodeOf(err error) Code {
	if err == nil {
		return ""
	}
	var ae *Error
	if errors.As(err, &ae) && ae != nil {
		return ae.Code
	}
	// Classify common stdlib / context errors.
	if c, ok := Classify(err); ok {
		return c
	}
	return CodeInternal
}

// ModelMessage returns a secret-safe string suitable for MCP tool errors.
func ModelMessage(err error) string {
	if err == nil {
		return ""
	}
	var ae *Error
	if errors.As(err, &ae) && ae != nil {
		return ae.Error()
	}
	// Unknown errors: redact and avoid dumping raw transport details wholesale.
	return redact.Secrets(err.Error())
}

// Classify maps context and common sentinel failures to stable codes.
// ok is false when no classification is available.
func Classify(err error) (Code, bool) {
	if err == nil {
		return "", false
	}
	var ae *Error
	if errors.As(err, &ae) && ae != nil && ae.Code != "" {
		return ae.Code, true
	}
	if errors.Is(err, context.Canceled) {
		return CodeCancelled, true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return CodeTimeout, true
	}
	// Heuristic fallbacks for seed jenkins client string errors (pre-mapping).
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "401") || strings.Contains(msg, "unauthorized") || strings.Contains(msg, "authentication"):
		return CodeAuthentication, true
	case strings.Contains(msg, "403") || strings.Contains(msg, "forbidden"):
		return CodeAuthorization, true
	case strings.Contains(msg, "404") || strings.Contains(msg, "not found"):
		return CodeNotFound, true
	case strings.Contains(msg, "429") || strings.Contains(msg, "throttl") || strings.Contains(msg, "rate limit"):
		return CodeThrottled, true
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		return CodeTimeout, true
	}
	return "", false
}

// IsCode reports whether err has the given stable code.
func IsCode(err error, code Code) bool {
	return CodeOf(err) == code
}

// IsCancelled reports context cancellation classification.
func IsCancelled(err error) bool { return IsCode(err, CodeCancelled) }

// IsTimeout reports timeout classification.
func IsTimeout(err error) bool { return IsCode(err, CodeTimeout) }
