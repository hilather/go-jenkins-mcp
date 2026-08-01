package tools

import (
	"errors"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// mapToolErr converts failures to stable apperr codes for MCP surfaces.
// Seed handlers still return Go errors; the SDK stringifies them. Using apperr
// ensures Error() is model-safe and coded (FND-005 light wiring).
func mapToolErr(err error) error {
	if err == nil {
		return nil
	}
	var ae *apperr.Error
	if errors.As(err, &ae) && ae != nil {
		return ae
	}
	if code, ok := apperr.Classify(err); ok {
		// Use a short safe default for classified upstream/context errors so
		// raw transport text (which may include headers) is not model-visible.
		return apperr.Wrap(code, code.DefaultMessage(), err)
	}
	return apperr.Wrap(apperr.CodeUpstreamProtocol, "Jenkins request failed", err)
}

// invalidArg is a stable validation error for missing/invalid tool arguments.
func invalidArg(message string) error {
	return apperr.New(apperr.CodeInvalidArgument, message)
}
