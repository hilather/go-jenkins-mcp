package tools

import (
	"errors"
	"fmt"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// progressiveConsent is satisfied by *gateway.ConsentRequired (Mode C) without
// tools importing gateway (depgraph). Surfaces auth URL + session id only.
type progressiveConsent interface {
	ConsentAuthorizationURL() string
	ConsentSessionID() string
}

// mapToolErr converts failures to stable apperr codes for MCP surfaces.
// Seed handlers still return Go errors; the SDK stringifies them. Using apperr
// ensures Error() is model-safe and coded (FND-005 light wiring).
//
// Mode C ConsentRequired is preserved as authentication with authorization_url
// + session_id only (progressive consent UX residual). Never tokens, refresh
// material, client secrets, or Authorization headers.
func mapToolErr(err error) error {
	if err == nil {
		return nil
	}
	// Progressive consent (gateway ConsentRequired): full auth URL + session for
	// agent UX. Must run before generic Classify (which would drop metadata).
	var pc progressiveConsent
	if errors.As(err, &pc) && pc != nil {
		url := strings.TrimSpace(pc.ConsentAuthorizationURL())
		sid := strings.TrimSpace(pc.ConsentSessionID())
		if url != "" && sid != "" {
			return apperr.New(apperr.CodeAuthentication,
				fmt.Sprintf("consent required; authorization_url=%s session_id=%s", url, sid))
		}
		// Incomplete consent metadata: still fail closed as authentication.
		return apperr.Wrap(apperr.CodeAuthentication, "consent required", err)
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
