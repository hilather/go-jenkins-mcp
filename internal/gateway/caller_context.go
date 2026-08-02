package gateway

import (
	"context"
	"os"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/contracts"
)

// EnvGatewayMultiUser enables per-request multi-user Obtain on gateway serve
// (HOST-001/003 residual beyond single-subject pin).
//
// When truthy (1/true/yes/on):
//   - AuthProviderCtx selects Caller from request context (or process default)
//   - HTTP ExpectedExternalSubject pin is NOT applied
//   - HTTP AfterIdentity injects gateway.Caller into request context
//
// Default off: single-process foundation keeps process-bound caller + subject pin.
const EnvGatewayMultiUser = "JENKINS_MCP_GATEWAY_MULTI_USER"

type callerCtxKey struct{}

// ContextWithCaller returns a child context carrying the validated gateway Caller
// (HOST multi-user Obtain). Caller must contain only non-secret labels.
// Nil parent becomes context.Background().
func ContextWithCaller(ctx context.Context, c Caller) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, callerCtxKey{}, c)
}

// CallerFromContext returns the gateway Caller previously stored by
// ContextWithCaller (or HTTP AfterIdentity wire). ok is false when unset.
// Never contains tokens.
func CallerFromContext(ctx context.Context) (Caller, bool) {
	if ctx == nil {
		return Caller{}, false
	}
	c, ok := ctx.Value(callerCtxKey{}).(Caller)
	if !ok {
		return Caller{}, false
	}
	return c, true
}

// CallerFromHTTPInbound maps trusted HTTPInbound + process profileID to Caller
// (HOST multi-user). ExternalSubject → Subject; Tenant/Workload from inbound;
// ProfileID is always the process default (never spoofed from client headers
// that are not part of the trusted identity contract for profile namespace).
//
// Does not require Verified — callers that need verified-only should check
// HTTPInbound.Verified before mapping. Empty ExternalSubject yields invalid Caller.
func CallerFromHTTPInbound(in HTTPInbound, profileID contracts.ProfileID) Caller {
	return Caller{
		Subject:    strings.TrimSpace(in.ExternalSubject),
		Tenant:     strings.TrimSpace(in.Tenant),
		WorkloadID: strings.TrimSpace(in.WorkloadID),
		ProfileID:  contracts.ProfileID(strings.TrimSpace(string(profileID))),
	}
}

// MergeCallerDefaults fills empty Tenant/WorkloadID/ProfileID on c from defaults
// (process-bound gateway subject). Subject is never taken from defaults when c
// already has a Subject — prevents elevating to another identity.
//
// Use after CallerFromHTTPInbound so lab partial claims inherit process tenant/
// workload/profile while keeping the HTTP ExternalSubject.
func MergeCallerDefaults(c, defaults Caller) Caller {
	out := c
	if strings.TrimSpace(string(out.ProfileID)) == "" {
		out.ProfileID = defaults.ProfileID
	}
	if strings.TrimSpace(out.Tenant) == "" {
		out.Tenant = strings.TrimSpace(defaults.Tenant)
	}
	if strings.TrimSpace(out.WorkloadID) == "" {
		out.WorkloadID = strings.TrimSpace(defaults.WorkloadID)
	}
	return out
}

// MultiUserEnabled reports whether JENKINS_MCP_GATEWAY_MULTI_USER is truthy.
// getenv nil defaults to os.Getenv.
func MultiUserEnabled(getenv func(string) string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	return envTruthy(getenv(EnvGatewayMultiUser))
}
