package gateway

import (
	"context"
	"errors"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// TokenFetcher obtains a Jenkins-audience credential for a validated caller
// (GWY-001 offline-mock / live pin path).
//
// Implementations must:
//   - never log, return via Error()/String(), or embed access tokens in metadata
//   - never fall back to a shared Jenkins service account
//   - fail closed on wrong audience / protocol errors
//   - return *ConsentRequired (or wrap it) when interactive consent is needed
//
// Default production construction leaves AgentCoreProvider.Fetcher nil so
// Live=false stays the fail-closed default until operators inject a fetcher.
type TokenFetcher interface {
	FetchJenkinsCredential(ctx context.Context, caller Caller, cfg AgentCoreConfig) (Credential, error)
}

// FuncTokenFetcher adapts a function to TokenFetcher (tests and explicit injection).
type FuncTokenFetcher func(ctx context.Context, caller Caller, cfg AgentCoreConfig) (Credential, error)

// FetchJenkinsCredential implements TokenFetcher.
func (f FuncTokenFetcher) FetchJenkinsCredential(ctx context.Context, caller Caller, cfg AgentCoreConfig) (Credential, error) {
	if f == nil {
		return Credential{}, apperr.New(apperr.CodeCapabilityMissing, "token fetcher is not configured")
	}
	return f(ctx, caller, cfg)
}

// mapFetcherError converts TokenFetcher failures into stable apperr codes.
// ConsentRequired is preserved for progressive consent UX. No shared-SA fallback.
func mapFetcherError(err error) error {
	if err == nil {
		return nil
	}
	if cr, ok := AsConsentRequired(err); ok && cr != nil {
		return cr
	}
	var ae *apperr.Error
	if errors.As(err, &ae) && ae != nil {
		// Already classified (authentication, capability_missing, etc.).
		return err
	}
	if errors.Is(err, context.Canceled) {
		return apperr.Wrap(apperr.CodeCancelled, "gateway credential fetch cancelled", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return apperr.Wrap(apperr.CodeTimeout, "gateway credential fetch timed out", err)
	}
	// Unknown fetcher failure: treat as authentication (fail closed; no SA).
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		msg = "credential fetch failed"
	}
	// Never forward raw error text that might contain tokens; keep short class only.
	return apperr.New(apperr.CodeAuthentication, "credential fetch failed")
}

// wrongAudienceError is the stable fail-closed residual for audience mismatch.
func wrongAudienceError(got string) error {
	got = strings.TrimSpace(got)
	if got == "" {
		return apperr.New(apperr.CodeAuthentication,
			"token audience missing or does not match configured Jenkins API resource")
	}
	// Do not echo the full wrong audience if it looks secret-like; keep short.
	return apperr.New(apperr.CodeAuthentication,
		"token audience does not match configured Jenkins API resource")
}
