// Package apperr defines the stable application error taxonomy and safe
// wrapping for model-visible MCP output (FND-005).
//
// Model-visible messages must never include authorization headers, tokens,
// cookies, or raw secret parameters. Internal cause chains remain available
// via errors.Unwrap / Cause for local diagnostic mode only.
package apperr
