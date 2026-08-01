// Package authlab provides disposable OAuth/JWT lab helpers for HOST-012…HOST-015.
//
// These are **lab-only** mock IdP, JWT resource-server, and token-exchange peers
// for opt-in Docker Compose integration. They are not production auth code.
// Production packages must never import this package for runtime identity.
//
// Offline unit tests run under `make test`. Live Docker smoke is opt-in via
// `make live-oauth-test` / `scripts/oauth-lab-smoke.sh` (not default CI).
//
// Residual: real Entra, real jwt-auth-filter plugin pin, real AgentCore vault.
package authlab
