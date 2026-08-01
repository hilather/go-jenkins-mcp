// Package qualify provides an offline (mock) security and performance
// qualification harness for gateway credential modes (GWY-003 lite).
//
// It never performs live Entra / AgentCore network calls. Coverage includes:
//
//   - HOST-011 modes A/B/C Obtain matrix (Basic vault, JWT Bearer vault,
//     AgentCore Live=false / mock Fetcher / wrong audience / consent)
//   - OAUTH-009 offline bearer / fallthrough matrix (Mode B)
//   - OAUTH-010 Mode C prototype matrix (auth_code consent, token_exchange
//     Bearer, Live gates, ModeMatrix residual honesty)
//   - No silent cross-mode fallthrough (HOST-011)
//   - Fail-closed config/binding, process vault hit/miss, mock IdP outage chaos,
//     JWKS kid-selection lite
//
// Live Entra / AgentCore / jwt-auth-filter production pins remain residual.
// Opt-in residual lab: testdata/oauth-lab + make live-oauth-* (HOST-015 mock-token
// for Mode C; not default make test).
// See docs/gateway/qualification.md and docs/auth/oauth-capability-matrix.md §4.
package qualify
