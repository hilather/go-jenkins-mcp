// Package qualify provides an offline (mock) security and performance
// qualification harness for gateway credential modes (GWY-003 lite).
//
// It never performs live Entra / AgentCore network calls. Coverage includes:
//
//   - HOST-011 modes A/B/C Obtain matrix (Basic vault, JWT Bearer vault,
//     AgentCore Live=false / mock Fetcher / wrong audience / consent)
//   - No silent cross-mode fallthrough (HOST-011)
//   - Fail-closed config/binding, process vault hit/miss, mock IdP outage chaos,
//     JWKS kid-selection lite
//
// Live Entra / AgentCore / jwt-auth-filter production pins remain residual.
// Opt-in residual lab: testdata/oauth-lab + make live-oauth-* (not default make test).
// See docs/gateway/qualification.md.
package qualify
