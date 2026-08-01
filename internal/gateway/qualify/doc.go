// Package qualify provides an offline (mock) security and performance
// qualification harness for gateway 3LO/OBO paths (GWY-003 lite).
//
// It never performs live Entra / AgentCore network calls. Coverage includes
// fail-closed config/binding, process vault hit/miss, mock IdP outage chaos,
// and JWKS kid-selection lite. Live Entra pin / JWKS under load remain residual
// — see docs/gateway/qualification.md.
package qualify
