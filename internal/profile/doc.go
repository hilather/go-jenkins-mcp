// Package profile models versioned, non-secret Jenkins connection profiles
// (identity, base URL, auth method, data paths, optional OIDC IdP settings)
// and persists them under XDG config. Credential material is never stored
// here; see keyring and auth.
//
// CFG-001 — versioned profile configuration.
// OAUTH-001 — external-IdP OIDC fields (issuer, public clientId, audience,
// redirect allowlist, scopes); no client_secret in profile JSON.
package profile
