// Package auth provides credential providers and session types for Jenkins
// access (API token via keyring; OIDC profile/discovery + PKCE helpers).
// Authentication is not a global string; providers return scoped sessions (AUTH-001).
//
// AUTH-003/004: login stores tokens only after VerifyIdentity (whoAmI) succeeds;
// sessions may bind a non-secret Principal. Status never includes tokens.
//
// OAUTH-001: external-IdP OIDC discovery validation and PKCE S256 pure helpers.
// Browser login loop is OAUTH-002 residual (writes via OIDCProvider.StoreTokens).
//
// OAUTH-004: TokenBundle + TokenStore (keyring method=oidc_tokens), single-flight
// refresh (grant_type=refresh_token), atomic refresh-token rotation, invalid_grant
// clears store and demands re-login.
//
// OAUTH-007: logout (best-effort IdP revocation when revocation_endpoint known;
// always clear local keyring + memory), status has_refresh bool + recovery hint.
//
// OAUTH-008: capability matrix constants (docs/auth/oauth-capability-matrix.md).
//
// Wave 14 residual close: LiveSessionSource + SessionGuard for mid-serve OIDC
// refresh and fail-closed tool gating; ValidateServeAccessToken for JWT re-check
// at serve start (opaque tokens still bind via whoAmI).
//
// Wave 15 residual: SessionEpochStore (non-secret session.epoch under profile
// data dir) bumped on login/StoreTokens and logout; LiveSessionSource watches
// the file so CLI logout fail-closes a running serve without waiting for refresh
// failure or process restart. Epoch files never contain tokens.
//
// Wave 23 / AUTH-004 mid-serve: IdentityReverifyGate re-runs whoAmI on cache TTL
// expiry and fail-closes on anonymous / 401 / principal id drift from the
// serve-time bound principal. MultiGate composes Live/epoch then reverify for
// OIDC; api_token serve attaches reverify alone.
//
// Wave 24 / AUTH-004: re-verify TTL is configurable via
// JENKINS_MCP_IDENTITY_REVERIFY_TTL or --identity-reverify-ttl (flag wins);
// empty/zero → DefaultIdentityCacheTTL (5m); bounds min 10s max 30m (fail closed
// at serve start via ParseIdentityReverifyTTL). Residual by design: not
// continuous every-call whoAmI — only on TTL expiry / cache miss.
//
// OAUTH-003 (offline): ValidateAccessToken claim matrix (iss/aud/alg/exp/nbf/azp/tid,
// ID-token rejection, Graph/known-bad audiences, size bound). LoginOIDC and serve
// both call it for JWT-shaped access tokens; opaque tokens skip JWT parse and rely
// on whoAmI. Live RS lab remains OAUTH-005/009 residual.
//
// HOST-001 JWKS refresh foundation: JWKSSource / RefreshingJWKS (TTL refresh,
// stale-if-error, optional MaxStaleAge fail-closed, per-validation Get).
// Env JENKINS_MCP_HTTP_JWKS_REFRESH_TTL (default 5m, min 30s max 1h);
// JENKINS_MCP_HTTP_JWKS_MAX_STALE (default 0 unlimited, min 1m max 24h when set;
// process-local). Residual: multi-instance shared JWKS cache, live Entra under load.
//
// OAUTH-009 (offline expand): rs_qualification fallthrough classifier (status +
// WWW-Authenticate + body class), JWKS outage fail-closed pure contracts,
// RequiredMCPRoutes inventory completeness, RFC 9728 protected-resource metadata
// parser (fixture-only). Live jwt-auth-filter lab remains residual.
//
// OAUTH-006 (light): ExtractGroups / BoundGroups with MaxStoredGroups + MaxGroupNameBytes.
// Entra group overage (_claim_names/_claim_sources or groups-as-ref) without a full
// groups array fails closed (CheckIncompleteGroupOverage); hybrid concrete groups OK.
// Microsoft Graph membership expansion remains residual (OAUTH-010).
//
// Legacy -auth / JENKINS_MCP_AUTH remain bootstrap-only (KD-003 deprecated path).
package auth
