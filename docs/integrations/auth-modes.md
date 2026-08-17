# Integration — authentication modes

| Mode | Status | Setup / verify |
|------|--------|----------------|
| API token + Secret Service | Supported | `login --profile` · `status` |
| OIDC browser (PKCE) | Opt-in supported | `login --oidc` · offline claim tests |
| Gateway JWT / AgentCore | Free-lab validated | `testdata/oauth-lab`, `jwt-rs-lab` |
| SAML SP | Free-lab validated | `make live-saml-test` |
| Jenkins-as-AS | Not implemented | [../auth/jas-no-go.md](../auth/jas-no-go.md) |

## Security

Audience/iss/exp fail-closed; no shared SA tokens in examples; mid-serve re-verify.
OIDC issuers must be https (cleartext http is accepted only for loopback test
fixtures/labs — discovery, token, and JWKS traffic all use that channel). The
RFC 8707 `resource` indicator (profile `oidc.jenkinsAudience`) is sent at login
**and** on every refresh so refreshed access tokens stay Jenkins-audience
scoped. SAML assertions must be signed by the pinned IdP key and carry a
Recipient equal to the configured ACS URL plus a NotOnOrAfter expiry — missing
or malformed security timestamps fail closed (ADR 0015).

## Rollback

Switch profile `authMethod` back to token; disable gateway multi-user flags.

## Related

- [../auth-architecture.md](../auth-architecture.md)
- [../auth/oauth-capability-matrix.md](../auth/oauth-capability-matrix.md)
