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

## Rollback

Switch profile `authMethod` back to token; disable gateway multi-user flags.

## Related

- [../auth-architecture.md](../auth-architecture.md)
- [../auth/oauth-capability-matrix.md](../auth/oauth-capability-matrix.md)
