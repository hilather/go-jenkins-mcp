# Integrations

External systems and optional adapters. Core Jenkins path does **not** require adapters.

| Integration | Status | Doc |
|-------------|--------|-----|
| Jenkins HTTP API | Supported | [jenkins.md](jenkins.md) |
| Personal API token + keyring | Supported | [auth-modes.md](auth-modes.md) |
| OIDC / JWT resource-server | Opt-in · free-lab | [auth-modes.md](auth-modes.md) |
| SAML SP (identity/groups) | Opt-in · free-lab | [auth-modes.md](auth-modes.md) |
| Adapter framework | Opt-in supported | [adapters.md](adapters.md) |
| ext-logs | Opt-in · mock free-lab; SaaS residual | [../adapters/ext-logs.md](../adapters/ext-logs.md) |
| work-items | Opt-in / metadata-oriented | [../adapters/work-items.md](../adapters/work-items.md) |
| otel-export / correlate | Opt-in · mock backends | [../adapters/otel-export.md](../adapters/otel-export.md) · [../adapters/otel-correlate.md](../adapters/otel-correlate.md) |
| Fleet peer cache | Opt-in | [../fleet/shared-cache-operator.md](../fleet/shared-cache-operator.md) |

## Related

- Features: [../features/README.md](../features/README.md)
- Architecture: [../architecture/integrations.md](../architecture/integrations.md)
- Optional operator Entra + jwt-auth-filter walkthrough (not a production pin): [../testing/entra-jwt-rs-lab.md](../testing/entra-jwt-rs-lab.md)
