# Product qualification

## Policy

- **Free disposable labs are sufficient** for product qualification.
- Customer production Entra, AgentCore, corporate certificates, or production
  Jenkins are **optional operator validation**, not release blockers.

## Offline merge gate

```bash
make fmt && make lint && make test && make build && make package && make vuln
make docs-check
```

## Free labs (opt-in)

| Lab | Command | Covers |
|-----|---------|--------|
| Jenkins LTS | `make live-jenkins-test` | HTTP client + RO smoke |
| OAuth mock | `make live-oauth-test` | Gateway OAuth modes |
| JWT RS + Keycloak | `make live-jwt-rs-test` | jwt-auth-filter free lab (default) |
| Optional operator Entra + jwt-auth-filter | [entra-jwt-rs-lab.md](entra-jwt-rs-lab.md) (manual; not a merge gate) | Browser PKCE + real Entra JWKS on the same Jenkins lab |
| SAML Keycloak | `make live-saml-test` | SAML SP |
| Fleet cache | `make fleet-cache-lab-smoke` | Peer cache offline/lab |
| Local Docker admin | `make local-docker-smoke` | Admin stack |

Record skipped labs and why in the PR when integration boundaries change.

## Related

- [../architecture/testing.md](../architecture/testing.md)
- [../tst/README.md](../tst/README.md)
