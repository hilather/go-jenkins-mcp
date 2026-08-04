# Security policy

## Supported platforms

Local client support targets **Rocky Linux** and **Ubuntu** (Tier 1) only.
**macOS and Windows clients are out of scope.** See
`docs/architecture/platform.md` §19 and ADR 0008.

## Reporting a vulnerability

Do **not** open a public GitHub issue for security-sensitive reports.

1. Email or use the private security contact configured for the
   `hilather/go-jenkins-mcp` repository (GitHub Security Advisories preferred
   when enabled).
2. Include: affected version/commit, reproduction steps, impact, and whether
   credentials or customer data are involved.
3. Allow a reasonable window for triage before public disclosure.

## Secrets handling (development and agents)

- Never commit Jenkins API tokens, OAuth refresh tokens, private keys, or
  cookie material.
- Do not put secrets in CLI arguments, fixtures, snapshots, CI logs, or MCP
  tool results.
- Unit tests must not require live Jenkins credentials.

## Product security posture (summary)

- Fail closed: Jenkins allow ∧ global read-only ∧ MCP policy ∧ budgets.
- Credentials in OS secret stores (Linux Secret Service on Tier 1).
- Treat Jenkins logs/artifacts as untrusted model input.
- Progressive log transfer must be bounded (no unbounded body reads).
- Jenkins is a resource server / protected API — **not** a native 3LO OAuth
  authorization server (see auth architecture below).

## Threat model and auth architecture

| Doc | Purpose |
|-----|---------|
| [`docs/security/threat-model.md`](docs/security/threat-model.md) | SEC-001 assets, actors, trust boundaries, data classes, control map |
| [`docs/auth-architecture.md`](docs/auth-architecture.md) | AUTH-000 identity paths, non-solutions, no-native-3LO terminology |
| [`docs/adr/0003-jenkins-not-oauth-authorization-server.md`](docs/adr/0003-jenkins-not-oauth-authorization-server.md) | Binding ADR |
| [`docs/auth/jas-no-go.md`](docs/auth/jas-no-go.md) | JAS-001 threat model + default no-go enforcement |

See `AGENTS.md` and the architecture document for enforcement requirements.
