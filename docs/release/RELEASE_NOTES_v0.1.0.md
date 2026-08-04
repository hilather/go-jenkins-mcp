# v0.1.0 — First enterprise pilot release

First tagged **read-only pilot** baseline of the enterprise `go-jenkins-mcp` fork.

## Highlights

- **Phase 0–1 foundations**: profiles, keyring (Secret Service), whoAmI bind, deny-only RBAC, progressive logs, budgets, cache/store, search, audit, doctor/pilot-check
- **Phase 2 hardening through Wave 53**: NET resilience operator resolves (JSON body, retries, circuit, concurrent, backoff), soft target absolute **64 MiB**, mutation confirm cooldown / max previews / token TTL, operator_caps honesty
- **Pilot logging**: `--log-level` / `JENKINS_MCP_LOG_LEVEL` (`debug|info|warn|error`); structured secret-free `tool_dispatch_*` JSON on stderr for offline analysis
- **Platforms**: Rocky Linux / Ubuntu Tier-1 only; **macOS and Windows out of scope**
- **Transport**: prefer **stdio** + `--read-only` (loopback HTTP is residual; not the pilot default)

## Install (portable tarball)

```bash
tar -xzf jenkins-mcp_v0.1.0_linux_amd64.tar.gz
sudo install -m 0755 usr/bin/jenkins-mcp /usr/local/bin/jenkins-mcp
jenkins-mcp version --json
```

Or Debian/Ubuntu:

```bash
sudo dpkg -i jenkins-mcp_v0.1.0_amd64.deb
```

Verify checksums against `SHA256SUMS` in this release.

## Limited RO pilot (personal API token)

```bash
jenkins-mcp profile add corp --url https://jenkins.example.com/
jenkins-mcp login --profile corp
jenkins-mcp doctor --profile corp
jenkins-mcp serve --profile corp --stdio --read-only

# Offline analysis (optional):
jenkins-mcp serve --profile corp --stdio --read-only --log-level=debug 2> pilot-serve.stderr
```

Cursor MCP: profile only + `--read-only` + `--stdio` — **never** put tokens on argv or in `JENKINS_MCP_AUTH`.

See `docs/pilot/README.md` and `docs/pilot/checklist.md`.

## Artifacts

| File | Notes |
|------|--------|
| `jenkins-mcp_v0.1.0_linux_amd64.tar.gz` | Portable Tier-1 layout (`usr/bin/jenkins-mcp`) |
| `jenkins-mcp_v0.1.0_amd64.deb` | Ubuntu/Debian package (when built) |
| `SHA256SUMS` | Checksums for attached assets |
| `BUILD_INFO` | Version / commit / Go / arch metadata |

**Code signing residual**: packages are not cosign/rpm-signed in this pipeline (see `docs/packaging.md`).

## Honesty / residuals

This is a **pilot** release, not a claim of full enterprise production completeness. Still residual (non-exhaustive):

- Live Entra / jwt-auth-filter lab / AgentCore Obtain production pin
- Production multi-tenant gateway isolation
- Adapter allowlist cosign / SBOM / HSM supply-chain provenance
- True t-of-n threshold crypto / production HSM
- Live multi-controller chaos / reverse-proxy origin pin matrix
- LKG auto-install / binary rollback (operator-owned)

Full list: `docs/archive/phase2-progress.md`.

## Commit

- Tag: `v0.1.0`
- Tree: enterprise pilot baseline (Phases 0–2 through Wave 53 + pilot logging)
