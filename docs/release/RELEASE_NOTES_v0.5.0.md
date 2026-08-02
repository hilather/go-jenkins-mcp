# Release notes — v0.5.0

**Date:** 2026-08-02  
**Tag:** `v0.5.0`  
**Baseline:** continues `v0.4.0` (admin MCP ops, POL-006 bindings, gateway residual honesty)

## Highlights

### Product identity (UPSTREAM-EXIT)

- Module and product identity: `github.com/hilather/go-jenkins-mcp`
- Seed history moved to past-tense docs (`docs/HISTORY.md`, `docs/archive/`)
- Hard-retire of `-auth` / `JENKINS_MCP_AUTH` bootstrap (fail closed; `login --profile` + keyring only)
- Optional headless file keyring residual for CI (`JENKINS_MCP_KEYRING_FILE`)

### Multi-fleet + policy SoT

- Multi-fleet rollout: shared **signed policy** + per-host profiles (no local user DB) — [`docs/fleet/multi-fleet-rollout.md`](../fleet/multi-fleet-rollout.md)
- Fixtures: `testdata/fleet-pack/`
- **HOST-008 multi-pod gateway HA cancelled** — scale via multi-fleet single-replica members, not multi-pod shared vault/rate

### Fleet-wide MCP reads (`fleet_*`)

Opt-in request-time fan-out across roster members (mesh-token peer API). **Not** multi-pod HA.

| Enable | `--fleet-mode` (bool) + `--fleet-member-id` + `--fleet-roster` + mesh token (`JENKINS_MCP_FLEET_MESH_TOKEN` or `--fleet-mesh-token-file`) |
|--------|------------------------------------------------------------------------------------------------------------------------------------------|

**Tools (when config valid):** `fleet_list_members`, `fleet_health`, `fleet_version`, `fleet_metrics`, `fleet_residual_status`, `fleet_doctor`, `fleet_cache_status`

- Membership only from roster (tool args cannot invent peers)
- Partial peer failures set `incomplete` with per-member residuals
- Secret-free envelopes; optional peer listen `--fleet-peer-listen`
- Design SoT: [`docs/fleet/fleet-mcp-ops.md`](../fleet/fleet-mcp-ops.md)

### Cache quota operator tunables (ARC-007)

| Flag / env | Default | Bounds |
|------------|---------|--------|
| `--cache-total-quota-bytes` / `JENKINS_MCP_CACHE_TOTAL_QUOTA_BYTES` | 10 GiB | min 64 MiB, max 1 TiB fail closed |
| `--cache-low-disk-bytes` / `JENKINS_MCP_CACHE_LOW_DISK_BYTES` | 1 GiB | min 16 MiB, max 1 TiB fail closed |

Serve maintenance, offline `cache quota` / eviction plan/evict, and admin BFF/MCP share `store.ResolveQuotaConfig`. Operator guide: [`docs/caching.md`](../caching.md).

### SAML admin SSO + Access / RBAC management

- **POL-007 Done\* offline:** SAML SP (`internal/saml`, `JENKINS_MCP_SAML_CONFIG`), ACS session, group→role map; Keycloak lab (`testdata/saml-lab`, `make live-saml-*` / saml-lab targets)
- **UI-011 Done\* pilot:** Access SPA + BFF `/admin/v1/policy/bindings` + `admin_rbac_*` MCP tools
- Fleet SoT for bindings remains **signed config**, not SPA alone
- Live Entra/Okta/ADFS production pin remains operator residual

### Free labs vs production pin policy

- Product free-lab bar kept: disposable Jenkins, oauth-lab, jwt-rs lab, saml-lab
- Site Entra / jwt-auth-filter / AgentCore production pin = operator residual ([`docs/gateway/free-lab-qualification.md`](../gateway/free-lab-qualification.md), [`live-pin-blockers.md`](../gateway/live-pin-blockers.md))

### Managed update residual honesty (UPD-001)

- Signed manifest verify + optional checksum download + LKG remain; **no** auto-install / in-process binary swap
- Install/rollback operator / package-manager owned — [`docs/release/update.md`](update.md)

### Agent / docs hygiene

- Session todos: **remove completed items** (open queue only) — `AGENTS.md` + global rule
- Living product residuals: [`docs/security/product-residuals.md`](../security/product-residuals.md)
- Platform: Tier-1 Rocky + Ubuntu only; macOS/Windows out of scope (ADR 0008)

## Breaking / migration

| Change | Operator action |
|--------|-----------------|
| `-auth` / `JENKINS_MCP_AUTH` removed | Use `login --profile` + Secret Service (or file keyring residual for CI) |
| HOST-008 multi-pod HA not a product path | Do not plan `replicas > 1` interactive gateway HA; use multi-fleet members |
| `fleet_*` tools default **off** | Enable only with full fleet mode + roster + mesh token |
| Cache total quota now operator-settable | Unset keeps 10 GiB default; invalid bounds fail closed at resolve/start |

## Security / residual honesty

| Residual | Status |
|----------|--------|
| Live Entra / production jwt-auth-filter / AgentCore | Operator site pin — not free-lab DoD |
| Multi-pod HA | **Cancelled** (multi-fleet) |
| Fleet peer mTLS | Residual (mesh token shipped for free-lab / same-host) |
| SIEM audit ship | AUD-T residual |
| ratarmount-rs dual L2 path | ARC-000 qualification open; native Go L2 required |
| Per-user usage metrics | Process totals only; not per-subject request/byte dashboards |
| MUT-ADMIN surfaces | Still out of scope without security go |

Pilot default remains **read-only** stdio + personal API token. Admin MCP, fleet MCP, and mutations stay **opt-in**.

## Verify

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make lint
go test -count=1 ./...
make residual-smoke
./bin/jenkins-mcp version --json

# Fleet MCP unit evidence
go test -count=1 ./internal/fleetmcp/ ./internal/tools/ -run 'Fleet'
```

Package:

```bash
make admin-ui   # optional SPA embed
make package VERSION=v0.5.0
```

## Docs index (this release)

| Doc | Topic |
|-----|--------|
| [`docs/caching.md`](../caching.md) | Cache planes + quota config by deploy type |
| [`docs/fleet/multi-fleet-rollout.md`](../fleet/multi-fleet-rollout.md) | Shared policy multi-fleet |
| [`docs/fleet/fleet-mcp-ops.md`](../fleet/fleet-mcp-ops.md) | `fleet_*` MCP fan-out |
| [`docs/release/update.md`](update.md) | UPD-001 residual honesty |
| [`docs/admin/mcp-ops-parity.md`](../admin/mcp-ops-parity.md) | `admin_*` + fleet pointer |
| [`docs/security/product-residuals.md`](../security/product-residuals.md) | Living residual honesty |
