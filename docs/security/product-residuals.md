# Product residuals (operator honesty)

Living residual risk for **this product** — not seed-fork debt. Historical seed
defect IDs (KD-*) are closed or rehomed here after the UPSTREAM-EXIT cut.

| Area | Status | Residual |
|------|--------|----------|
| Progressive log bounds | **Fixed** for app buffers / payload caps | Jenkins may still emit a small write-buffer multiple on the wire until close; full logical overdownload is a regression |
| Log tail without `X-Text-Size` | **Reduced** | True seek tail needs size header; otherwise bounded prefix |
| Credentials on argv/env (`-auth`, `JENKINS_MCP_AUTH`) | **Removed** | Fail closed; use `login --profile` + Secret Service (or `JENKINS_MCP_KEYRING_FILE` headless CI residual) |
| Log redaction | **Strong** | Sub-threshold hex FN / git-SHA FP / force-flush boundary; prefer `telemetry.Logger` |
| Mutations always-on | **Fixed** | RO default; `--allow-mutations` opt-in only |
| Package monolith | **Fixed** | `cmd/` + `internal/*` |
| Jenkins HTTP resilience | **Done\*** offline | Live reverse-proxy path-prefix matrix residual |
| Streamable HTTP loopback | **Partial** | Shared secret optional on loopback by default (pilot); not multi-user auth; prefer stdio (ADR 0002) |
| Live Entra / jwt-auth-filter / AgentCore | **Product free-lab Done\*** | Site production pin is **operator-owned residual** — not open product DoD. Free labs kept: `live-jenkins-*`, `live-oauth-*`, `live-saml-*`. Policy: [free-lab-qualification.md](../gateway/free-lab-qualification.md). Runbook: [live-pin-blockers.md](../gateway/live-pin-blockers.md). Doctor keeps `mode_*_live_*_qualified=false` until **that site** attaches evidence. |
| Multi-pod gateway HA | **Cancelled / out of scope** | Same-host flock lite historical Done\*; multi-pod HA is **not** a product task — use **multi-fleet** (independent single-replica members + shared signed policy). See HOST-008 cancelled + [multi-fleet-rollout.md](../fleet/multi-fleet-rollout.md). |

Archive of the former seed defect table (historical):
[`docs/archive/KNOWN_DEFECTS.md`](../archive/KNOWN_DEFECTS.md).
