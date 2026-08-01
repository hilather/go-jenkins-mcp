# Limited read-only pilot (REL-001)

This package is the **pilot readiness evidence kit** for go-jenkins-mcp on
**Tier-1 Linux only**: Rocky Linux and Ubuntu (Desktop/Server share one binary).
**Windows is out of scope.** macOS is optional and non-blocking.

Real Rocky/Ubuntu pilot installs happen on operator hosts. This repository
provides:

| Artifact | Purpose |
|----------|---------|
| This README | How to run a limited RO pilot without shared credentials |
| [`checklist.md`](checklist.md) | Step-by-step install → diagnose → cache → rollback |
| `jenkins-mcp pilot-check` | Offline/online evidence JSON (doctor + cache + sample verify) |
| `scripts/pilot-evidence.sh` / `make pilot-evidence` | Offline/local secret-free evidence bundle under `dist/pilot-evidence/<ts>/` |
| `scripts/gateway-residual-smoke.sh` / `make residual-smoke` | Opt-in offline residual honesty (qualify + release-evidence residual ids + residual-status honesty canaries; not live GO) |
| [gateway/live-pin-blockers.md](../gateway/live-pin-blockers.md) | Live production GO residual runbook (OAUTH-009/010, HOST-008; residual-smoke proves-vs-not) |
| Deterministic chaos tests (QA-002 lite) | Recovery under truncated fetch, corrupt L1/L2, disk-full pack, mid-evict kill, cancel |

**User path:** [../user/README.md](../user/README.md)  
**Operator path:** [../admin/README.md](../admin/README.md)  
**Optional Docker admin/support (no host package):** [`../../deploy/local/README.md`](../../deploy/local/README.md) · `make local-docker-up`  
**Agent triage:** [../agent-usage.md](../agent-usage.md) · [../tool-contracts.md](../tool-contracts.md)  
**Wave board:** [../phase2-progress.md](../phase2-progress.md) (Wave 20 DOC-001/002)

## Non-negotiable pilot constraints

1. **Personal credentials only** — each pilot user stores their own Jenkins API
   token in **Linux Secret Service** via `jenkins-mcp login`. No shared robot
   accounts, no tokens in CLI args, Cursor `args`, env files, or git.
2. **Read-only default** — pilot runs with global read-only on (POL-001). Do not
   enable mutations unless a separate approved exception exists.
3. **Profile-only Cursor config** — `command` + `args: ["serve", "--profile", "<id>", "--read-only", "--stdio"]` and `JENKINS_MCP_READ_ONLY=true`. **Never** `JENKINS_MCP_AUTH` or `-auth`.
4. **No Windows** — do not collect or claim Windows pilot evidence.
5. **Modes honesty (REL-001)** — record which surfaces/modes were piloted
   (stdio vs gateway **A/B/C**). Offline `gateway qualify` is **not** live
   multi-user production evidence. See [checklist §0](checklist.md).

## Auth modes matrix (pilot evidence)

| Mode | Id | Typical pilot path | Offline evidence | Live residual |
|------|-----|--------------------|------------------|---------------|
| Local stdio | (default) | Cursor + personal API token / OIDC profile | `pilot-check`, doctor | — |
| **A** | `api_token_vault` | Gateway vault per subject (HOST-009) | vault CLI + unit/lab | Multi-user Obtain under load |
| **B** | `jwt_rs_bearer` | Jenkins JWT RS bearer (HOST-010) | offline vault + oauth-lab | Entra + jwt-auth-filter pin |
| **C** | AgentCore Live | 3LO/OBO Obtain (GWY-001) | `gateway qualify --offline` | Live AgentCore / Entra pin |

Default pilot for REL-001 is **local stdio + personal credentials**. Gateway
cohorts are optional and must list modes explicitly on the checklist.

## Prerequisites

- Rocky Linux (supported major) **or** Ubuntu LTS (Desktop or Server)
- Unlocked user session Secret Service (`libsecret` / gnome-keyring or equivalent)
  for interactive login; headless servers fail closed unless policy explicitly
  allows a protected-file fallback (not recommended for pilot)
- Network reachability to the approved Jenkins controller origin
- Signed or checksum-verified Tier-1 package (see [`../packaging.md`](../packaging.md))

## Quick start (limited RO pilot)

```bash
# 1) Install (example: portable tarball)
tar -xzf jenkins-mcp_*_linux_amd64.tar.gz
sudo install -m 0755 usr/bin/jenkins-mcp /usr/local/bin/jenkins-mcp
jenkins-mcp version --json

# 2) Profile (no secrets)
jenkins-mcp profile add corp --url https://jenkins.example.corp/

# 3) Personal login (token never echoed; stored in Secret Service)
jenkins-mcp login --profile corp
# prompts for user + token; verifies identity before success
# Optional OIDC: jenkins-mcp login --profile corp --oidc
# (live Jenkins RS / jwt-auth-filter lab residual — see user guide)

# 4) Doctor + pilot evidence (prefer --offline first for local integrity)
jenkins-mcp doctor --profile corp --offline
jenkins-mcp security self-check --json --profile corp
jenkins-mcp pilot-check --profile corp --offline
# then online when network is approved:
jenkins-mcp pilot-check --profile corp

# 5) Cache status / sample verify
jenkins-mcp cache status --profile corp
jenkins-mcp cache verify --profile corp --sample 3

# 6) Cursor: stdio MCP with profile + --read-only (see user/README.md)

# 7) Optional: debug structured logs for offline analysis (stderr)
#    Captures tool_dispatch_* JSON lines (no secrets / no tool args).
jenkins-mcp serve --profile corp --stdio --read-only --log-level=debug \
  2> pilot-serve.stderr
# or: JENKINS_MCP_LOG_LEVEL=debug
```

Save `pilot-check` JSON (stdout after the human summary) as pilot evidence.
It is scrubbed: no tokens, cookies, or Authorization material.

### Pilot logging (offline analysis)

| Goal | How |
|------|-----|
| Default serve noise | `--log-level=info` (default) or omit flag |
| Per-tool timeline for a failing session | `--log-level=debug` (or `JENKINS_MCP_LOG_LEVEL=debug`) |
| Capture file for a ticket | Redirect **stderr** only (`2> pilot-serve.stderr`) |
| What is safe | tool names, effect class, reason codes, error codes, durations, principal id on human lines |
| What is never logged | tokens, Authorization, tool args, log bodies, job parameters |

See [observability.md](../observability.md#serve-log-level-pilot-offline-analysis) for the message table.
Also run `security self-check` / `support-bundle` for scrubbed posture packs.

## Automated offline evidence pack (`make pilot-evidence`)

Collect version, security self-check, gateway offline qualify, gateway
residual-status (residual honesty), optional consent-residual, optional
doctor/pilot-check, and optional `go test` summary into a timestamped directory:

```bash
export PATH="$HOME/.local/go/bin:$PATH"
# Offline-only (no profile): version + security self-check + gateway qualify
make pilot-evidence PROFILE= SKIP_GO_TEST=1

# With profile (doctor --offline + pilot-check --offline):
make pilot-evidence PROFILE=corp SKIP_GO_TEST=1

# Direct script:
./scripts/pilot-evidence.sh --profile corp --skip-go-test
```

Output: `dist/pilot-evidence/<UTC-timestamp>/` with:

| File | Source |
|------|--------|
| `MANIFEST.json` | Schema `jenkins-mcp.pilot-evidence.manifest.v1` (artifact index + overall) |
| `version.json` | `jenkins-mcp version --json` |
| `security-self-check.json` | `security self-check --json` |
| `gateway-qualify.json` | `gateway qualify --offline` (when available) |
| `gateway-residual-status.json` | `gateway residual-status` (always when subcommand exists; residual honesty canaries hard-fail) |
| `gateway-consent-residual.json` | `gateway consent-residual` (optional when subcommand exists) |
| `doctor.txt` | `doctor --profile … --offline` when `PROFILE` set |
| `pilot-check.json` | `pilot-check --profile … --offline` when `PROFILE` set |
| `go-test-summary.txt` | Bounded `go test` unless `SKIP_GO_TEST=1` |

The pack is **secret-free** by construction (CLI paths that already scrub). Do not
copy live tokens into the evidence directory. Exit code is non-zero when overall
is `fail` (including residual-status honesty canary failure). Without `PROFILE`,
overall is **`incomplete`** (doctor/pilot-check skipped) when the offline
generators pass. Residual-status in this pack is **offline honesty only** — not
live multi-user GO; deeper path canaries remain on `make residual-smoke`.

See also REL-002 gates: [`../release/gates.md`](../release/gates.md).

## Residual honesty smoke (`make residual-smoke`)

Opt-in check that offline lite evidence still lists the residual ids operators
must not treat as live multi-user / Entra / multi-replica GO:

```bash
make residual-smoke
# alias:
make gateway-residual-smoke
# optional doctor gateway_residual_status embed when a profile exists
# (doctor requires --profile; PROFILE empty → doctor step skipped):
make residual-smoke PROFILE=corp
```

Runs `gateway qualify --offline`, `release-evidence --offline`, and
`gateway residual-status`, asserts
`multi_user_offline` · `oauth009_offline` · `oauth010_offline` ·
`progressive_consent_offline` · `host008_single_replica` · `gateway_modes_live`
(**offline only** — not live Entra / AgentCore / multi-replica GO), and writes
artifacts under `dist/residual-smoke/<ts>/`. With `PROFILE=`, also runs
`doctor --offline --json` and asserts nested `gateway_residual_status` honesty
(same map as residual-status; never live GO).
**Not** part of default `make test` / `make ci`. See [release gates](../release/gates.md),
[checklist §0](checklist.md), and [live-pin-blockers.md](../gateway/live-pin-blockers.md)
(what residual-smoke proves vs live pin checklists for OAUTH-009 / OAUTH-010 / HOST-008).

## Doctor / cache / support-bundle / policy

| Command | Use in pilot |
|---------|----------------|
| `jenkins-mcp doctor --profile <id> [--offline] [--json]` | Local + optional whoAmI; `gateway_residual_status` embed (same residual-status map); never prints secrets |
| `jenkins-mcp security self-check [--json] [--profile <id>]` | Secret-free posture (RO, policy residual, RS residual) |
| `jenkins-mcp pilot-check --profile <id> [--offline]` | Combines doctor + cache status + sample verify → exit non-zero on fail + evidence JSON |
| `jenkins-mcp cache status --profile <id>` | L1 data-dir / schema summary |
| `jenkins-mcp cache verify --profile <id> [--sample N\|--full]` | Pack integrity sample (ARC-008) |
| `jenkins-mcp cache repair --profile <id>` | Rebuild sidecar indexes only (never rewrites pack bodies) |
| `jenkins-mcp support-bundle --profile <id> [--preview]` | Privacy-scrubbed zip under XDG cache |
| `jenkins-mcp doctor --profile <id> --bundle` | Doctor then support-bundle |
| `jenkins-mcp policy show-effective --profile <id> [--json]` | Secret-free effective deny list / force RO |
| `jenkins-mcp policy verify --file PATH [--keys PATH]` | Signed or plain overlay check |

Operator detail: [../admin/README.md](../admin/README.md).

## Success criteria (pilot exit evidence)

Record for **both** Rocky and Ubuntu cohorts (macOS optional):

- [ ] Install succeeds; `jenkins-mcp version --json` shows expected build
- [ ] `profile add` + `login` use **personal** API tokens only (no shared creds; no `JENKINS_MCP_AUTH`)
- [ ] `status` / `doctor` show authenticated identity without secrets
- [ ] Cursor MCP uses `--read-only` + `JENKINS_MCP_READ_ONLY=true` (see [user guide](../user/README.md))
- [ ] At least one real workflow: survey / diagnose / log tail on a known job (triage: [agent-usage](../agent-usage.md))
- [ ] `cache status` healthy; `cache verify` sample has `pack_fail=0` (or empty cache)
- [ ] `pilot-check --profile <id>` overall `pass` or `warn` (not `fail`) with saved JSON
- [ ] Optional: `make pilot-evidence PROFILE=<id> SKIP_GO_TEST=1` MANIFEST overall not `fail`
- [ ] **Modes piloted** recorded (stdio and/or A/B/C); gateway residuals named if gateway was in scope
- [ ] No secret/privacy incident; support-bundle used if debugging is needed
- [ ] Rollback path exercised or documented (see [checklist](checklist.md))

## Rollback

1. Remove Cursor MCP entry for the pilot binary.
2. `jenkins-mcp logout --profile <id>` (drops Secret Service credential).
3. Optionally remove profile: `jenkins-mcp profile remove <id>`.
4. User-controlled cleanup of XDG data/cache (see packaging uninstall notes).
5. Reinstall previous signed package if a binary regression is confirmed.

## Chaos / fault-injection (CI evidence)

Deterministic unit suite (QA-002 lite + HTTP expand) — not live Jenkins chaos:

```bash
export PATH="$HOME/.local/go/bin:$PATH"
# Storage / L1 / L2 / logmirror
go test ./internal/store/ ./internal/logmirror/ ./internal/archive/ -count=1 -run Chaos
# Jenkins HTTP client fault injection (httptest; part of default make test)
go test ./internal/jenkins/ -count=1 -run ChaosHTTP
# MCP cancellation smoke (FND-006 residual reduced)
go test ./internal/mcpserver/ ./internal/tools/ -count=1 -run 'Cancel|cancel'
```

Covers:

| Layer | Faults |
|-------|--------|
| store / archive / logmirror | truncated progressive mid-fetch resume, corrupt L1 zstd, corrupt L2 pack + quarantine, disk-full pack write (L1 intact), half-applied evict journal recover, cancel during pack/mirror |
| jenkins HTTP (QA-002 expand) | truncated progressive / mid-stream close, slow handler + context cancel, empty/wrong Content-Length JSON fail-closed (no secret leak), mutation POST connection-reset **no auto-retry**, GET 429/503 Retry-After then success |
| mcpserver / tools | CallTool cancel reaches tool handler context; RunHTTP cancel shutdown |

These stay in `make test` (fast, no Docker).

**Live disposable Jenkins (opt-in only):** `make live-jenkins-test` — see
[`../tst/README.md`](../tst/README.md). Not part of default CI unit gates.

**Residual:** full QA-002 live network disconnect / Jenkins restart / OAuth JWKS
outage / process-kill chaos remains out of this suite. Cursor host stdio
conformance CI is still residual (FND-006). Offline binary stdio smoke
(`make stdio-smoke`, Wave 25) reduces residual further but does not replace Cursor.
Live Entra / jwt-auth-filter lab is residual.

## Optional: Docker admin console (operators)

For day-2 **admin UI / doctor** without installing a host package, use the
first-class local stack (loopback only; lab tokens). **Not** a substitute for
Cursor stdio pilot evidence on Rocky/Ubuntu packages.

```bash
make local-docker-up          # http://127.0.0.1:8787 — see deploy/local/.env for token
make local-docker-doctor
make local-docker-down
```

Docs: [`../../deploy/local/README.md`](../../deploy/local/README.md). Checklist
item is optional under [checklist.md](checklist.md).

## Related docs

- User guide (Cursor + login): [`../user/README.md`](../user/README.md)
- Admin guide: [`../admin/README.md`](../admin/README.md)
- Local Docker support stack: [`../../deploy/local/README.md`](../../deploy/local/README.md)
- Operator security: [`../security/operator-guide.md`](../security/operator-guide.md)
- Tool contracts / agent usage: [`../tool-contracts.md`](../tool-contracts.md), [`../agent-usage.md`](../agent-usage.md)
- Release gates: [`../release/gates.md`](../release/gates.md)
- Platform matrix: [`../adr/0008-platform-matrix.md`](../adr/0008-platform-matrix.md)
- Packaging: [`../packaging.md`](../packaging.md)
- Observability / doctor: [`../observability.md`](../observability.md)
- Live Jenkins lab: [`../tst/README.md`](../tst/README.md)
- Phase 2 board: [`../phase2-progress.md`](../phase2-progress.md)
- Docs index: [`../README.md`](../README.md)
- Backlog REL-001 / DOC-001 / DOC-002: [`../jenkins-mcp-enterprise-agent-todo.md`](../jenkins-mcp-enterprise-agent-todo.md)
