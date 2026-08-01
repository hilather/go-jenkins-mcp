# Production release gates (REL-002 lite checklist)

**Objective:** evidence-based go/no-go. A release must not publish when a **mandatory** gate lacks passing evidence or an approved exception.

**Lite scope in this repo:** checklist + commands that produce evidence. Full org sign-off, code signing HSM, and fleet matrices remain operator-owned.

**Honest residual:** Offline `release-evidence` and `make pilot-evidence` **do not** complete production sign-off. Named owners still fill [`evidence-template.md`](evidence-template.md) and attach full suite / package / pilot logs.

Fill-in form: [`evidence-template.md`](evidence-template.md)  
Offline CLI sample: `jenkins-mcp release-evidence --offline [--profile <id>] [--output dist/release-evidence.json]`  
Schema: `jenkins-mcp.release-evidence.v2` (Wave 21 expand)  
Offline pack automation: `make pilot-evidence` → `dist/pilot-evidence/<timestamp>/` (REL-001/002 lite)  
**Residual honesty smoke (opt-in):** `make residual-smoke` (alias `make gateway-residual-smoke`) → `scripts/gateway-residual-smoke.sh` runs `gateway qualify --offline` + `release-evidence --offline` and **fails** if residual ids `multi_user_offline` · `oauth009_offline` · `host008_single_replica` · `gateway_modes_live` are missing. Artifacts under `dist/residual-smoke/<ts>/`. **Not** part of default `make test` / `make ci`. Proves residual ids still advertised — **not** live multi-user / Entra / multi-pod GO. Operator runbook: [gateway/live-pin-blockers.md](../gateway/live-pin-blockers.md).

---

## How to use

1. Record artifact identity (`version --json`, `dist/BUILD_INFO`, `SHA256SUMS`).
2. Run each gate command; attach logs/JSON under a release evidence directory.
3. Optionally run **`make pilot-evidence PROFILE=<id>`** (or `PROFILE=` offline-only) to capture version, security self-check, gateway qualify, doctor/pilot-check into one secret-free bundle with `MANIFEST.json`.
4. Run **`jenkins-mcp release-evidence --offline`** for the expanded lite JSON (version, security self-check, policy self-test, MCP SDK pin, LKG note, gateway offline qualify, structured residuals).
5. Mark pass / fail / exception (with owner + ticket).
6. Complete ownership sign-offs on the template.
7. Decision: **GO** only if all mandatory rows are pass or approved exception.

---

## Gate IDs (map from `release-evidence` checks / residuals)

Stable IDs emitted on `checks[].gate_id` and `residual[].gate_ids` in schema **v2**:

| Gate ID | Matrix section | Offline `release-evidence` check / residual |
|---------|----------------|-----------------------------------------------|
| `REL-002.compat.version` | Compatibility / identity | `version_metadata`, `version_commit` |
| `REL-002.compat.mcp-sdk` | Compatibility · MCP SDK | `mcp_sdk_pin` (+ residual `cursor_host_ci`) |
| `REL-002.compat.gateway` | Compatibility · gateway | `gateway_qualify_offline` |
| `REL-002.compat.auth` | Compatibility · auth | residual `live_entra` |
| `REL-002.compat.modes` | Compatibility · modes A/B/C | residual `gateway_modes_live` + `multi_user_offline` + `oauth009_offline` (operator mode matrix) |
| `REL-002.compat.os` | Compatibility · OS Tier-1 | residual `install_operator` |
| `REL-002.sec.self-check` | Security · self-assessment | `security_self_check` |
| `REL-002.sec.policy` | Security · read-only / deny-only | `policy_engine_self_test` |
| `REL-002.sec.oauth` | Security · OAuth residual | residual `live_entra` |
| `REL-002.ops.doctor` | Reliability / usability · doctor | `doctor_offline` (optional `--profile`) |
| `REL-002.ops.cache` | Reliability · cache | `cache_status` (optional `--profile`) |
| `REL-002.ops.lkg` | Ops · update LKG | `update_lkg` (+ residual `update_install`) |
| `REL-002.rel.unit` | Reliability · `make test` | residual `full_suite` |
| `REL-002.rel.fuzz` | Reliability · fuzz-smoke | residual `full_suite` |
| `REL-002.rel.mcp-matrix` | Reliability · MCP matrix | residual `cursor_host_ci` |
| `REL-002.use.install` | Usability · install docs | residual `install_operator` |
| `REL-002.own.signoff` | Ownership | residual `production_signoff` |

---

## Gate matrix

### Security (mandatory)

| Gate | Evidence command / artifact | Notes |
|------|----------------------------|-------|
| Personal identity + keyring | `go test ./internal/auth/ ./internal/keyring/ ./cmd/jenkins-mcp/ -count=1` + pilot login on Rocky/Ubuntu | No shared SA |
| Secret handling (no argv/log leak) | `go test ./internal/redact/ ./internal/audit/ ./cmd/jenkins-mcp/ -count=1` + canary tests | Support-bundle exclusions; release-evidence secret canary |
| Read-only default | `go test ./internal/policy/ ./internal/tools/ -count=1 -run 'POL\|ReadOnly\|Mutation'` | Mutations omit under RO |
| Policy deny-only self-test | Embedded in `release-evidence --offline` (`policy_engine_self_test`) | Empty deny-only doc + empty target → Allow for valid subject |
| Origin / TLS controls | `go test ./internal/jenkins/ -count=1 -run 'Origin\|TLS\|Transport'` | Verify on by default |
| Cache privacy | Manual: support-bundle `--preview` categories; `go test ./internal/diagnostics/ -count=1` | No tokens in bundle |
| Security self-check (QA-005) | `jenkins-mcp security self-check [--json]` **or** embed via `release-evidence --offline` | Self-assessment only; independent review residual |
| Privacy / retention (QA-006) | `docs/security/privacy-data-retention.md` + canary tests (`-run Privacy\|Canary`) | REL-002 checklist §8 |
| SBOM | `make sbom` → `dist/modules.json` | Scanner input |
| Signing | Org process + `dist/SHA256SUMS` (pilot) | Full cosign/rpmsign residual |
| Independent review | `/review` or PR review record | AGENTS.md |

### Performance (mandatory for claimed SLOs)

| Gate | Evidence command / artifact | Notes |
|------|----------------------------|-------|
| No hidden log over-download | `go test ./internal/jenkins/ ./internal/tools/ -count=1 -run 'Progressive\|Diagnose\|Budget\|Log'` | Progressive frames |
| Cache reuse | diagnose/compare cache tests in `./internal/tools/` | PERF-003 |
| Response limits | budget tests MCP-001 | 64 KiB / 1 MiB |
| Progressive baselines | `make bench-progressive` → `dist/perf-baseline.json` | Opt-in; see `docs/perf-baseline.md` |
| Perf regression budgets (QA-003) | `make perf-regression` → `dist/perf-regression-report.json` | Opt-in; budgets in `docs/perf-budgets.json`; hardware variance documented |
| L2 random access | `go test ./internal/archive/ -count=1` | Multi-frame only |

### Reliability (mandatory)

| Gate | Evidence command / artifact | Notes |
|------|----------------------------|-------|
| Crash / corruption / cancel | `go test ./internal/store/ ./internal/logmirror/ ./internal/archive/ -count=1 -run Chaos` | QA-002 lite |
| Jenkins HTTP chaos | `go test ./internal/jenkins/ -count=1 -run ChaosHTTP` | QA-002 expand (httptest) |
| MCP cancel smoke | `go test ./internal/mcpserver/ ./internal/tools/ -count=1 -run 'Cancel\|cancel'` | FND-006 residual reduced |
| MCP protocol matrix | `go test ./internal/tools/ ./internal/mcpserver/ -count=1 -run 'ProtocolMatrix\|MCPProtocolMatrix'` | FND-006 Wave 20 offline matrix; Cursor host CI residual |
| MCP stdio binary smoke (opt-in) | `make stdio-smoke` | FND-006 Wave 25 offline binary over stdio; Wave 26 optional CI job `stdio-smoke` (continue-on-error, not merge-gate); residual id `stdio_binary_smoke` Done*; Cursor host CI residual |
| Unit + contract suite | `make test` | Merge gate subset |
| Race (when practical) | `make test-race` | Longer |
| Fuzz smoke | `make fuzz-smoke` | QA-001 short |
| Doctor / cache repair | `jenkins-mcp doctor --offline`; cache verify/repair docs | OPS; also optional in release-evidence with `--profile` |

### Compatibility (mandatory for declared matrix)

| Gate | Evidence | Notes |
|------|----------|-------|
| OS Tier-1 | Install + `pilot-check` on **Rocky** and **Ubuntu** | Windows out of scope |
| Package | `make package` / `make package-amd64` | tar always; deb/rpm when tools exist |
| Package offline smoke (optional) | `make package-smoke` | PKG-001 script smoke with `SKIP_DEB`/`SKIP_RPM`; SHA256SUMS + secret canaries; **does not** close cosign/rpmsign residual |
| MCP SDK | `go test ./internal/tools/ -count=1 -run MCP` + `mcp_sdk_pin` in release-evidence (go.mod / build_info) | ADR 0006 versions |
| Gateway offline qualify | `jenkins-mcp gateway qualify --offline` or embed in release-evidence | Live AgentCore residual |
| Auth matrix | API-token cohort evidence; OAuth residual if not claimed | AUTH docs |
| **Modes piloted (A/B/C + stdio)** | Fill [evidence-template](evidence-template.md) mode matrix + [pilot checklist §0](../pilot/checklist.md) | Offline `gateway qualify` ≠ live mode GO; residual `gateway_modes_live` in release-evidence |
| Jenkins LTS / plugins | Org matrix notes (version + Pipeline REST + JUnit) | capability tool |

### Usability (mandatory for pilot/production docs)

| Gate | Evidence | Notes |
|------|----------|-------|
| Install from docs | Follow [user](../user/README.md) + [packaging](../packaging.md) | No plaintext secret examples |
| profile / login / status | Operator runbook | Secret Service |
| diagnose workflow | Real job#build on pilot controller | RO only |
| doctor | `jenkins-mcp doctor --profile <id>` | |
| pilot-check | `jenkins-mcp pilot-check --profile <id> [--offline]` | REL-001 JSON |
| pilot-evidence pack | `make pilot-evidence PROFILE=<id>` or `scripts/pilot-evidence.sh` | Bundle + `MANIFEST.json` under `dist/pilot-evidence/` |
| release-evidence lite | `jenkins-mcp release-evidence --offline [--output PATH]` | Schema v2: version, security self-check, policy self-test, MCP SDK pin, LKG, gateway offline, structured residual[] |
| Residual honesty smoke (opt-in) | `make residual-smoke` / `scripts/gateway-residual-smoke.sh` | Asserts residual ids present; **not** default `make test`; does not close live pins |

### Ownership (mandatory names)

| Role | Named owner (fill in template) |
|------|--------------------------------|
| Release owner | |
| On-call / support | |
| Vulnerability response | |
| Jenkins-side auth/OAuth (if applicable) | |

---

## Suggested evidence capture script

Prefer the automated pack for the local CLI subset:

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make pilot-evidence PROFILE=          # offline-only (incomplete without profile)
# or with profile:
# make pilot-evidence PROFILE=corp SKIP_GO_TEST=1
# → dist/pilot-evidence/<timestamp>/MANIFEST.json
```

Full gate capture (still operator-owned for package/signing/sign-off):

```bash
export PATH="$HOME/.local/go/bin:$PATH"
mkdir -p dist/release-evidence
make lint 2>&1 | tee dist/release-evidence/lint.txt
make test 2>&1 | tee dist/release-evidence/test.txt
make build
./bin/jenkins-mcp version --json | tee dist/release-evidence/version.json
./bin/jenkins-mcp release-evidence --offline --output dist/release-evidence/release-evidence.json
make pilot-evidence PROFILE= SKIP_GO_TEST=1
# optional heavier:
# make fuzz-smoke 2>&1 | tee dist/release-evidence/fuzz-smoke.txt
# make package && cp dist/BUILD_INFO dist/SHA256SUMS dist/release-evidence/
# jenkins-mcp pilot-check --profile corp --offline | tee dist/release-evidence/pilot-check.json
```

---

## `release-evidence` v2 fields (secret-free)

| Field | Meaning |
|-------|---------|
| `schema` | `jenkins-mcp.release-evidence.v2` |
| `offline` | Always true for this command path |
| `overall` | `pass` \| `warn` \| `fail` \| `incomplete` (core offline checks; optional doctor/cache skips do not alone force incomplete) |
| `version` | Binary version / commit / buildTime / go / os / arch |
| `mcp_sdk` | `{module, version, source}` from go.mod parse or build info |
| `security_self_check` | Compact QA-005 summary (`independent_review_required` always true) |
| `update_lkg` | Present/absent note (+ version/channel when present) |
| `gateway_qualify` | Offline GWY-003 suite counts |
| `checks[]` | Rows with `id`, `gate_id`, `status`, `message`, optional `optional` |
| `residual[]` | Structured known residuals (`id`, `gate_ids`, `message`) — live Entra, Cursor host CI, install operator, full suite, production sign-off |

**Does not claim production GO.** Attach full gate matrix evidence + named sign-offs before any production decision.

---

## Residuals (explicit)

- UPD-001 signed manifest verify + optional checksum-only download are implemented; **auto-install and binary rollback remain residual** (prefer package manager).
- `release-evidence --offline` and `make pilot-evidence` do **not** replace full `make test` / package / signing gates; attach those logs separately when claiming production GO.
- Live Entra / jwt-auth-filter / AgentCore Obtain remain residual (offline contracts only).
- **Gateway modes A/B/C live multi-user** remain residual unless the release evidence mode matrix records live pilot cohorts; offline `gateway_qualify` / unit contracts are foundation only (`gateway_modes_live`).
- Structured lite residual ids (automation honesty): `multi_user_offline` (Done\* foundation; not production multi-user GO), `oauth009_offline` (Done\* Bearer matrix; live Entra pin open), `host008_single_replica` (Tier A replicas:1; multi-replica HA residual). See [pilot checklist §0](../pilot/checklist.md).
- **Verify residual honesty offline (opt-in):** `make residual-smoke` / `make gateway-residual-smoke` (`scripts/gateway-residual-smoke.sh`) — fails closed if those ids (plus `gateway_modes_live`) drop from `release-evidence --offline`. Unit contract: `go test ./cmd/jenkins-mcp/ -run 'KnownReleaseResidualIDsStable|ParseReleaseEvidenceResidualJSON'`.
- Cursor host stdio CI remains residual (offline MCP protocol matrix + Wave 25 binary stdio smoke + Wave 26 optional CI job `stdio-smoke`; not real Cursor). Residual ids: `stdio_binary_smoke` Done* vs `cursor_host_ci` open.
- Live Rocky/Ubuntu pilot install evidence remains operator-owned (REL-001).
- Code signing keys and HSM remain organization-owned (packaging placeholder).
- OAUTH-011 Jenkins-as-AS remains **default no-go** ([jas-no-go](../auth/jas-no-go.md), ADR 0013); not a release dependency.
