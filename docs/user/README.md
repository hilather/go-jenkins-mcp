# User guide — go-jenkins-mcp (Cursor stdio)

**Audience:** developers and pilot users on **Tier-1 Linux** (Rocky Linux, Ubuntu).  
**macOS and Windows are out of scope.** Tier-1: Rocky Linux + Ubuntu only.  
**Wave 20 (DOC-001):** pilot path kept in sync with waves 16–19 code; no false production claims.

This guide gets you from install → personal login → Cursor MCP → common diagnosis workflows **without ever putting a token in Cursor config, CLI history examples, or git**.

Related:

| Doc | Purpose |
|-----|---------|
| [Admin guide](../admin/README.md) | Packages, policy, gateway env, live lab, telemetry, HTTP rules |
| [Operator security guide](../security/operator-guide.md) | Tokens, keyring, support bundles, threat-model pointer |
| [Tool contracts](../tool-contracts.md) | MCP tool inventory, budgets, RO vs mutation |
| [Agent usage](../agent-usage.md) | How agents should triage builds (diagnose → compare → evidence) |
| [Pilot kit](../pilot/README.md) | Limited RO pilot evidence (REL-001) |
| [Pilot checklist](../pilot/checklist.md) | Per-host install → diagnose → cache → rollback |
| [Packaging](../packaging.md) | Install artifacts and XDG paths |
| [Caching](../caching.md) | Log store + gateway caches; configure for Cursor, Docker, fleet, gateway |

---

## 1. Prerequisites

- Binary on `PATH` (`jenkins-mcp version` or `jenkins-mcp version --json`)
- Unlocked user session **Secret Service** (e.g. `libsecret` / gnome-keyring / KeePassXC) for interactive token storage
- Network reachability to your approved Jenkins origin (HTTPS preferred)
- A **personal** Jenkins API token (created in Jenkins user settings) — **never shared**

---

## 2. Install (Tier-1)

Rocky Linux or Ubuntu only. Prefer a checksum-verified package from your enterprise channel.

```bash
# Portable tarball (always produced by make package)
tar -xzf jenkins-mcp_*_linux_amd64.tar.gz
sudo install -m 0755 usr/bin/jenkins-mcp /usr/local/bin/jenkins-mcp

# Ubuntu (when DEB is published)
# sudo dpkg -i jenkins-mcp_*_amd64.deb

# Rocky (when RPM is published)
# sudo dnf install ./jenkins-mcp-*.rpm

jenkins-mcp version --json
```

Ordinary use does **not** require root after the binary is on `PATH`. Config, cache, and credentials are **per-user**. Details: [admin guide](../admin/README.md), [packaging](../packaging.md).

---

## 3. One-time setup (profile + login)

Profiles hold **non-secret** connection data only (URL, display name, TLS paths).  
Credentials live in the OS keyring after `login`.

```bash
# Create a profile (no secrets in this command)
jenkins-mcp profile add corp --url https://jenkins.example.corp/

# Interactive login (API token — pilot / first production path):
# prompts for username + API token on the terminal.
# Token is verified against Jenkins, then stored in Secret Service.
# Success output prints identity only — never the token.
jenkins-mcp login --profile corp

# Confirm keyring + identity (no secrets printed)
jenkins-mcp status --profile corp
jenkins-mcp doctor --profile corp --offline
```

### Optional: external-IdP OIDC login

When the profile `authMethod` is `oidc_bearer` (or you pass `--oidc`):

```bash
# Opens the corporate browser (Authorization Code + PKCE).
# Stock Jenkins is NEVER the authorization server (ADR 0003).
# Requires profile oidc.redirectUris with http://127.0.0.1:<port>/...
# and a configured jenkinsAudience (Jenkins API resource, not Graph).
jenkins-mcp login --profile corp --oidc
```

Optional operator Entra + jwt-auth-filter lab (not a production pin):
[entra-jwt-rs-lab.md](../testing/entra-jwt-rs-lab.md).

**Residual (live RS lab):** offline OIDC discovery, claim validation, and
resource-server contract tests are implemented. **Live** Jenkins LTS +
`jwt-auth-filter` (or approved proxy) pin, JWKS outage under load, and
full route fallthrough evidence remain **open** — see
[jwt-auth-filter qualification](../auth/jwt-auth-filter-qualification.md) §8
and `jenkins-mcp oauth probe-rs --profile corp --offline` / doctor check
`rs_auth`. Do not claim OAuth cohort production readiness until live lab
evidence exists.

### Never put secrets in

- Cursor `mcp.json` / `command` / `args` / `env`
- shell history examples or scripts committed to git
- profile JSON under `~/.config/jenkins-mcp/`
- long-lived desktop environment variables (test-only login env exists for automation; see security guide)

**Do not use** `-auth user:token` or `JENKINS_MCP_AUTH` — those bootstrap paths are **removed** (fail closed). Use `login --profile` + Secret Service only (headless CI may set `JENKINS_MCP_KEYRING_FILE`).

---

## 4. Cursor stdio configuration (read-only default)

Read-only is the **pilot and production default** (POL-001). Prefer explicit flags/env so hosts never rely on “forgot to set RO.”

### Recommended Cursor MCP entry

```json
{
  "mcpServers": {
    "jenkins": {
      "command": "jenkins-mcp",
      "args": [
        "serve",
        "--profile",
        "corp",
        "--read-only",
        "--stdio"
      ],
      "env": {
        "JENKINS_MCP_READ_ONLY": "true"
      }
    }
  }
}
```

Notes:

- Use the absolute path to the binary if it is not on Cursor’s `PATH` (e.g. `/usr/bin/jenkins-mcp`).
- **Never** put `user:token`, API tokens, or `JENKINS_MCP_AUTH` in `args` or `env`.
- There is **no** supported “generic inverse switch” that bypasses enterprise `force_read_only` or a stronger profile RO setting.
- Optional adapters (`ext-logs`, `work-items`, `otel-correlate`) are **off** unless the host adds `--enable-adapter=…` — pilot Cursor configs should stay RO + core tools only unless an exception is approved.

### Shared cache with local Docker admin (optional)

Operator SoT for all cache planes and deploy types: **[caching.md](../caching.md)** (especially § Cursor stdio and § local Docker).

Default host stdio uses `~/.config|share|cache/jenkins-mcp`. The local Docker admin stack uses **separate** named volumes unless you opt into **shared XDG** so Cursor and Docker share profile + L1/log cache:

1. Follow [`deploy/local/README.md`](../../deploy/local/README.md) § *Agent + cache models* → **Model 2**.
2. Point Cursor `env` at absolute `XDG_CONFIG_HOME` / `XDG_DATA_HOME` / `XDG_CACHE_HOME` under the repo’s `.local-mcp/xdg/…` tree.
3. Keep `--read-only` + `JENKINS_MCP_READ_ONLY=true`; still no tokens in Cursor config.

This is the usual way to get **valuable Docker-backed cache** while keeping Cursor on **stdio**.

### Optional TLS / proxy for enterprise networks

Prefer profile fields (paths only):

```bash
jenkins-mcp profile add corp \
  --url https://jenkins.example.corp/ \
  --ca-bundle /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
  --proxy http://proxy.corp:8080
```

CLI `--ca-bundle` / `--proxy` on `serve` override the profile. Certificate verification is **always on** by default. Diagnostic TLS skip requires **both** `--diag-insecure-tls` and `JENKINS_MCP_DIAG_INSECURE_TLS=1` (never a silent production default).

---

## 5. Common MCP tools (what to ask for first)

Prefer **high-level triage** tools over dumping full console logs.

| Goal | Tool | Typical args |
|------|------|----------------|
| Triage one failed build | `jenkins_diagnose_build` | `job_name`, `build_number` |
| Survey recent failures | `jenkins_survey_recent_failures` | `job_names` or `job_prefix` (+ `allow_cross_job` if multi-job) |
| Compare fail vs green | `jenkins_compare_builds` | `job_name`, `build_a`, `build_b` |
| Find when it broke | `jenkins_find_regression_window` | `job_name`, failing build range |
| Pipeline stage log | `jenkins_get_stage_log` | `job_name`, `build_number`, `stage_name` or `stage_id` |
| Bounded console tail | `jenkins_get_build_log_tail` | `job_name`, `build_number`, `max_length` |
| Controller / queue health | `jenkins_controller_health`, `jenkins_queue_pressure` | — |

**Full inventory, budgets, error codes:** [tool-contracts.md](../tool-contracts.md).  
**Recommended triage order (agents):** [agent-usage.md](../agent-usage.md) — diagnose → compare / regression / graph → bounded evidence only.

**Treat all build logs, tests, and artifacts as untrusted model input.** They may contain secrets that Jenkins itself printed; redaction reduces but does not eliminate risk.

---

## 6. Daily operator commands

| Command | Use |
|---------|-----|
| `jenkins-mcp status --profile corp` | Credential present? verified principal? |
| `jenkins-mcp doctor --profile corp [--offline]` | Local integrity + optional whoAmI |
| `jenkins-mcp cache status --profile corp` | L1 store / schema summary |
| `jenkins-mcp support-bundle --profile corp --preview` | See what a support zip includes/excludes (offline security/RS lite members; no secrets) |
| `jenkins-mcp logout --profile corp` | Remove keyring credential |
| `jenkins-mcp version --json` | Machine-readable build metadata |

---

## 7. Mutations (disabled by default)

**Default pilot and production posture is read-only.** Mutation tools (start job, stop build, cancel queue, power-user writes, …) are **not registered** unless you deliberately enable them.

### Enablement (opt-in)

| Control | Default | Effect |
|---------|---------|--------|
| `--allow-mutations` | **off** | When set **and** no stronger RO is in force, mutation tools **register** (and are executable when RO is not effective) |
| `--read-only` / `JENKINS_MCP_READ_ONLY=true` | often **on** in Cursor | Process RO — mutations not executable (and pilot configs should keep this) |
| Enterprise `force_read_only` | site policy | **Cannot** be defeated by `--allow-mutations` alone |
| Profile RO | profile field | Stronger RO still wins |

**CLI / lab enable (stdio or HTTP):**

```bash
# Opt-in mutations for a deliberate non-RO host (not the pilot Cursor entry)
jenkins-mcp serve --profile corp --stdio --allow-mutations

# Same with local Streamable HTTP
jenkins-mcp serve --profile corp --http 127.0.0.1:8765 --allow-mutations
```

Do **not** combine pilot Cursor configs with both `--read-only` and `--allow-mutations` expecting writes — RO wins. Enterprise force RO still registers mutation tools for ListTools honesty in some modes but they remain **not executable** until force clears (doctor check `mutations` shows this).

**Optional Cursor entry (mutations host only — not pilot default):**

```json
{
  "mcpServers": {
    "jenkins-mutations": {
      "command": "jenkins-mcp",
      "args": [
        "serve",
        "--profile",
        "corp",
        "--stdio",
        "--allow-mutations"
      ]
    }
  }
}
```

Still **never** put tokens in `args` / `env`. Prefer a separate MCP server id from your RO pilot entry so everyday triage stays read-only.

**Verify posture:**

```bash
jenkins-mcp doctor --profile corp --json --allow-mutations
# Check mutations: allow_mutations_opt_in, mutations_should_register, mutations_executable
```

### Preview → confirm (always)

Even after enablement:

1. Call **without** `confirmation_token` → **preview** + short-lived token.
2. Show the user the preview (job / build / queue id, redacted params, mode).
3. Only after **explicit human confirm**, call again with the token **once**.
4. Agents must never invent confirmation tokens.
5. Preview rate limit and confirm cooldown apply (see [agent-usage.md](../agent-usage.md#5-mutations-and-confirmation)).

### Tools available when enabled

**Seed + power-user mutate tools:** `jenkins_start_job`, `jenkins_stop_build`, `jenkins_cancel_queue_item`, `jenkins_interrupt_build` (`mode=stop|term|kill`), `jenkins_rebuild_build`, `jenkins_replay_pipeline` (same definition only), `jenkins_set_job_buildable`, `jenkins_set_build_keep_forever`, `jenkins_set_build_description`, `jenkins_cancel_queue_items_for_job` (cap 20).

Optional enterprise overlay allowlists (further restrict, never elevate): `allow_mutation_tools`, `allow_interrupt_modes`, `allow_mutation_job_prefixes`.

`jenkins_start_job` validates parameters against job definitions (MUT-002): secret types and secret-named keys are rejected; choice/boolean must match definitions. Wrong-state targets (finished builds, left queue) return errors, not success.

**Not** exposed (MUT-ADMIN residual): script console, config.xml write, credentials, nodes, plugins, quiet-down.

More detail: [agent-usage.md § Mutations](../agent-usage.md#5-mutations-and-confirmation) · [tool-contracts.md](../tool-contracts.md) · [power-user backlog](../mutations/power-user-backlog.md).

---

## 8. Troubleshooting (safe actions)

| Symptom / error code | Safe action |
|----------------------|-------------|
| `authentication` | Re-run `login --profile`; check Secret Service unlocked; never paste token into chat |
| `authorization` | Your Jenkins user lacks Job/Read (or similar); use personal account, not a shared SA |
| `policy_denial` | Global RO, `deny_tools`, or `deny_job_prefixes` blocked the tool — expected in pilot; do not seek bypass |
| `not_found` | Check job full name (`folder/job`); not an HTTP URL |
| `timeout` / `cancelled` | Narrow scope; use diagnose/survey budgets; retry once |
| `corrupt_cache` | `cache verify` / `cache repair --index-only`; doctor offline |
| `quota` | Free disk; wait for cache maintenance; pin only needed generations |
| `capability_missing` | Controller lacks Pipeline REST / JUnit / etc.; use alternate tool or residual note |
| `invalid_argument` | Fix typed refs (job full name, positive build numbers) |

Full stable codes: `internal/apperr` / [tool-contracts.md](../tool-contracts.md#error-codes).

---

## 9. Platform residual

- **Tier 1:** Rocky Linux + Ubuntu only  
- **Out of scope:** macOS and Windows (ADR 0008)

Pilot evidence and rollback: [pilot kit](../pilot/README.md) · [checklist](../pilot/checklist.md).
