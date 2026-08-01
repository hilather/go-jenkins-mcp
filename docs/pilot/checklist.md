# Pilot operator checklist (REL-001)

Use one copy per host. Platforms: **Rocky Linux** or **Ubuntu** only.
Windows: stop — not a pilot platform.

Companion: [README.md](README.md) · [user guide](../user/README.md) · [admin guide](../admin/README.md) · [agent usage](../agent-usage.md)

Host OS: _____________  (Rocky / Ubuntu)  
Binary version/commit: _____________  
Profile id: _____________  
Operator: _____________  Date: _____________

## 0. Deployment surface + auth modes piloted (REL-001)

Record **what was actually piloted**. Do not claim gateway multi-user production
from offline qualify alone. Modes: **A** personal API-token vault,
**B** Jenkins JWT RS bearer, **C** AgentCore 3LO/OBO Live (see
[gateway README](../gateway/README.md), [roadmap](../roadmap/server-team-hosted.md)).

| Surface | Piloted? (Y/N) | Evidence path / command | Residual honesty |
|---------|----------------|-------------------------|------------------|
| Local Cursor **stdio** (default ADR 0002) | | `pilot-check` / Cursor session notes | Personal Secret Service token |
| Mode **A** gateway (`api_token_vault`) | | vault inventory secret-free / lab | Live multi-user Obtain residual |
| Mode **B** gateway (`jwt_rs_bearer`) | | HOST-010 offline / oauth-lab | Live Entra + jwt-auth-filter residual |
| Mode **C** gateway (AgentCore Live) | | `gateway qualify --offline` only unless live pin | Live AgentCore / Entra Obtain residual |
| Offline gateway qualify only | | `gateway-qualify.json` in pilot-evidence pack | **Not** live multi-user GO |
| Admin console (loopback / Docker) | | optional `local-docker-*` | localStorage token pilot-only |

Modes **not** piloted: _____________  
Gateway residual accepted (ticket/notes): _____________  

**REL lite residual ids** (from `jenkins-mcp release-evidence --offline`; do not treat as live GO):  
`multi_user_offline` · `oauth009_offline` · `host008_single_replica` · `gateway_modes_live`  
See [release gates](../release/gates.md) residuals section.

## 1. Install

- [ ] Verified package checksum (`SHA256SUMS`) against published artifact
- [ ] Binary on `PATH` (`jenkins-mcp version` prints expected version/commit)
- [ ] No secrets in install scripts or environment

## 2. Profile

- [ ] `jenkins-mcp profile add <id> --url <https://jenkins…/>`
- [ ] `jenkins-mcp profile show <id>` — URL correct; **no token fields**
- [ ] Optional TLS: `--ca-bundle` / profile `caBundlePath` if corporate CA required
- [ ] Cursor `mcpServers` uses **profile only** + `--read-only` + `--stdio` (no `-auth`, no `JENKINS_MCP_AUTH`)
- [ ] Cursor env includes `JENKINS_MCP_READ_ONLY=true` (see [user guide](../user/README.md#4-cursor-stdio-configuration-read-only-default))

## 3. Login / whoami

- [ ] `jenkins-mcp login --profile <id>` with **personal** API token (not shared)
- [ ] Token stored in Secret Service; not written to disk config
- [ ] `jenkins-mcp status --profile <id>` shows authenticated user, method `api_token`, **no secret material**
- [ ] Online doctor identity: `jenkins-mcp doctor --profile <id>` (or skip with `--offline` when network blocked)
- [ ] Optional OIDC cohort: `login --oidc` only with approved profile; record **live RS residual** if not lab-qualified

## 4. Diagnose / survey (read-only workflows)

- [ ] MCP or CLI path reaches controller (capabilities / health as available)
- [ ] At least one of: survey recent failures, diagnose build, progressive log tail
- [ ] Prefer triage flow in [agent-usage.md](../agent-usage.md) (diagnose → compare → bounded evidence)
- [ ] Confirm global read-only remains on (mutations denied if attempted)
- [ ] Note job/build used (non-secret): _____________
- [ ] Optional offline log capture: serve with `--log-level=debug` and save stderr (`2> pilot-serve.stderr`) if investigating failures

## 5. Cache verify

- [ ] `jenkins-mcp cache status --profile <id>` — dataDir OK, schema OK
- [ ] `jenkins-mcp cache verify --profile <id> --sample 3` — `pack_fail=0` or empty archives
- [ ] If pack failures: `cache repair --index-only` then re-verify; quarantine path documented if corrupt

## 6. Pilot evidence package

- [ ] `make pilot-evidence PROFILE=<id> SKIP_GO_TEST=1` → `dist/pilot-evidence/<ts>/MANIFEST.json` overall not `fail`
- [ ] `gateway-qualify.json` present when pack ran (offline GWY-003; **not** live AgentCore pin)
- [ ] Section **0** mode matrix filled (modes A/B/C + stdio surface)
- [ ] `jenkins-mcp security self-check --json --profile <id>` → saved or noted (secret-free)
- [ ] `jenkins-mcp pilot-check --profile <id> --offline` → overall not `fail`; JSON saved
- [ ] `jenkins-mcp pilot-check --profile <id>` (online) when approved → JSON saved
- [ ] Optional: `jenkins-mcp support-bundle --profile <id>` for ticket attachment (scrubbed)
- [ ] Optional enterprise overlay: `policy show-effective --profile <id>` matches intended deny list
- [ ] Enterprise gateway pin residual (if claimed): `JENKINS_MCP_REQUIRE_SIGNED_POLICY=1` + trusted keys (see [policy-bundles](../security/policy-bundles.md))
- [ ] Evidence files stored in pilot tracker (not in git with secrets)

## 7. Optional — Docker admin path (support / no host package)

Not required for Cursor stdio pilot evidence. Useful when operators need the
admin console without an RPM/DEB install. SoT: [`../../deploy/local/README.md`](../../deploy/local/README.md).

- [ ] `make local-docker-up` (or `LOCAL_COMPOSE_PROFILES=with-jenkins make local-docker-up`)
- [ ] Open `http://127.0.0.1:8787` with lab token from `deploy/local/.env` (never commit `.env`)
- [ ] `make local-docker-doctor` offline OK
- [ ] `make local-docker-down` after use (volumes wiped)

## 8. Rollback

- [ ] Cursor MCP entry removed or pointed at previous binary
- [ ] `jenkins-mcp logout --profile <id>`
- [ ] Optional: `profile remove`, XDG cache/data cleanup (user-controlled)
- [ ] Previous package reinstall verified if regression
- [ ] If Docker admin was used: `make local-docker-down`

## Sign-off

| Item | OK? |
|------|-----|
| No shared credentials | |
| No secrets in logs/support bundle | |
| No `JENKINS_MCP_AUTH` / `-auth` in Cursor config | |
| Rocky **or** Ubuntu evidence recorded | |
| Modes piloted recorded (A/B/C/stdio); gateway residual honest | |
| Go / no-go recommendation | go / no-go / deferred |

Notes / defects: _____________
