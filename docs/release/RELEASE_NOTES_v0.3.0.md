# Release notes — v0.3.0

**Date:** 2026-08-01  
**Tag:** `v0.3.0`  
**Baseline:** continues `v0.2.0` admin/gateway foundations

## Highlights

### Opt-in power-user Jenkins mutations (MUT-010…017)

Behind `--allow-mutations` and no stronger RO (`--read-only`, env, enterprise force):

| Tool | Purpose |
|------|---------|
| `jenkins_interrupt_build` | `mode=stop\|term\|kill` |
| `jenkins_rebuild_build` | Rebuild using prior build parameters |
| `jenkins_replay_pipeline` | Same-definition replay (no script-edit default) |
| `jenkins_set_job_buildable` | Enable/disable job |
| `jenkins_set_build_keep_forever` | Keep-forever (no-op when already matching) |
| `jenkins_set_build_description` | Description (max 4096) |
| `jenkins_cancel_queue_items_for_job` | Cap 20; optional `stuck_only`; folder-safe full-name match |

All use MUT-001 preview → confirm. Overlay allowlists: `allow_mutation_tools`, `allow_interrupt_modes`, `allow_mutation_job_prefixes` (wired into serve).

### Gateway residual honesty (Waves 9–17)

- residual-status / residual-smoke / pilot-evidence canaries for shared_*_file, vault XDG, consent path, limiter max
- Admin health camelCase progressive consent store residual
- Support-bundle progressive_consent nest + `stores_tokens` sanitize allowlist
- Consent process-store mutex (race-safe under `go test -race`)

### Product / docs

- Merged remote presentation polish: README, GitHub Pages site, issue/PR templates
- Power-user backlog SoT: `docs/mutations/power-user-backlog.md`

## Still residual (not production multi-user GO)

- Live Entra / jwt-auth-filter pin / AgentCore Identity vault
- Multi-pod HA (HOST-008) — later **cancelled**; multi-fleet is the scale model
- MUT-ADMIN: config.xml, credentials, script console, plugins, quiet-down

Pilot default remains read-only stdio + personal API token.

## Verify

```bash
make lint && go test -count=1 ./... && go test -count=1 -race ./...
make residual-smoke   # offline residual honesty; not live GO
```
