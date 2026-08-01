# Phase 1 progress

Tracks Phase 1 implementation after multi-wave subagent merges.  
Incomplete work lists **next steps**.

## Status board

| Task | Status | Notes |
|------|--------|--------|
| **SEC-001..003** | Done* | Threat model + layered redaction + control sanitize. *Owner sign-off residual. |
| **AUTH-000..004** | Done | Keyring, whoAmI bind + Wave 23 mid-serve re-verify (`IdentityReverifyGate`) + Wave 28 audit-on-mismatch (`auth_fail` / `identity_*` reason codes). |
| **CFG-001/002** | Done | Profiles + enterprise overlay. |
| **POL-001..005** | Done | RO + deny-only RBAC + multi-layer PEPs + adversarial tests. |
| **MCP-001/002** | Done | Budgets + typed job/build/queue/log refs. |
| **LOG-001..004** | Done | Bounded fetch, generations, frames, multi-log fan-out, MCP local path. |
| **NET-001..004** | Done | Origin pin, transport, resilience, CA/proxy/mTLS. |
| **STO-001..004** | Done | Secure dirs, SQLite, independent Zstd frames, crash-safe commit. |
| **SEARCH-001/002** | Done | Literal + RE2 over L1 frames; optional `jenkins_search_logs` tool. |
| **AUD-001** | Done | Local JSONL/memory audit sink; denials + login/serve events. |
| **OBS-001** | Done | Structured stderr logger + in-process metrics registry. |

## Pilot flow

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make test && make build

jenkins-mcp profile add corp --url https://jenkins.example.com \
  --ca-bundle /etc/ssl/corp-ca.pem
jenkins-mcp login --profile corp
jenkins-mcp serve --profile corp --stdio --read-only
```

With `--profile`, serve opens L1 store, logmirror, search engine, and audit file under the profile data dir.

## Verify

```bash
make test
make lint
make build
go test -race -count=1 ./internal/search/ ./internal/store/ ./internal/logmirror/ ./internal/redact/ ./internal/audit/ ./internal/telemetry/ ./internal/tools/
```

## Next steps

See **`docs/phase2-progress.md`** for ARC / JEN / PIPE / TEST / DIAG / OPS / HEALTH wave.

- [ ] **MUT-001** mutation preview/confirm (still RO by default)  
- [ ] **PKG-001** signed Rocky/Ubuntu packages  
- [ ] **ARC-004+** when ratarmount-rs is supplied  
- [ ] Commit + tag baseline when ready  
