# Fleet peer-cache — offline production release gate (FLC-073)

**Status:** **implemented offline gate pack (2026-08-02)  
**Audience:** release owners, security, operators  
**Not:** a claim of live multi-host production GO without site canary evidence  

**Related:** [shared-cache-operator.md](shared-cache-operator.md) · [shared-cache-architecture.md](shared-cache-architecture.md) · [gates.md](../release/gates.md) · ADR [0016](../adr/0016-fleet-p2p-shared-cache.md)

---

## 1. Effective defaults (must match release notes)

| Control | Default | Notes |
|---------|---------|--------|
| Fleet-cache mode | **`off`** | `JENKINS_MCP_FLEET_CACHE_MODE` / `--fleet-cache-mode` |
| Object classes | **`console_log` only** | Unknown kinds fail closed (FLC-082) |
| Admin MCP fleet tools | **off** until `--enable-admin-mcp` | BFF loopback separate |
| Near-cache promotion | **off** | `AdmitNearCache` Enabled=false |
| HOST-008 multi-pod HA | **Cancelled** | Independent members only |

---

## 2. Offline gate commands (evidence)

Run from repository root (Go **1.25.12** on this tree):

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go version   # expect go1.25.12
gofmt -l internal/fleetcache internal/store internal/admin internal/adminops | tee /tmp/gofmt.out
test ! -s /tmp/gofmt.out
go test -race -count=1 ./internal/fleetcache/ ./internal/store/ ./internal/admin/ ./internal/adminops/ ./internal/fleetmcp/
# Optional broader offline suite when packaging a tag:
# make lint && make test-race   # or make ci when offline-safe
```

Opt-in lab (not required for offline implemented): `make fleet-cache-lab-smoke` (see `testdata/fleet-cache-lab/`).

---

## 3. Rollback / support runbook (must work without data migration)

1. Set mode to **`off`** (flag or env) and restart serve processes.  
2. Local plane A caches remain; peer paths stop.  
3. No schema reverse migration required for mode rollback (FLC-072 `rollback_no_migration`).  
4. Purge residual: process-local tombstones; multi-member HTTP purge residual.  
5. Support: collect secret-free `StatusSummary` / doctor / `admin_fleet_cache_*` residuals — never tokens or log bodies.

Operator walkthrough: [shared-cache-operator.md](shared-cache-operator.md) §10.

---

## 4. Residual register (honest)

| Residual | Owner | Status |
|----------|-------|--------|
| Live multi-host LB canary soak | Operations | Residual (offline dual-dir + lab smoke only) |
| Production mTLS / peer identity | Security / Ops | Residual beyond FLC-016 lab HTTP allowlist |
| Admin SPA fleet-cache page | Product | Residual (BFF+MCP implemented FLC-063) |
| Signed multi-platform release artifacts | Release | Operator / REL-002 packaging residual when not produced in CI |
| SIEM ship of fleet-cache audit | Security | Residual (AUD-001 local) |
| HOST-008 multi-pod shared vault | Architecture | **Cancelled** |
| Extra object classes beyond console_log | Product | Framework implemented (FLC-082); new class = separate PR |

---

## 5. Structured residual review (FLC-073 lite)

| Surface | Check | Outcome |
|---------|-------|---------|
| Mode default | StatusSummary / ResolveConfig | **off** — fail-closed enable |
| Secret-free admin/MCP | fleet_cache tests + canaries | No tokens/Bearer in status/purge |
| Canary rollback | FLC-072 ValidateTransition any→off | Allowed, no migration residual |
| Object class | AdmitObjectClass unknown deny | Fail closed |
| Production GO claims | Operator + architecture docs | Must say residual / mode off |

**Bug-severity findings this gate:** none open; SPA/mTLS/live multi-host explicitly residual (accepted).

---

## 6. Ship surface (high level)

Opt-in peer shared cache for **sealed completed console logs** among multi-fleet members: owner-directed pure-zstd frames, fill leases, RF2/repair library, isolation/crypto proofs, process-local metrics, BFF+MCP fleet-cache status/doctor/purge, canary criteria, running finalize without recompress, operator runbook.

**Do not** enable `read`/`full` by default. **Do not** claim production GO without site canary + packaging evidence beyond this offline pack.
