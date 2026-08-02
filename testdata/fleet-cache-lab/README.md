# Fleet-cache lab (FLC-003) — opt-in three-member scaffold

**Status:** Lab scaffold for multi-member **config + independent data dirs**  
**Not:** production peer-cache GO · fill-lease · RF2  
**Default CI:** **not** in `make test` / `make ci`

Three independent multi-fleet members share one gitops **roster** (with cache eligibility) and **distinct** XDG data volumes so plane A never shares SQLite/frames across members (HOST-008 remains cancelled).

## Layout

```text
testdata/fleet-cache-lab/
  README.md                 # this file
  roster.json               # 3 members + cache eligibility (secret-free)
  mesh-token.lab            # disposable lab mesh token (not production)
  docker-compose.yml        # optional Docker up (3 members + simple LB)
  nginx/lb.conf             # round-robin VIP → members (no stickiness on purpose)
```

## Offline smoke (no Docker)

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make fleet-cache-lab-smoke
# or:
go test ./internal/fleetmcp ./internal/fleetcache -count=1
python3 scripts/validate-task-index.py
```

`make fleet-cache-lab-smoke` validates the lab roster parses, cache eligibility filters match controller/pool, locator golden fixtures pass, and data-dir paths in compose are distinct.

## Docker (optional)

Requires Docker Compose v2 and a successful image build (slow cold start).

```bash
make fleet-cache-lab-up      # build/up 3 members + LB on 127.0.0.1:19080
make fleet-cache-lab-down    # down -v (destroys volumes + ephemeral mesh material mount)
```

| Port | Role |
|------|------|
| `19080` | nginx LB (round-robin; **no stickiness** — exercises multi-member routing) |
| `19443`–`19445` | member peer HTTP binds (host) |

**Env (lab-only):** mesh token from `mesh-token.lab`; members get unique `XDG_DATA_HOME` volumes `fc-data-a|b|c`.

### Residuals

| Residual | Notes |
|----------|--------|
| Peer sealed-log **protocol** | Not implemented yet — members may only expose fleet ops/health when `fleet-mode` is on |
| Production mTLS / unique node identity | Mesh token lab only |
| Real Jenkins origin in this compose | Optional later; offline unit path is the CI gate |
| Stickiness | Intentionally **off** on LB so cold multi-member behavior is visible |

## Tear-down

```bash
make fleet-cache-lab-down
# removes containers and named volumes (independent caches destroyed)
```

Never commit production mesh tokens. Rotate `mesh-token.lab` freely; it is disposable.

## See also

- ADR [0016](../../docs/adr/0016-fleet-p2p-shared-cache.md)  
- SLOs [shared-cache-slos.md](../../docs/fleet/shared-cache-slos.md)  
- Roster example with cache blocks: `roster.json`  
