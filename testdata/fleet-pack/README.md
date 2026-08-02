# Multi-fleet pack fixtures

Secret-free examples for multi-host convergence. See
[docs/fleet/multi-fleet-rollout.md](../../docs/fleet/multi-fleet-rollout.md).

| Path | Role |
|------|------|
| `profiles/site-a.json`, `site-b.json` | Two fleet members (URL only) |
| `policy/overlay.json` | Shared deny-only + `subjects.users` / `subjects.groups` |
| `policy/README.md` | How to sign for `REQUIRE_SIGNED_POLICY` |
| `keys/README.md` | Public keys only |
| `roster/roster.example.json` | Example `fleet_*` MCP membership roster (peer URLs; no secrets) |

**Fleet MCP** (`fleet_metrics`, etc.): see [docs/fleet/fleet-mcp-ops.md](../../docs/fleet/fleet-mcp-ops.md).  
Requires `--fleet-mode` + member id + roster path + mesh token (not multi-pod HA).

**Not** production secrets. **Not** a local user directory.
