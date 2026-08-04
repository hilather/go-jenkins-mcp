# Feature — fleet MCP tools

**Support status:** Opt-in supported

## Setup

Fleet mode / mesh token flags as documented in [../fleet/fleet-mcp-ops.md](../fleet/fleet-mcp-ops.md).
Not multi-pod HA.

## Tools

`fleet_list_members`, `fleet_health`, `fleet_cache_status`, `fleet_doctor`, …

## Security / rollback

Mesh auth; residual honesty for multi-host live. Disable fleet flags to roll back.
