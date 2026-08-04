# Feature — admin MCP tools

**Support status:** Opt-in supported

## Setup

Enable admin MCP registration on serve (`--enable-admin-mcp` or profile equivalent).
Tools call `internal/adminops` / shared libs — not loopback HTTP to admin serve.

## Representative tools

`admin_health`, `admin_doctor`, `admin_metrics`, `admin_audit_list`,
`admin_policy_*`, `admin_cache_*`, `admin_rbac_*`, `admin_saml_config_get`,
`admin_saml_status`, `admin_support_bundle`, …

Full parity matrix: [../admin/mcp-ops-parity.md](../admin/mcp-ops-parity.md).

## Security

Role/confirm gates; secret-free; AUD-001 on destructive ops.

## Rollback

Disable flag; restart.
