# Architecture — admin console and admin MCP

**Support status:** Opt-in supported

```mermaid
flowchart TB
  Browser[Operator browser] --> SPA[web/admin SPA]
  SPA --> BFF[internal/admin BFF]
  Agent[Agent] --> Tools[admin_* MCP tools]
  Tools --> Ops[internal/adminops]
  BFF --> Libs[policy audit store diagnostics gateway …]
  Ops --> Libs
```

| Rule | Detail |
|------|--------|
| Shared libraries | MCP tools do **not** HTTP-proxy to admin serve |
| Secret-free | No tokens in JSON, logs, support bundles |
| Charts | Apache ECharts only in SPA |
| Opt-in | `--enable-admin-mcp` for admin tools on serve |
| SPA merge gate | `make admin-ui-check` / CI job `admin-ui` (Node 22). Go `lint-test-build` does not typecheck TSX. |

## Related

- [../admin/README.md](../admin/README.md)
- [../admin/mcp-ops-parity.md](../admin/mcp-ops-parity.md)
- ADR 0014
