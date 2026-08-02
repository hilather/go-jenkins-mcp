# Project history

**go-jenkins-mcp** is an independently maintained enterprise Jenkins MCP product
([hilather/go-jenkins-mcp](https://github.com/hilather/go-jenkins-mcp), module
`github.com/hilather/go-jenkins-mcp`).

## Origin (past tense)

Early source was imported from the community MIT project
[simonfxr/go-jenkins-mcp](https://github.com/simonfxr/go-jenkins-mcp) at commit
`83f66a9c57c0bc26044f654e589b6361787f0c89` (2026-04-21; import date 2026-07-31).
That tree was a **historical seed only** — not the long-term architecture, not a
living upstream fork, and not an architecture source of truth for agents.

Byte-for-byte import notes and the frozen baseline tag (if present) live under
[`docs/archive/`](archive/) for license and archaeology. Prefer this product’s
`docs/`, ADRs, and `AGENTS.md` for current design.

## License

MIT. Original copyright notice for Simon Reiser’s contribution is retained in
`LICENSE` / `NOTICE` as required by the license. Product ownership and ongoing
maintenance are under the hilather repository.

## What changed since the import

The product replaced the monolithic seed layout with package boundaries
(`cmd/jenkins-mcp`, `internal/*`), profile + OS keyring auth (legacy `-auth` /
`JENKINS_MCP_AUTH` **removed**), read-only defaults, policy/RBAC, bounded logs,
admin console, gateway offline modes, and the rest of the enterprise backlog.

Open risk is tracked as **product residuals** (see
[`docs/security/product-residuals.md`](security/product-residuals.md)), not as
“seed known defects.”
