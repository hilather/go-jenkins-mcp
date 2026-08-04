# Mutations — residual honesty

**Support status:** Opt-in supported (core preview/confirm gate) · additional write tools tracked in Issues

Mutations are **off by default**. Enable with `--allow-mutations`. Enterprise
`force_read_only` / `--read-only` still win for execute.

## What is shipped

| Area | Notes |
|------|--------|
| MUT gate | Preview → short-lived confirmation token → single-use confirm; cooldown; audit |
| Representative tools | See [tool-contracts.md](../tool-contracts.md) mutation inventory |
| Docs for pilots | [user guide mutations](../user/README.md) · [agent-usage mutations](../agent-usage.md) |

## Open residual (tracker)

Do **not** grow Markdown task lists here. File focused GitHub Issues for:

- Additional power-user write tools not yet exposed
- Admin-console mutation management residual (MUT-ADMIN)
- Classifier / crumb edge cases against live Jenkins (free lab first)

Search Issues with label `enhancement` and title prefix `feat: mutation` (or create one).

## Security

- No invented confirmation tokens
- No secrets in audit or MCP output
- Policy allowlists still apply after the flag is on

## Related

- Features: [../features/mutations.md](../features/mutations.md)
- Tool contracts: [../tool-contracts.md](../tool-contracts.md)
