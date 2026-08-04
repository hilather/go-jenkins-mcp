# Feature — local stdio MCP

**Support status:** Supported

## Setup

Install binary, profile, login — [getting-started/local-native.md](../getting-started/local-native.md).

## Verification

Cursor (or compatible client) discovers `jenkins_*` tools; one RO call succeeds.

## Security

Tokens never in MCP client JSON; RO default; redaction on tool output.

## Limits

Tool response budgets — [tool-contracts.md](../tool-contracts.md).

## Troubleshooting / rollback

Remove MCP server entry; `logout`; uninstall binary.
