# Deploy — local native stdio

**Support status:** Supported

Host-native `jenkins-mcp serve --stdio` is the default Cursor entry (ADR 0002).

## Layout

- Config: XDG config home (`~/.config/jenkins-mcp/` typically)
- Data/cache: XDG data/cache homes
- Credentials: OS Secret Service after `login` (not profile JSON)

See [packaging.md](../packaging.md) and [caching.md](../caching.md).

## Run

```bash
jenkins-mcp serve --profile <id> --stdio --read-only
```

Cursor invokes this as the MCP `command`. Do not embed tokens in client config.

## Verification / rollback

- Quick start: [getting-started/local-native.md](../getting-started/local-native.md)
- Disable: remove MCP server entry; `logout`; uninstall binary
