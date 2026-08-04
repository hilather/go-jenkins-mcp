# Getting started

Three first-class, **read-only by default** deployment paths. Pick one; you do
not need architecture plans or release gates to get a working triage setup.

| Path | MCP runs on | Jenkins | Audience | Est. time | Guide |
|------|-------------|---------|----------|-----------|--------|
| **Local native** | Workstation (native process) | Remote | Individual developer | 10–20 min | [local-native.md](local-native.md) |
| **Local Docker** | Workstation (container) | Remote | Isolation / no local Go | 15–30 min | [local-docker.md](local-docker.md) |
| **Server gateway** | Shared Linux host | Remote / fleet | Teams | 30–60 min | [server.md](server.md) |

## Platforms

- **Supported hosts:** Rocky Linux, Ubuntu (Tier 1). macOS and Windows are out of scope.
- **Jenkins:** any reachable HTTPS Jenkins with a personal API token (or your site’s approved auth mode).
- **Qualification:** free disposable labs are enough — see [testing/qualification.md](../testing/qualification.md).

## Defaults (all paths)

- Personal identity (not a shared service account) where the path supports it
- Read-only tools unless you explicitly enable mutations
- Secrets outside config files and MCP client JSON
- Bounded, redacted model-facing output

## Detailed deployment references

Quick starts stay short. Full volumes, reverse-proxy, upgrade, and rollback:

- [deployment/local-native-stdio.md](../deployment/local-native-stdio.md)
- [deployment/local-docker.md](../deployment/local-docker.md)
- [deployment/server-compose.md](../deployment/server-compose.md)
- [deployment/upgrades-and-rollback.md](../deployment/upgrades-and-rollback.md)

## Related

- User guide (deeper Cursor workflows): [user/README.md](../user/README.md)
- Security: [security/operator-guide.md](../security/operator-guide.md)
