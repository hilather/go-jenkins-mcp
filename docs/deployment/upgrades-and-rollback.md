# Upgrades and rollback

**Support status:** Supported (process)

## Before upgrade

1. Note current version: `jenkins-mcp version --json` or image tag  
2. Backup XDG config/data/cache volumes and non-secret `.env`  
3. Read [release notes](../release/) for breaking changes  

## Upgrade

| Path | Steps |
|------|--------|
| Native package | Install new RPM/DEB/tarball; restart MCP client |
| Local Docker | New tag/source → `make local-docker-up` rebuild |
| Server Compose | New tag → `docker compose … up -d --build` |

## Rollback

1. Stop new process/containers  
2. Restore previous binary/image tag  
3. Restore config volumes if schema migration occurred  
4. Verify health + one RO Jenkins call  

## Related

- Packaging: [packaging.md](../packaging.md)
- Caching paths: [caching.md](../caching.md)
