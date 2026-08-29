# Documentation — go-jenkins-mcp

Task-oriented index for the product. Active pages describe **current** behavior.
Open work lives in [GitHub Issues](https://github.com/hilather/go-jenkins-mcp/issues).
Historical material is under [archive/](archive/).

**Product site:** [hilather.github.io/go-jenkins-mcp](https://hilather.github.io/go-jenkins-mcp/) · **Repo README:** [../README.md](../README.md)

## Support status labels

| Label | Meaning |
|-------|---------|
| **Supported** | Implemented, tested, documented |
| **Opt-in supported** | Requires an explicit enable flag/env; default off |
| **Free-lab validated** | Exercised on disposable free lab infrastructure |
| **Experimental** | May change; not a stability commitment |
| **Stub/demo** | Mock, scaffold, or demo only |
| **Not implemented | Named only; not usable |

## Start here

| Intent | Go to |
|--------|--------|
| **Local native** (stdio + remote Jenkins) | [getting-started/local-native.md](getting-started/local-native.md) |
| **Local Docker** (workstation container → remote Jenkins) | [getting-started/local-docker.md](getting-started/local-docker.md) |
| **Server gateway** | [getting-started/server.md](getting-started/server.md) |
| Choose a path | [getting-started/README.md](getting-started/README.md) |
| Cursor / pilot user guide | [user/README.md](user/README.md) |
| Agent triage patterns | [agent-usage.md](agent-usage.md) |

## Deploy and operate

| Intent | Go to |
|--------|--------|
| Deployment drill-downs | [deployment/](deployment/) |
| Local admin/support Docker stack | [../deploy/local/README.md](../deploy/local/README.md) |
| Gateway scaffold | [../deploy/gateway/README.md](../deploy/gateway/README.md) · [gateway/](gateway/) |
| Packaging / XDG paths | [packaging.md](packaging.md) |
| Caching (L1/L2, gateway, fleet) | [caching.md](caching.md) |
| Admin console | [admin/README.md](admin/README.md) · [admin/api-v1.md](admin/api-v1.md) |
| Observability / audit | [observability.md](observability.md) |
| Security operator guide | [security/operator-guide.md](security/operator-guide.md) |

## Architecture and security

| Intent | Go to |
|--------|--------|
| Architecture overview + diagrams | [architecture/README.md](architecture/README.md) |
| ADRs | [adr/README.md](adr/README.md) |
| Auth model | [auth-architecture.md](auth-architecture.md) · [architecture/authentication.md](architecture/authentication.md) |
| Policy / RBAC | [policy-rbac.md](policy-rbac.md) · [architecture/authorization.md](architecture/authorization.md) |
| Threat model | [security/threat-model.md](security/threat-model.md) |

## Features and integrations

| Intent | Go to |
|--------|--------|
| Features index | [features/README.md](features/README.md) |
| Integrations / adapters / auth modes | [integrations/README.md](integrations/README.md) |
| MCP tool contracts | [tool-contracts.md](tool-contracts.md) |
| Mutations (opt-in) | [user/README.md](user/README.md) (mutations section) · [mutations/power-user-backlog.md](mutations/power-user-backlog.md) |

## Test and qualify

| Intent | Go to |
|--------|--------|
| Qualification policy & free labs | [testing/qualification.md](testing/qualification.md) |
| Optional operator Entra + jwt-auth-filter (not a merge gate) | [testing/entra-jwt-rs-lab.md](testing/entra-jwt-rs-lab.md) |
| Live Jenkins route matrix | [tst/README.md](tst/README.md) |
| Contributor CI | [../CONTRIBUTING.md](../CONTRIBUTING.md) |

## Reference

| Intent | Go to |
|--------|--------|
| Reference index | [reference/README.md](reference/README.md) |
| Tool inventory & budgets | [tool-contracts.md](tool-contracts.md) |
| Pack format / pins | [arc/](arc/) |
| Release notes | [release/](release/) |

## Contribute

| Intent | Go to |
|--------|--------|
| Agent policy | [../AGENTS.md](../AGENTS.md) |
| Contributing | [../CONTRIBUTING.md](../CONTRIBUTING.md) |
| Project history (origin only) | [HISTORY.md](HISTORY.md) |
| Archived / historical docs | [archive/](archive/) |

## Related

- Root product landing: [../README.md](../README.md)
- Issues: https://github.com/hilather/go-jenkins-mcp/issues
