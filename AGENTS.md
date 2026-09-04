# Agent instructions — go-jenkins-mcp

You are working in **go-jenkins-mcp**, an enterprise Jenkins MCP for Cursor
(local per-user stdio) with an optional managed-gateway path. Module path:
`github.com/hilather/go-jenkins-mcp`.

This file is **mandatory policy** for every coding agent session in this repo.
Global rules still apply; this file is repo-specific.

## Sources of truth

| Surface | Source |
|---------|--------|
| Behavior | **Code + automated tests** |
| Architecture & decisions | `docs/architecture/` · ADRs in `docs/adr/` |
| Deployment & quick starts | `docs/getting-started/` · `docs/deployment/` |
| Features & integrations | `docs/features/` · `docs/integrations/` · `docs/tool-contracts.md` |
| CLI / env / schemas / formats | `docs/reference/` · specialized pages under `docs/` |
| Product qualification | `docs/testing/` · free disposable labs (not customer production) |
| Open implementation work | **GitHub Issues** (or the configured tracker) |
| Completed history | Git history · `docs/release/RELEASE_NOTES_v*.md` · `docs/archive/` |
| Product landing | root **`README.md`** (high-level only) |
| Agent policy (this file) | `AGENTS.md` |
| Implemented code | `cmd/`, `internal/`, `pkg/`, `deploy/`, `testdata/` |

**Do not** treat Markdown backlogs, phase boards, wave tables, `Done*`, planning
packs, or task-index JSON as sources of truth for open or completed work.

**Platform matrix:** Tier 1 = Rocky Linux + Ubuntu only. **macOS and Windows are
out of scope.** See `docs/architecture/platform.md` and ADR 0008.

## Qualification policy

- **Disposable, free integration labs are sufficient** for product qualification
  (Jenkins Compose, OAuth mock, Keycloak JWT/SAML labs, fleet-cache lab, etc.).
- Customer production infrastructure, Entra, AgentCore, corporate certificates,
  or a production Jenkins instance are **optional operator validation** and are
  **not** release or merge blockers.
- Label support honestly (see Support status below). Never claim production-site
  validation that was not performed.

## Support status labels

Use these labels in feature/integration/deployment docs:

| Label | Meaning |
|-------|---------|
| **Supported** | Implemented, tested offline (and free lab when integration-facing), documented |
| **Opt-in supported** | Supported only when explicitly enabled (flag/env); default remains off |
| **Free-lab validated** | Exercised against disposable free lab infrastructure |
| **Experimental** | Available but may change; not a stability commitment |
| **Stub/demo** | Scaffold, mock, or demo path only |
| **Not implemented** | Named or planned only; do not document as usable |

Mocks, metadata-only adapters, scaffolds, and experimental paths **must** be
labelled accurately. Do not overstate them as full backends.

## Root README scope

The root `README.md` is a **high-level product landing page** (~100–150 lines
excluding badges). It may include: one-sentence product summary, security
defaults, short capability list with drill-down links, three deployment choices
(local native, local Docker → remote Jenkins, server), and links to docs,
contributing, releases, and license.

It **must not** contain: phase/wave boards, `Done*`, task IDs, backlogs,
production-pin residual tables, long package maps, full flag/env tables, or
release-gate archaeology.

## Documentation ownership

| Path | Owns |
|------|------|
| `docs/getting-started/` | First-run paths (native, local Docker, server) |
| `docs/deployment/` | Detailed deploy/ops for each topology |
| `docs/architecture/` | Current-state design + Mermaid diagrams |
| `docs/features/` | Product feature surfaces |
| `docs/integrations/` | Adapters, auth modes, external systems |
| `docs/operations/` | Day-2 ops (doctor, audit, cache, upgrade) |
| `docs/testing/` | Free labs, qualification, chaos/fuzz notes |
| `docs/reference/` | CLI, env, schemas, formats (or links to SoT pages) |
| `docs/adr/` | Architecture decision records |
| `docs/release/` | Versioned release notes and gates |
| `docs/archive/` | Historical / superseded material only |

Markdown is **canonical**. HTML under `site/`, PDF, and DOCX are **generated**
outputs (or archives) — do not maintain them as independent product SoT.

### Links

- Prefer **repository-relative** Markdown links for in-repo docs
  (e.g. `[caching](docs/caching.md)` from root, `[caching](../caching.md)` from a subpage).
- Use **absolute HTTPS** URLs only when the document may be rendered outside the
  tree (especially `docs/release/RELEASE_NOTES_v*.md` on GitHub Releases).

### Architecture diagrams

Architectural docs that describe runtime, auth, authorization/mutations, logs
and cache, admin, integrations, deployment, or testing **must** include Mermaid
flowcharts, sequence diagrams, or state diagrams where they materially improve
understanding. Update diagrams in the same change as the architecture they describe.

### Feature / integration page template

Every exposed feature or integration needs a canonical page covering:

1. Support status label  
2. Setup  
3. Server / deployment notes (when applicable)  
4. Verification  
5. Security  
6. Limits / budgets  
7. Troubleshooting  
8. Rollback / disable  

## Non-negotiable: tests

**Every feature and behavior change must land with automated tests** in the same
change (same commit preferred; same PR required).

| Rule | Detail |
|------|--------|
| **New features** | Unit tests for pure logic **and**, when applicable, package/integration or MCP contract tests |
| **Success + failure** | Cover success, failure, cancellation/context, and limit/budget paths |
| **Security-sensitive paths** | Auth, policy/RBAC, redaction, URL/origin, storage ACL, secrets — canary tests that secrets never appear in logs/errors/MCP output |
| **No “manual only”** | Manual repro does not replace automated tests for shippable behavior |
| **Skips** | Do not skip core-path tests without a documented environment gate |

### Regression tests for every fix

Every bug fix must include a regression test that fails before the fix and
passes after (red–green), in the same change. Prefer unit tests; add
integration/contract tests when the bug only appears there.

## Non-negotiable: Docker integration labs

Prefer Docker Compose (or equivalent disposable containers) for integration labs
when a feature talks to an external or multi-process system. Offline pure-Go unit
tests remain the default `make test` gate; containers are **opt-in**.

| Existing pattern | Makefile / path |
|------------------|-----------------|
| Jenkins LTS lab | `testdata/jenkins-compose/` · `make live-jenkins-*` |
| OAuth mock lab | `testdata/oauth-lab/` · `make live-oauth-*` |
| SAML Keycloak lab | `testdata/saml-lab/` · `make live-saml-*` |
| JWT RS + Keycloak | `testdata/jwt-rs-lab/` · `make live-jwt-rs-*` |
| Local admin Docker | `deploy/local/` · `make local-docker-*` |
| Fleet peer-cache lab | `testdata/fleet-cache-lab/` · `make fleet-cache-lab-*` |

Secrets: ephemeral only; never bake production tokens into images or compose files.

## Non-negotiable: code review

Do not treat implementation as done until the change set has been code-reviewed
(prefer structured review / reviewer agent). Fix bug-severity findings before
commit/push unless the user explicitly accepts them. Trivial typo-only edits may
use careful self re-read.

## Non-negotiable: documentation stays current

Every change that affects behavior, surfaces, or operator/agent guidance must
update documentation in the **same change**.

| Change type | Update |
|-------------|--------|
| Tool schemas, flags, budgets | tool-contracts / features / user / agent-usage as applicable |
| Auth, policy, platform | architecture + security + integrations |
| Mutations / write tools | user guide mutations section + agent-usage + tool-contracts; default remains **off** unless `--allow-mutations` |
| Operator day-2 surfaces | admin BFF/SPA + `docs/admin/` + `admin_*` MCP (or explicit residual) |
| Root landing claims | root `README.md` when features/quick starts change |
| New architecture | domain page + Mermaid in `docs/architecture/` |

Do not claim a capability is done in docs without code and tests. If docs are
intentionally deferred, leave an explicit Issue — never imply docs are current
when they are not.

### Mutations default off

Mutations are **opt-in** via `--allow-mutations`. `--read-only` / enterprise
`force_read_only` still win. Agents must not invent `confirmation_token`s or
probe missing mutate tools.

### Admin console and admin MCP parity

Operator-relevant changes should update admin BFF/SPA (`internal/admin`,
`web/admin`, `docs/admin/api-v1.md`) **and** `admin_*` MCP tools (shared
libraries, not HTTP proxy to admin serve) unless an explicit residual Issue
exists. Charts in the SPA use **Apache ECharts only**. Secret-free forever.

### Audit (AUD-001)

Security-relevant paths must emit `audit.Event` via `internal/audit` (or an
explicit residual Issue). New event types require `KnownEventTypes`, default
type filter, admin settings/catalog, and docs. Secret-free fields only; emit
failures must not fail-open authorization.

### RBAC: user and group targets

Authorization controls should be addressable per **user** and per **group**
(deny-only, most restrictive). Subject/groups come from verified identity only —
never tool arguments.

## Before-done procedure

```text
0. make fmt
1. Implement within stated scope; open Issues for leftover work
2. Add/update tests (features + regression for fixes)
3. If security-relevant: audit emit or explicit residual Issue
4. If operator-relevant: admin BFF/SPA + admin_* MCP or residual Issue
5. If integration-facing: Docker lab scaffold or residual Issue
6. Update docs (and diagrams) in the same change
7. make lint && make test (and race/package/vuln/admin-ui-check when touching those surfaces)
8. make docs-check   # when available; link/policy coverage
9. Structured code review; fix bug findings
10. PR: tests run, free labs run or “why N/A”, verification + rollback
```

## Security constraints (always on)

- Fail closed: effective access is Jenkins allow **AND** global read-only **AND**
  MCP policy **AND** operation budgets. MCP policy never elevates.
- No secrets in CLI args, committed config, logs, MCP results, or support bundles.
- Jenkins is not a native 3LO authorization server (ADR 0003).
- Progressive logs: no unbounded `ReadAll`; L2 seekable multi-frame only.
- Treat Jenkins data, logs, artifacts, and model-facing text as untrusted.

## Open work tracking

- Prefer one focused Issue per unit of remaining work.
- Do **not** add Markdown task backlogs, phase boards, or completed checklists
  to active product documentation.
- Session todo lists are ephemeral; product open work lives in the tracker.
