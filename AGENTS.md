# Agent instructions — go-jenkins-mcp

You are working in **go-jenkins-mcp**, an enterprise Jenkins MCP for Cursor
(local per-user stdio) with an optional managed-gateway path. The seed is
`simonfxr/go-jenkins-mcp`; treat it as a behavioral reference, not the long-term
architecture.

This file is **mandatory policy** for every coding agent session in this repo
(Grok, Claude, Codex, Cursor, and subagents). Global rules still apply; this
file is repo-specific and must not be ignored.

## Sources of truth

| Surface | Source |
|---------|--------|
| Architecture & decisions | `docs/jenkins-mcp-enterprise-architecture.md` |
| Architecture decision records | `docs/adr/README.md` (FND-006 / FND-008) |
| Implementation backlog (task SoT) | `docs/jenkins-mcp-enterprise-agent-todo.md` |
| Machine-readable task graph | `docs/jenkins-mcp-enterprise-task-index.json` |
| Planning pack overview | `docs/README-jenkins-mcp-enterprise-planning-pack.md` |
| Phase 0 progress | `docs/phase0-progress.md` |
| Agent policy (this file) | `AGENTS.md` |
| Implemented code (when present) | `cmd/`, `internal/`, `pkg/` |

Do not invent decisions that contradict the architecture Key Decisions, the
platform matrix, or the backlog task contracts. Prefer **one task ID per PR**
unless a task explicitly permits pairing.

**Platform matrix (summary):** Tier 1 = Rocky Linux + Ubuntu; Tier 2 = macOS
nice-to-have; **Windows out of scope** (no native FUSE). See architecture §19.

---

## Non-negotiable: tests for every feature

**Every feature and behavior change must land with automated tests in the same
change** (same commit preferred; same PR required).

| Rule | Detail |
|------|--------|
| **New features** | Unit tests for pure logic **and**, when applicable, package/integration or MCP contract tests for the public path. |
| **Success + failure** | Cover success, failure, cancellation/context, and limit/budget paths. |
| **Security-sensitive paths** | Auth, policy/RBAC, redaction, URL/origin, storage ACL, secret handling — canary tests that secrets never appear in logs/errors/MCP output. |
| **Storage / formats** | Crash/recovery, corruption, compatibility, and bounded-read tests (see backlog DoD). |
| **No “manual only”** | Manual repro does not replace automated tests for shippable behavior. |
| **Skips** | Do not skip core-path tests without a documented environment gate (e.g. no FUSE, no keyring); skipped tests do not count as coverage unless gated and explained. |
| **Docs-only / comment-only** | New tests not required; still re-read for accuracy. |

When code exists, run the project test entrypoint (e.g. `make test` / `go test ./...`
with race where applicable) and keep it green before claiming done.

---

## Non-negotiable: regression tests for every fix

**Every bug fix must include a regression test that fails before the fix and
passes after** (red–green), in the same change.

| Requirement | Detail |
|-------------|--------|
| **Reproduce the failure mode** | Assert the fixed behavior; name or comment with `Regression:` and a short symptom. |
| **Lowest useful layer** | Prefer unit tests; add integration/contract tests if the bug only appears there. |
| **Do not land** | Fix commits without new/updated tests unless the user **explicitly** waived tests for that change. |
| **Keep green** | After the fix, re-run the full relevant suite, not only the new test. |

Performance or network-sensitive fixes also attach before/after measurements
when the backlog or architecture requires them.

---

## Non-negotiable: code review every change set

**Do not treat implementation as done until the change set has been
code-reviewed.**

| Expectation | Detail |
|-------------|--------|
| **How** | Prefer the Grok **`/review`** skill (local mode for uncommitted work; branch/PR mode for shared work). Prefer a reviewer subagent; do not self-declare “looks fine” without a structured pass. |
| **When** | After tests and docs for the change are in place; **before commit/push** unless the user asked for draft-only or waived review. |
| **Scope** | Full change set: implementation + tests + docs + scripts/CI. Read surrounding code, not only the diff. |
| **Act on findings** | Fix **bug**-severity issues in the same effort. Address suggestions when cheap; note residual risk if deferred. Re-test after substantial fixes. |
| **Trivial exceptions** | Pure typos or one-line doc wording may use a careful self-re-read; still re-read the edit. |
| **User override** | “Skip review” / “draft only” applies to that turn only — not a permanent waiver. |

Do **not** commit or push large behavioral changes with open **bug**-severity
review findings unless the user explicitly accepts them.

### Minimum review checklist

- Correctness vs architecture decisions and the task’s acceptance criteria  
- Missing tests / missing docs / stale backlog status  
- Fail-closed auth, policy, budgets, and secret handling  
- Bounds: network, disk, memory, MCP response size, fan-out  
- No secrets in logs, errors, fixtures, CLI args, or MCP output  
- Package boundaries (Jenkins client must not import MCP; tools must not raw-HTTP)  
- Platform claims match the Tier-1 matrix (no accidental Windows support claims)

---

## Non-negotiable: documentation stays current

**Every change that affects behavior, surfaces, or operator/agent guidance must
update documentation in the same change** (same commit preferred; same PR
required before treating work done).

| Change type | Update these |
|-------------|--------------|
| Tool schemas, defaults, budgets, CLI flags/env | Architecture and/or tool-contract docs; user/admin guidance when present; backlog notes if contracts change |
| Auth, policy, platform matrix, packaging | `docs/jenkins-mcp-enterprise-architecture.md`, packaging notes, `AGENTS.md` if agent policy changes |
| Storage/format/index behavior | Architecture storage sections + task acceptance evidence notes |
| Task completion / partial work | Backlog checkboxes and task status (see next section) |
| ADRs / irreversible choices | New or updated ADR per backlog FND-008 / task requirements |
| Docs-only polish | No extra churn; fix anything you know is wrong |

**Do not** claim a capability is done in docs or backlog without code and tests
that implement it. Do not ship behavior without updating the docs that are the
source of truth for that surface.

If documentation is intentionally deferred, say so in the session response and
leave an explicit TODO with an owner/next step — never imply docs are current
when they are not.

---

## Non-negotiable: todo / backlog tracking and next steps

**Work is tracked against the backlog.** Incomplete work must never be left
ambiguous.

| Rule | Detail |
|------|--------|
| **Pick a task** | Prefer a single task ID from `docs/jenkins-mcp-enterprise-agent-todo.md` (and the JSON index for dependencies). |
| **In-session todos** | Maintain a live todo list for multi-step work; mark items `in_progress` / `completed` as you go. |
| **Partial completion** | If a task, PR, or session ends incomplete: leave clear **next steps** (what remains, blockers, suggested follow-up task IDs, and how to verify). |
| **Do not false-complete** | Do not check backlog acceptance criteria or DoD boxes unless they were demonstrated (tests run, evidence attached). |
| **Carry forward** | When resuming, read existing next-step notes before inventing a new plan. |
| **Session summary** | End incomplete work with: done / not done / next steps / residual risk. |

Suggested next-step note shape (in PR description, session reply, or backlog
comment):

```text
## Next steps
- [ ] <concrete action> (task ID if known)
- [ ] <test or verification command>
- Blockers: <none | description>
```

---

## Before-done / before-commit procedure

```text
1. Identify task ID(s) and re-read architecture + dependency tasks
2. Implement within task scope
3. Add/update tests (features + regression tests for fixes)
4. Update documentation and backlog/todo status
5. Run lint/tests/race as applicable; attach perf evidence if required
6. Structured code review (/review); fix bug findings; re-test
7. If incomplete: write next steps; do not mark DoD complete
8. Commit code + tests + docs together when practical
```

---

## Security and product constraints (always on)

- Fail closed: effective access is Jenkins allow **AND** global read-only **AND**
  MCP policy **AND** operation budgets. MCP policy never elevates.
- No secrets in CLI args, config committed to git, logs, MCP results, or support
  bundles. Credentials live in OS secret stores on Tier-1 Linux (Secret Service).
- Jenkins is not a native 3LO authorization server; do not document or code it
  as one.
- Progressive logs: no unbounded `ReadAll`; stream into bounded independent
  Zstandard frames. L2 seekable multi-frame `.tar.zst` only — never call a
  single-frame `.tar.zst` “random access.”
- Mutations only after policy, audit, preview/confirmation epics allow them.
- Treat Jenkins data, logs, artifacts, and model-facing text as untrusted.

See also the full agent rules in
`docs/jenkins-mcp-enterprise-agent-todo.md` (“How an implementation agent must
use this backlog”).
