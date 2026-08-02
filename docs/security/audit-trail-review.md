# Audit trail review vs industry standards

**Audience:** security, compliance, platform, implementers  
**Related:** [observability.md](../observability.md) (AUD-001), [privacy-data-retention.md](privacy-data-retention.md), [threat-model.md](threat-model.md), [adapters/ext-logs.md](../adapters/ext-logs.md)  
**Code:** `internal/audit`  
**Agent policy:** Root [AGENTS.md](../../AGENTS.md) — *Non-negotiable: audit trails when security-relevant*  
**Status:** Review snapshot 2026-08-01 — local privacy-preserving audit is **Done\*** for pilot; enterprise SIEM ship and several AU-* strengths remain residual.

---

## 1. What we mean by “audit trail”

| Plane | Product surface | Purpose |
|-------|-----------------|---------|
| **MCP security audit (AUD-001)** | Local JSONL + admin list | Attribution: who (principal / external subject hash), what (tool/action), decision, reason — **no content** |
| **Operational logs (OBS-001)** | Redacted stderr JSON | Support / debug; not the compliance audit plane |
| **External log *query* (INT-003)** | Optional `ext-logs` adapter | Read **Jenkins-linked** logs from an approved backend for triage — **not** shipping our audit file out |
| **Fleet telemetry (MGR-002)** | Opt-in metadata queue | Separate from audit; disabled by default |

**Critical distinction:** *Querying* Splunk/ELK for build logs ≠ *shipping* MCP audit events to Splunk/syslog. The latter is still residual (see §4).

---

## 2. Industry control mapping (summary)

Mapped to common control families (NIST SP 800-53 AU-*, CIS Controls logging, ISO 27001 logging themes, OWASP logging cheatsheet, SOC 2 logging expectations). This is an **engineering gap analysis**, not a formal certification claim.

| Control theme | Industry expectation | Current posture | Gap |
|---------------|----------------------|-----------------|-----|
| **AU-2 / event types** | Define auditable events (authn, authz, admin, security) | Stable types: login_*, serve_start, tool_deny, tool_error, auth_fail; optional tool_success; mutations preview/confirm/deny | Expand coverage for admin BFF writes, policy apply, vault CRUD, consent purge, config changes (see **AUD-T-001**) |
| **AU-3 / content** | Who, what, when, outcome, source; no secrets | Schema v1: principalId, externalSubject, subjectKeyHash, tool, decision, reasonCode, requestId, targetHash, time | Source IP / client identity residual on gateway multi-user; session id hash residual (**AUD-T-002**) |
| **AU-3 / privacy** | No passwords, tokens, PII dumps | Sanitize + canary tests; never log bodies/parameters | Keep canaries; add admin-route canary matrix (**AUD-T-003**) |
| **AU-4 / capacity** | Bound storage | Size rotate 8 MiB × 3 siblings | Time-based retention + disk full fail-closed policy residual (**AUD-T-004**) |
| **AU-5 / response** | Alert on audit process failure | Best-effort emit; never authorize on failure | Metrics/alert when emit fails repeatedly (**AUD-T-005**) |
| **AU-6 / review** | Support review/investigation | Admin SPA audit list + export loaded JSON; CLI file | Server-side search by reason/time range residual; SIEM residual |
| **AU-7 / reduction** | Query/report by attributes | BFF filters: type, limit, before, external_subject | Filter by principalId / reasonCode / requestId (**AUD-T-006**) |
| **AU-8 / time** | Trusted timestamps | UTC `time` on emit | NTP/clock skew residual (operator OS) |
| **AU-9 / protection** | Protect audit from unauthorized access/mod | File **0600**, dir **0700**, profile data tree | Integrity (hash chain / WORM / append-only FS) residual (**AUD-T-007**); multi-user file ACLs residual |
| **AU-9 / non-repudiation lite** | Detect tampering | No chain of custody / signatures | Hash-chain or external WORM residual (**AUD-T-007**) |
| **AU-11 / retention** | Org retention policy | Size rotation only | Policy-controlled days/legal hold residual (**AUD-T-004**) |
| **AU-12 / generation** | Generate for defined events | Wired on serve, policy, mutations, identity re-verify | See coverage matrix **AUD-T-001** |
| **Central collection** | Forward to SIEM (syslog/HEC/etc.) | **Not implemented** for audit plane | **AUD-T-010…013** (syslog / Splunk HEC / webhook) |
| **Separation** | Audit admin separate from operators | Admin BFF RBAC for read | Role-gated audit download residual (**AUD-T-008**) |

### What already aligns well

- **Privacy-preserving by design** (no content, tokens, Authorization headers) — matches OWASP “don’t log secrets” and data-minimization.
- **Stable schema + reason codes** — SIEM-friendly low cardinality.
- **Fail-closed security path** — audit emit errors do not authorize mutations (AU-5 spirit).
- **Local access control** — restrictive file modes; admin console viewer/operator gates.
- **Multi-user correlation foundation** — `externalSubject` + opaque `subjectKeyHash` without raw keys.
- **Best-effort Multi sink** — fan-out interface exists (`audit.Multi`) ready for remote sinks without changing emitters.

---

## 3. Current architecture (as implemented)

```text
  MCP serve / admin BFF / login
            │
            ▼
     audit.Emit(ctx, sink, Event)
            │
            ├─► File sink  →  $profileDataDir/audit/audit.jsonl  (+ rotates)
            ├─► Memory     →  tests
            └─► Multi[]    →  fan-out (tests; production remote not wired)
                    │
                    └── (residual) Syslog / Splunk HEC / HTTPS webhook
```

| Component | Path |
|-----------|------|
| Schema / types | `internal/audit/event.go` |
| Sanitize | `internal/audit/sanitize.go` |
| File + rotate | `internal/audit/file.go` |
| Sink interface + Multi | `internal/audit/sink.go`, `file.go` |
| Admin list API | `GET /admin/v1/profiles/{id}/audit` |
| SPA | `web/admin` Audit page |

---

## 4. Remote audit logging (Splunk / syslog) — status

### Short answer

| Capability | Status |
|------------|--------|
| **Ship MCP security audit events to syslog / Splunk / SIEM** | **Residual — not implemented** |
| **Query external log platforms for Jenkins build logs** (`ext-logs` adapter) | MVP framework only; **real Splunk/ELK SaaS clients residual** (`docs/adapters/ext-logs.md`) |
| **OTLP metrics/traces export** | Separate residual (`otel-export` adapter) |

There is **no** production `audit.Sink` that dials UDP/TCP syslog, Splunk HEC, or a remote SIEM today. Operators who need SIEM today must:

1. Collect local `audit.jsonl` via host agent (Fluent Bit, Splunk UF, rsyslog `imfile`, Vector, etc.), **or**
2. Wait for in-product sinks (**AUD-T-010…013**).

Host-agent collection is the **recommended near-term path** and preserves fail-closed local emit.

### Multi sink (future wire-up)

`audit.Multi` already fans out Emit/Close. A future design:

```text
OpenProfileSink(dir)  +  optional SyslogSink / HECSink  →  audit.Multi{file, remote}
```

Requirements for any remote sink (non-negotiable):

- Same **sanitize/Normalize** as local (never secrets).
- **Best-effort**: remote down must not block tool deny path; queue+drop with metric (**AUD-T-005**).
- **TLS** for network sinks; no credentials in env files — keyring residual.
- **No content** fields; same Event schema.
- Document residual when only local file is configured.

---

## 5. Task backlog (audit trail)

Work IDs are **AUD-T-*** (audit trail) to avoid colliding with historical **AUD-001** Done\*.

### P0 — coverage & honesty

| ID | Task | Size | Acceptance |
|----|------|------|------------|
| **AUD-T-001** | **Coverage matrix**: inventory every security-relevant action (admin policy apply, vault put/delete/revoke, consent purge/clear_all, subject-invalidate, cache destructive, serve start/stop, identity re-verify, mutations) and emit or document residual | M | Table in this doc or `observability.md`; missing emits either wired or residual-id |
| **AUD-T-003** | **Secret canary suite** for new emit sites + admin audit JSON export | S | Canary never appears in file or admin API |
| **AUD-T-009** | **Doctor / residual-status honesty**: surface “remote_audit_sink=false” (or equivalent) until SIEM sinks land | S | residual-smoke / self-check item; never claim SIEM GO |

### P1 — retention, protection, review

| ID | Task | Size | Acceptance |
|----|------|------|------------|
| **AUD-T-004** | Time-based retention knobs + disk-full policy (beyond size rotate) | M | Config days/max; documented default; tests |
| **AUD-T-005** | Emit-failure metric/counter + optional stderr warn (no flood) | S | `mcp_audit_emit_fail` or equivalent; unit test |
| **AUD-T-006** | Admin BFF filters: principalId, reasonCode, requestId (exact, secret-free) | M | api-v1 + SPA + tests |
| **AUD-T-007** | Integrity lite: hash-chained events or external “append-only” ops note | M | Document; optional `prevHash` field schema v2 or residual ops guide |
| **AUD-T-008** | Role gate for bulk audit export / download (policy_admin vs viewer) | S | RBAC test |

### P1 — remote ship (SIEM)

| ID | Task | Size | Acceptance |
|----|------|------|------------|
| **AUD-T-010** | **Syslog sink** (RFC 5424 over TLS or unix socket) implementing `audit.Sink`; opt-in env/flag | L | Unit tests with fake conn; Multi with File; residual honesty when off |
| **AUD-T-011** | **Splunk HEC sink** (HTTPS, token from keyring residual) | L | Fail-closed TLS; body is Event JSON; canary tests |
| **AUD-T-012** | **Generic HTTPS webhook sink** (pinned origin, no redirects) for other SIEMs | M | Same as HEC contract without Splunk-specific fields |
| **AUD-T-013** | Operator runbook: host-agent ship of `audit.jsonl` vs in-process sinks; when to use which | S | Doc under observability or ops |

### P2 — correlation & gateway

| ID | Task | Size | Acceptance |
|----|------|------|------------|
| **AUD-T-002** | Optional client/source attributes: gateway path prefix, request hash, session fingerprint hash (never raw token) | M | Schema v2 or additive fields; SPA columns residual |
| **AUD-T-014** | Multi-pod audit aggregation | — | **Cancelled with HOST-008** — multi-fleet = per-member audit JSONL; optional fleet SIEM via AUD-T-010…013 per host |

---

## 6. Suggested implementation order

1. **AUD-T-001** coverage matrix (know the gaps).  
2. **AUD-T-009** residual honesty for remote sink.  
3. **AUD-T-005** emit-fail visibility.  
4. **AUD-T-006** better investigation filters.  
5. **AUD-T-010** syslog (most portable SIEM feed) *or* host-agent runbook **AUD-T-013** first if product prefers zero network from MCP.  
6. **AUD-T-011/012** when a site commits to HEC/webhook.  
7. **AUD-T-004/007** when compliance demands retention/integrity beyond pilot.

---

## 7. Explicit non-goals (for this backlog)

- Logging full Jenkins console text into the audit plane (use log tools + optional ext-logs).  
- Treating fleet telemetry as audit (different product surface).  
- Claiming SOC 2 / ISO certification from code alone.  
- Multi-pod HA audit store (HOST-008 **cancelled** — multi-fleet per-member audit only).

---

## 8. Quick answers

| Question | Answer |
|----------|--------|
| Are we “audit ready” for a local pilot? | **Yes** for privacy-preserving local AUD-001 with admin review. |
| Enterprise SIEM-ready out of the box? | **No** — local file + host agent, or implement **AUD-T-010…012**. |
| Do we have Splunk/syslog **remote audit** support? | **Not in-process.** Multi sink interface ready; implementations residual. |
| Is ext-logs the SIEM ship path? | **No** — ext-logs is **inbound query** of external logs for triage, not audit export. |

---

## 9. Document history

| Date | Note |
|------|------|
| 2026-08-01 | Initial industry mapping + AUD-T backlog; SIEM residual clarified |
