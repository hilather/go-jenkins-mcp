# Operator security guide — go-jenkins-mcp

**Audience:** security reviewers, platform owners, pilot operators.  
**Threat model (assets, actors, trust boundaries):** [`threat-model.md`](threat-model.md)  
**Auth architecture:** [`../auth-architecture.md`](../auth-architecture.md)  
**ADRs:** especially [0003 Jenkins is not a 3LO AS](../adr/0003-jenkins-not-oauth-authorization-server.md), [0004 RO + deny-only RBAC](../adr/0004-global-read-only-and-deny-only-rbac.md), [0009 Secret Service](../adr/0009-personal-api-token-secret-service.md)

---

## 1. Personal credentials only

| Rule | Detail |
|------|--------|
| Identity | Each interactive user uses **their own** Jenkins principal |
| Token storage | Linux **Secret Service** via `jenkins-mcp login --profile` |
| Profile JSON | Non-secret only (URL, username after login, principal id, TLS **paths**) |
| Shared service accounts | **Prohibited** for interactive MCP use |

### Login flow (safe)

1. `profile add` with Jenkins origin (no secret).
2. `login --profile` prompts on the TTY (or test-only env — never for production secret logging).
3. Token is verified (`whoAmI` / identity) **before** keyring write (fail closed).
4. Status/doctor print identity fields only.

### Never put secrets in

- CLI argv (`-auth` / `JENKINS_MCP_AUTH` are removed — fail closed)
- Cursor MCP `args` / `env` / committed config
- Git, tickets, chat logs, screenshots of terminals with tokens
- Support bundles (explicitly excluded — see below)
- MCP tool results and audit payloads

---

## 2. No secrets in CLI

| Surface | Policy |
|---------|--------|
| `jenkins-mcp status` | `has_credential` boolean; no token value |
| `profile show` | Paths for certs/keys only — never key material |
| Errors | Model-safe messages via `apperr`; canary tests |
| `version --json` / `update-check` / `release-evidence` | Build and health metadata only |
| Legacy `-auth` / `JENKINS_MCP_AUTH` | Warning + bootstrap-only; not for pilot configs |

Test-only non-interactive login env (`JENKINS_MCP_LOGIN_USER` / `JENKINS_MCP_LOGIN_TOKEN`) must never appear in CI logs or production runbooks as the preferred path.

---

## 3. Read-only default and policy intersection

Effective access is fail-closed:

```text
Jenkins allow  AND  global read-only  AND  MCP deny-only RBAC  AND  budgets
```

MCP policy **never elevates** Jenkins permissions. Enterprise overlay can force RO, deny tools, and **lower** result size — nothing more.

Cursor documentation must show:

- `--read-only`
- `JENKINS_MCP_READ_ONLY=true`

and must **not** advertise a generic inverse that bypasses stronger policy. `--allow-mutations` is test/pilot only and loses to any RO source.

Mutations (when deliberately enabled) require **preview + confirmation_token** (single use). Agents must not fabricate tokens.

---

## 4. Jenkins is not a native OAuth 3LO authorization server

Stock Jenkins is a **resource server** for personal API tokens / approved bearer routes — **not** an OAuth authorization server for browser 3LO.

| Path | Status |
|------|--------|
| Personal API token + Secret Service | Supported pilot default |
| External IdP (e.g. Entra) as AS + Jenkins as RS | Architecture path for OAuth cohorts |
| “Jenkins native 3LO” | **Out of scope** unless a gated custom plugin epic is approved |
| AgentCore / managed gateway 3LO/OBO | Optional deployment; separate threat model |

See ADR 0003 and auth-architecture for issuer/audience, JWT route coverage, fallback-auth risk, and conditional plugin scope.

---

## 5. Enterprise redact patterns (SEC-002)

Optional **additional** detectors on top of built-in layered redaction. Prefer
a dedicated JSON file + env (not policy overlay) so invalid config fails closed
at serve start without mixed schema concerns.

| Control | Behavior |
|---------|----------|
| Env | `JENKINS_MCP_REDACT_PATTERNS_FILE` → path to JSON array |
| Unset / empty | No enterprise patterns (built-ins + bare-token only) |
| Valid file | Compile at serve start; install via `SetEnterprisePatterns` |
| Invalid JSON / regexp / oversized | **Fail closed** — serve does not start |
| Reports | Category **counts only** — never match values or secrets |

### File format

```json
[
  {"name": "corp_id", "expr": "\\bCORP-[0-9]{6}\\b"},
  {"name": "badge", "expr": "(?i)(badge_token\\s*=\\s*)(\\S+)"}
]
```

Prefer two capture groups (prefix + secret) so labels stay visible while the
secret is replaced with `[REDACTED]`. `name` is the redaction report category
(value-free). Bounds: 1 MiB file, max 256 patterns.

### Operator validate (no serve)

```bash
jenkins-mcp redact validate-patterns --file /etc/jenkins-mcp/redact-patterns.json
jenkins-mcp redact validate-patterns --file ./patterns.json --json
```

### Serve

```bash
export JENKINS_MCP_REDACT_PATTERNS_FILE=/etc/jenkins-mcp/redact-patterns.json
jenkins-mcp serve --profile corp --read-only
# stderr (count only): enterprise redact patterns loaded: count=2
```

**Residual:** patterns never log matches or secret material; expression text is
not written to structured logs on success. Redaction is best-effort layered
defense — treat model-facing logs as untrusted. Split `Write` chunks and
novel secret formats remain residual false-negatives (see KD-004 / observability).

---

## 6. Support bundle exclusions

`jenkins-mcp support-bundle` / `doctor --bundle` produce a privacy-scrubbed zip.

**Never included (MVP):**

- tokens / API keys  
- keyring material  
- full build logs  
- artifact bodies  
- cookies  
- Authorization headers  
- private keys  
- raw HTTP transcripts  

**May include:** version/build, effective profile **without secrets**, doctor report, cache status, capability summary, metrics snapshot, error signature hashes (never full logs), GOOS/GOARCH, offline security self-check, release-evidence lite (version/runtime only), offline RS qualification residual summary.

Always run `--preview` first when learning the surface. Zip members are listed before write; new Wave 23 offline sections default on and remain secret-free by construction.

---

## 7. Encryption residual

| Layer | MVP posture |
|-------|-------------|
| TLS to Jenkins | Verify on by default; custom CA / mTLS via profile paths |
| At-rest L1/L2 cache | Local filesystem permissions + per-user XDG; optional L1 AEAD via `cache key init` (ARC-009) — see [cache-encryption.md](cache-encryption.md) and [caching.md](../caching.md) |
| Update manifests | HTTPS fetch for metadata only; **in-process signed update install residual** (use org package signing) |
| Policy overlays | Deny-only local file today; signed policy bundles residual |

Document residual honestly: local cache may contain sensitive build text; treat disk ACLs and user session hygiene as required controls.

---

## 8. Network and origin

- HTTPS + certificate verification  
- Origin allow / pin behavior in the Jenkins client (NET-00x)  
- Bounded response bodies; progressive logs into independent Zstd frames  
- Diagnostic TLS skip is dual-gated and never a profile default  

---

## 9. Incident response (operator checklist)

1. `logout --profile` for affected users; rotate Jenkins API tokens.  
2. Collect `support-bundle --preview` then bundle if needed (confirm no secret categories).  
3. Preserve doctor/pilot-check JSON as evidence (secret-free).  
4. Revoke Cursor MCP config that used retired `-auth` / `JENKINS_MCP_AUTH` if found.  
5. Escalate per org vulnerability response; see `SECURITY.md`.  

---

## 10. Threat-model pointer

For assets, actors, trust boundaries, and data classes, start at:

**[`docs/security/threat-model.md`](threat-model.md)**

This operator guide is the runbook layer on top of that model.

## Related

- [Signed policy bundles](policy-bundles.md) (MGR-001)
- [Privacy and data retention](privacy-data-retention.md) (QA-006)
- [OAuth capability matrix](../auth/oauth-capability-matrix.md) (OAUTH-008)
- Admin packaging / env table: [`../admin/README.md`](../admin/README.md) §3b
