# Release evidence template (REL-002)

Copy this file into the release folder (e.g. `dist/release-evidence/EVIDENCE.md`) and fill every field.  
Link artifacts by path or hash. **No secrets** in this document.

---

## Identity

| Field | Value |
|-------|--------|
| Product | go-jenkins-mcp / jenkins-mcp |
| Version (`jenkins-mcp version --json`) | |
| Commit | |
| Build time | |
| Go version | |
| GOOS/GOARCH | |
| Package artifacts | e.g. `dist/jenkins-mcp_*_linux_amd64.tar.gz` |
| SHA256SUMS | |
| BUILD_INFO | |
| Decision date (UTC) | |
| Release owner | |

---

## Decision

| | |
|--|--|
| **GO / NO-GO** | |
| Summary (2–5 lines) | |
| Exceptions approved (ticket IDs) | |
| Residual risks accepted | |

---

## Security gates

| Gate | Result (pass/fail/exception) | Evidence path / command | Notes |
|------|------------------------------|-------------------------|-------|
| Personal identity / keyring | | | |
| Secret handling / canaries | | | |
| Read-only default | | | |
| Origin / TLS | | | |
| Cache privacy / support-bundle | | | |
| SBOM | | | |
| Signing / checksums | | | |
| Independent code review | | | |

---

## Performance gates

| Gate | Result | Evidence | Notes |
|------|--------|----------|-------|
| Progressive log / no over-download | | | |
| Cache reuse | | | |
| Response budgets | | | |
| Perf baseline JSON (if claimed) | | | |
| L2 multi-frame access | | | |

---

## Reliability gates

| Gate | Result | Evidence | Notes |
|------|--------|----------|-------|
| `make test` | | | |
| Chaos suite | | | |
| `make test-race` (if run) | | | |
| `make fuzz-smoke` (if run) | | | |
| Doctor / cache | | | |

---

## Compatibility gates

| Gate | Result | Evidence | Notes |
|------|--------|----------|-------|
| Rocky install + pilot-check | | | |
| Ubuntu install + pilot-check | | | |
| Package build | | | |
| MCP smoke / SDK | | | |
| Auth cohort (API token / OAuth) | | | |
| Jenkins version matrix | | | |

### Modes piloted (REL-001/002 honesty)

Record deployment surfaces and gateway credential modes that have **evidence**
for this release decision. Offline-only rows must not be treated as live GO.
See [pilot checklist §0](../pilot/checklist.md) and [gates.md](gates.md).

| Mode / surface | Piloted? | Evidence path | Residual |
|----------------|----------|---------------|----------|
| Local Cursor stdio (personal API token) | | | |
| Local OIDC profile (IdP ≠ Jenkins) | | | live RS residual if unclaimed |
| Gateway Mode **A** `api_token_vault` | | | multi-user Obtain residual |
| Gateway Mode **B** `jwt_rs_bearer` | | | live Entra / jwt-auth-filter |
| Gateway Mode **C** AgentCore Live | | | live AgentCore / Entra Obtain |
| Offline only: `gateway qualify --offline` | | `gateway-qualify.json` / release-evidence | **not** live multi-user GO |
| Admin console (loopback) | | | localStorage pilot-only residual |

Modes **not** in release scope: _____________

---

## Usability gates

| Gate | Result | Evidence | Notes |
|------|--------|----------|-------|
| Docs walkthrough (user guide) | | | |
| profile + login + status | | | |
| diagnose real build | | | |
| doctor | | | |
| pilot-check JSON saved | | | |
| release-evidence JSON | | | |

---

## Ownership sign-off

| Role | Name | Date | Signature / ack |
|------|------|------|-----------------|
| Release owner | | | |
| On-call / support | | | |
| Vulnerability response | | | |
| Jenkins auth owner (if applicable) | | | |
| Security reviewer (if required) | | | |

---

## Attached machine JSON (secret-free)

- [ ] `version.json` from `jenkins-mcp version --json`
- [ ] `release-evidence.json` from `jenkins-mcp release-evidence --offline` (schema `jenkins-mcp.release-evidence.v2`; lite only — not production sign-off by itself)
- [ ] `pilot-check` JSON (Rocky)
- [ ] `pilot-check` JSON (Ubuntu)
- [ ] `BUILD_INFO` / `SHA256SUMS`
- [ ] Test / lint logs

---

## Deviations

| ID | Gate | Deviation | Exception approver | Ticket |
|----|------|-----------|--------------------|--------|
| | | | | |
