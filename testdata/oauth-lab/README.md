# Disposable OAuth / JWT auth lab (HOST-012…HOST-015)

Ephemeral **mock** OIDC IdP, JWT resource server, and AgentCore/token-exchange
peer for local / optional CI integration of server-side auth modes **B** and
**C**. **Not production.** Not real Entra, not real `jwt-auth-filter`, not real
AgentCore.

**Not part of** default `make test` / `make ci`.

## Auth modes map

| Mode | Lab | How |
|------|-----|-----|
| **A** — API token | Existing Jenkins compose | `make live-jenkins-*` → [`../jenkins-compose/`](../jenkins-compose/) |
| **B** — JWT RS bearer | **This lab** | `mock-oidc` mints JWT; `mock-rs` validates Bearer |
| **C** — AgentCore / OBO | **This lab** | `mock-token` returns HTTPTokenFetcher-shaped JSON |

## Services (loopback only)

| Service | Task | Host port (default) | Role |
|---------|------|---------------------|------|
| `keygen` | HOST-012 | — | One-shot disposable RSA into volume |
| `mock-oidc` | HOST-014 | **18081** | Discovery, JWKS, token mint |
| `mock-rs` | HOST-013 | **18082** | Bearer JWT RS (`/api/whoAmI`) |
| `mock-token` | HOST-015 | **18083** | Token exchange / consent / error fixtures |

Bind address defaults to **127.0.0.1** (`OAUTH_HOST_BIND`).

## Prerequisites

- Docker Engine + Compose v2 (Tier-1 Linux)
- `curl` for smoke
- Free ports 18081–18083 (override via env)

## Quick start (Makefile)

From the **repository root**:

```bash
export PATH="$HOME/.local/go/bin:$PATH"

# Build + start (waits for healthchecks)
make live-oauth-up

# Curl smoke only (compose already up)
make live-oauth-smoke

# Up + smoke + down -v (destroys lab_keys)
make live-oauth-test

# Tear down
make live-oauth-down
```

## Offline unit tests (default `make test`)

Pure-Go tests under `internal/authlab/` cover mint, claim validation (wrong
aud/iss/exp), RS fail-closed / no Basic fallthrough, and token peer scenarios
**without Docker**:

```bash
go test -count=1 ./internal/authlab/...
```

## Endpoints

### mock-oidc (HOST-014)

| Method | Path | Notes |
|--------|------|-------|
| GET | `/.well-known/openid-configuration` | issuer, jwks_uri, token_endpoint |
| GET | `/jwks` | Public RSA JWKS |
| POST/GET | `/token` | Mint JWT (`audience`, `subject`, `exp_offset`, `scenario=wrong_audience\|expired\|wrong_iss`) |
| GET | `/healthz` | Liveness |

Default claims: `iss=LAB_ISSUER`, `aud=jenkins-api`, short `exp`, `token_use=access_token`.

### mock-rs (HOST-013)

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/whoAmI` | Valid Bearer → `{ "ok": true, "sub": "..." }` |
| GET | `/mcp-rs/check` | Same as whoAmI |
| GET | `/healthz` | Liveness |

Fail closed:

- Missing / invalid / wrong aud / wrong iss / expired Bearer → **401**
- `Authorization: Basic …` alone → **401** (no fallthrough)
- Bearer scheme present with garbage token → **401** (no anonymous success)

**Residual:** this is a **mock RS proxy**, not the Jenkins `jwt-auth-filter`
plugin. Production pin remains [jwt-auth-filter qualification](../../docs/auth/jwt-auth-filter-qualification.md).

### mock-token (HOST-015)

| Method | Path | Notes |
|--------|------|-------|
| POST | `/oauth2/token` or `/token` | Success JWT + `jenkins_principal` |
| GET/POST | `/token?scenario=wrong_audience` | Token with Graph-like aud |
| GET/POST | `/token?scenario=consent` | **403** + `authorization_url` only (no tokens) |
| GET/POST | `/token?scenario=error` | **500** |
| GET | `/healthz` | Liveness |

JSON shape is compatible with `gateway.HTTPTokenFetcher` fields
(`access_token`, `token_type`, `expires_in`, `audience`, `jenkins_principal`,
consent metadata). **Residual:** production `HTTPTokenFetcher` requires
**https** token URLs; this lab publishes plain HTTP on loopback for curl smoke.
TLS termination / live gateway Obtain against the lab is a follow-up residual
(real AgentCore vault remains residual).

## Environment variables

| Variable | Default | Role |
|----------|---------|------|
| `LAB_ISSUER` | `http://127.0.0.1:18081` | Issuer in tokens + RS expected iss |
| `LAB_AUDIENCE` | `jenkins-api` | Default/expected audience |
| `LAB_KEYS_DIR` | `/lab-keys` | Shared volume path inside containers |
| `OAUTH_OIDC_PORT` | `18081` | Host port mock-oidc |
| `OAUTH_RS_PORT` | `18082` | Host port mock-rs |
| `OAUTH_TOKEN_PORT` | `18083` | Host port mock-token |
| `OAUTH_HOST_BIND` | `127.0.0.1` | Loopback publish |
| `OAUTH_LIVE_KEEP` | unset | If `1`, smoke leaves compose up |
| `LAB_JWKS_URL` | empty | Optional RS remote JWKS (else volume) |

## Security notes

- Keys are **lab-only**, generated at volume init by `keygen`, destroyed with
  `docker compose down -v`.
- Never commit production secrets, Entra client secrets, or real API tokens.
- Smoke script never prints access tokens.
- Do **not** use shared Jenkins service accounts; mode A remains per-user API
  tokens (`live-jenkins`).
- Jenkins is **not** an OAuth authorization server (ADR 0003). This lab does not
  implement Jenkins-as-AS.

## Manual curl examples

```bash
# Discovery
curl -fsS http://127.0.0.1:18081/.well-known/openid-configuration | jq .

# Mint (do not paste token into tickets/logs)
TOK=$(curl -fsS -X POST http://127.0.0.1:18081/token \
  -d 'grant_type=client_credentials&audience=jenkins-api&subject=alice' \
  | jq -r .access_token)

curl -fsS -H "Authorization: Bearer $TOK" http://127.0.0.1:18082/api/whoAmI

# Wrong audience → 401
BAD=$(curl -fsS 'http://127.0.0.1:18081/token?scenario=wrong_audience' | jq -r .access_token)
curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $BAD" \
  http://127.0.0.1:18082/api/whoAmI

# Consent fixture
curl -sS -D- 'http://127.0.0.1:18083/token?scenario=consent' -o /dev/null
```

## Code layout

| Path | Role |
|------|------|
| `internal/authlab/` | Mint/validate + HTTP servers (unit-tested offline) |
| `cmd/authlab/` | Multi-command binary: `keygen`, `oidc`, `rs`, `token` |
| `testdata/oauth-lab/` | Compose + Dockerfile + this README |
| `scripts/oauth-lab-smoke.sh` | Opt-in integration smoke |

## Related docs

- [server-team-hosted roadmap](../../docs/roadmap/server-team-hosted.md) — HOST-012…015
- [jwt-auth-filter qualification](../../docs/auth/jwt-auth-filter-qualification.md) — OAUTH-009 residual
- [jenkins-compose mode A](../jenkins-compose/README.md) — API token lab
- [gateway HTTPTokenFetcher](../../docs/gateway/README.md)
- Agent policy: [`AGENTS.md`](../../AGENTS.md) Docker scaffolds

## Residuals (honest)

| Residual | Status |
|----------|--------|
| Real Microsoft Entra tenant / Conditional Access | Not in lab |
| Real Jenkins `jwt-auth-filter` plugin version pin | Mock RS only |
| Real AgentCore Identity vault / 3LO browser | Mock peer only |
| `HTTPTokenFetcher` https pin against lab | HTTP loopback smoke; TLS residual |
| Mode A + B/C multi-compose single command | Use `live-jenkins-*` + `live-oauth-*` separately |
