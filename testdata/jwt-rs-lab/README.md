# JWT RS lab — Keycloak OIDC + real `jwt-auth-filter` (OAUTH-009 free lab)

Disposable **Keycloak** OIDC IdP + **Jenkins LTS** with the real
[`jwt-auth-filter`](https://plugins.jenkins.io/jwt-auth-filter/) plugin.

**Not production.** Not Microsoft Entra. Not multi-pod HA.

**Not part of** default `make test` / `make ci`.

Existing lightweight mock RS (no real plugin) remains:

```bash
make live-oauth-test   # testdata/oauth-lab mock-oidc + mock-rs
```

## What this lab provides

| Piece | Detail |
|-------|--------|
| **IdP** | Keycloak `start-dev` + realm `jwt-rs-lab` on `127.0.0.1:18091` |
| **Jenkins** | LTS + `jwt-auth-filter` + JCasC on `127.0.0.1:18092` |
| **Audience** | `jenkins-api` (access-token audience mapper) |
| **JWKS** | Jenkins container fetches `http://keycloak:8080/realms/jwt-rs-lab/protocol/openid-connect/certs` |
| **Lab users** | `alice` / `alice-lab` · `bob` / `bob-lab` |
| **Wrong-aud client** | `wrong-audience-client` (audience `not-jenkins-api`) for fail-closed smoke |

## Quick start (repo root)

```bash
export PATH="$HOME/.local/go/bin:$PATH"

make live-jwt-rs-up      # build/start Keycloak + Jenkins (plugin download; slow first time)
make live-jwt-rs-smoke   # assume up; mint token; Bearer whoAmI + invalid/wrong-aud checks
make live-jwt-rs-test    # up + smoke + down -v
make live-jwt-rs-down
```

## Smoke checks

1. Keycloak realm HTTP 200  
2. Jenkins `/login` reachable  
3. Password-grant access token from client `jenkins-api`  
4. `GET /whoAmI/api/json` with `Authorization: Bearer` → **authenticated** success  
5. Invalid Bearer → not authenticated success  
6. Wrong-audience token → not authenticated success  

## Env overrides

| Variable | Default | Meaning |
|----------|---------|---------|
| `JWT_RS_KC_PORT` | `18091` | Host Keycloak port |
| `JWT_RS_JENKINS_PORT` | `18092` | Host Jenkins port |
| `JWT_RS_HOST_BIND` | `127.0.0.1` | Bind (loopback) |
| `JWT_RS_AUDIENCE` | `jenkins-api` | Allowed JWT audience |
| `JWT_RS_JWKS_URL` | `http://keycloak:8080/realms/jwt-rs-lab/protocol/openid-connect/certs` | JWKS as seen **from Jenkins container** |
| `JWT_RS_JENKINS_ADMIN_PASSWORD` | `admin` | Lab UI admin (disposable) |

## Residual honesty

| Residual | Notes |
|----------|--------|
| **Site Entra / production RS** | This free plugin lab ≠ production GO ([free-lab-qualification.md](../../docs/gateway/free-lab-qualification.md)) |
| **Plugin fallthrough** | Invalid JWT may be ignored by the filter; Jenkins **deny anonymous read** means API is not anonymously authenticated — smoke asserts that |
| **Full MCP route matrix** | Smoke uses `whoAmI` API only; progressive/artifact/wfapi re-prove is site residual |
| **`mode_*_live_*_qualified`** | Remains **false** — free lab never flips production-qualified flags |

## Security

Lab-only passwords (`admin` / `alice-lab` / `bob-lab`). Loopback bind default.
Tear down with `make live-jwt-rs-down` removes the Jenkins volume.
