# SAML lab — Keycloak IdP (POL-007)

Disposable **Keycloak** SAML 2.0 IdP for local testing of SP config, metadata,
and trust material. **Not production.** Not Office 365 / Entra / Okta / ADFS.

**Not part of** default `make test` / `make ci`.

Offline unit tests (fixtures, no Docker) remain:

```bash
make saml-lab-test
# go test ./internal/saml/ ./internal/admin/ -count=1 -run SAML
```

## What this lab provides

| Piece | Detail |
|-------|--------|
| **IdP** | Keycloak `start-dev` + realm import `jenkins-mcp-lab` |
| **Host port** | `127.0.0.1:18090` (override `SAML_KC_PORT` / `SAML_HOST_BIND`) |
| **SAML SP client** | Entity ID `http://127.0.0.1:8787/sp` → ACS `http://127.0.0.1:8787/admin/v1/saml/acs` |
| **Lab users** | `alice` / `alice-lab` (group `mcp-operators`) · `bob` / `bob-lab` (`mcp-viewers`) |
| **Generated** | `.generated/idp.pem` + `.generated/saml-config.json` (gitignored) |

## Quick start (repo root)

```bash
export PATH="$HOME/.local/go/bin:$PATH"

# Build/start Keycloak (realm import on first boot)
make live-saml-up

# Wait + fetch metadata + write SP config + offline unit suite
make live-saml-smoke

# Up + smoke + down -v
make live-saml-test

# Tear down
make live-saml-down
```

## Wire admin serve (host)

```bash
export JENKINS_MCP_SAML_CONFIG="$PWD/testdata/saml-lab/.generated/saml-config.json"
# optional: export JENKINS_MCP_SAML_SESSION_KEY=lab-session-hmac
jenkins-mcp admin serve --addr 127.0.0.1:8787 --admin-role viewer
```

| Endpoint | Purpose |
|----------|---------|
| `GET /admin/v1/saml/status` | Secret-free enablement map |
| `POST /admin/v1/saml/acs` | `SAMLResponse` form (ACS) |
| `GET /admin/v1/saml/login` | Live IdP redirect residual (501 until browser path lands) |

Keycloak admin console (master realm): `http://127.0.0.1:18090/admin` — user `admin` / `admin` (lab only).

## Env overrides

| Variable | Default | Meaning |
|----------|---------|---------|
| `SAML_KC_PORT` | `18090` | Host port |
| `SAML_HOST_BIND` | `127.0.0.1` | Bind address |
| `SAML_KEYCLOAK_IMAGE` | `quay.io/keycloak/keycloak:26.0` | Image |
| `SAML_SP_ENTITY_ID` | `http://127.0.0.1:8787/sp` | SP entity / Keycloak clientId |
| `SAML_ACS_URL` | `http://127.0.0.1:8787/admin/v1/saml/acs` | Assertion consumer |

## Contents

| Path | Role |
|------|------|
| `docker-compose.yml` | Keycloak service |
| `realm/jenkins-mcp-lab-realm.json` | Realm + SAML client + users/groups |
| `config.example.json` | Multi-fleet config shape (no live cert) |
| `.generated/` | Smoke outputs (cert + config) — gitignored |
| `../../scripts/saml-lab-smoke.sh` | Up-wait-metadata-config-unit smoke |

## Residual honesty

| Residual | Notes |
|----------|--------|
| **Live Entra / Office 365** | Lab ≠ production Microsoft pin |
| **Full browser ACS** | IdP login → POST ACS may need SP **XML-DSig** hardening vs fixture verifier |
| **Login redirect** | `GET /admin/v1/saml/login` still residual 501 offline |
| **Multi-pod session** | Process-local cookie only |

Smoke **does** prove: Keycloak realm up, SAML metadata, cert export, product
`LoadConfigFile` + trust PEM load, offline unit suite green.

## Security

Ephemeral lab passwords only (`admin` / `alice-lab` / `bob-lab`). Never reuse in
production. Tear down with `make live-saml-down` removes the container.
