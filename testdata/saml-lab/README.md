# SAML lab (POL-007 offline)

Opt-in offline fixtures for SAML SP validation. **Not** production Entra/Okta/ADFS.
Default `make test` does **not** require this lab.

## Contents

| Path | Role |
|------|------|
| `config.example.json` | Multi-fleet SP config shape (secret-free) |
| `fixtures/` | Generated/signed assertions for unit tests (see `internal/saml`) |
| `Makefile` targets | `make saml-lab-test` runs offline unit suite |

## Config

```bash
export JENKINS_MCP_SAML_CONFIG=/path/to/saml.json
# Optional session HMAC for admin cookies:
export JENKINS_MCP_SAML_SESSION_KEY=...
# IdP signing cert PEM path in config: idp_certificate_pem_path
```

## Residual

Live IdP browser redirect + production pin remains residual (`live_entra_okta_adfs_pin`).
Jenkins is never SAML IdP/AS (ADR 0015 / ADR 0003).

## Verify offline

```bash
make saml-lab-test
# equivalent: go test ./internal/saml/ ./internal/admin/ -count=1 -run SAML
```
