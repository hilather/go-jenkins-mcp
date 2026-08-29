# Optional operator Entra + jwt-auth-filter walkthrough

**Support status:** **optional operator Entra walkthrough** — not Supported
production, not a merge gate, not a production pin.

The default free plugin lab remains Keycloak + `jwt-auth-filter`
([`../../testdata/jwt-rs-lab/README.md`](../../testdata/jwt-rs-lab/README.md),
**Free-lab validated**). This page records how an operator pointed that same
Jenkins at a real Microsoft Entra tenant (Entra ID Free is enough) and proved
browser PKCE login plus Bearer calls to Jenkins.

This walkthrough does **not**:

- flip `mode_*_live_*_qualified`
- close OAUTH-009 / OAUTH-010
- claim production Entra GO
- change free-lab qualification policy

Residual banners stay in
[jwt-auth-filter qualification](../auth/jwt-auth-filter-qualification.md) and
[live pin blockers](../gateway/live-pin-blockers.md). A worked walkthrough is
not a site production pin.

Placeholders only — never commit real tenant IDs, client IDs, emails, or tokens:

| Meaning | Placeholder |
|---------|-------------|
| Operator mailbox | `operator@example.com` |
| Directory (tenant) GUID | `{tenant-id}` |
| Entra domain (display only) | `{tenant}.onmicrosoft.com` |
| Jenkins API / resource app id | `{api-app-id}` |
| Public client / gateway app id | `{gateway-app-id}` |
| Application ID URI | `api://{api-app-id}` |
| Delegated scope | `api://{api-app-id}/jenkins.access` |
| Issuer | `https://login.microsoftonline.com/{tenant-id}/v2.0` |
| JWKS | `https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys` |
| Loopback callback | `http://127.0.0.1:8400/callback` |
| jwt-auth-filter lab | `http://127.0.0.1:18092/` |
| API-token Jenkins lab (contrast) | `http://127.0.0.1:18080/` |

Use the directory **GUID** `{tenant-id}` in `oidc.issuer`, `oidc.tenantId`, and
the JWKS URL. Do not put `{tenant}.onmicrosoft.com` in those fields — jenkins-mcp
compares issuer and tenant **exactly**.

## Agent hints

- Two **separate** Entra app registrations (API resource + public client). Do not merge them.
- Public / native client (`publicClient`), **not** Single-page application.
- `api.requestedAccessTokenVersion` = `2` on the **API** app (not the gateway app).
- Profile `oidc.jenkinsAudience` and Jenkins `JWT_RS_AUDIENCE` are the API **app id GUID**, not `api://…`. Scopes still use `openid`, `profile`, and `api://{api-app-id}/jenkins.access`.
- App A Token configuration: optional claims on the **access** token — `preferred_username` (optionally `name`, `email`). Scope `profile` is a companion only; it does not replace those claims.
- JWKS is `https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys`.
- `jenkins-mcp login --profile <id> --oidc`; prove with Bearer `GET /whoAmI/api/json` and `GET /api/json`.
- Never bake secrets or tokens. Isolated XDG + `JENKINS_MCP_KEYRING_FILE` for the lab.
- This does **not** flip `mode_*_live_*_qualified` or close OAUTH-009/010.

## Terms (one line each)

| Term | Meaning |
|------|---------|
| **Audience** (`aud`) | Who the access token is for. Jenkins and jenkins-mcp require an **exact** match. |
| **JWKS** | The HTTPS URL of public keys used to check the token signature. |
| **PKCE** | Extra proof on the token request so a stolen browser code cannot be redeemed. |
| **SPA** | Browser-only public client. Entra may require an `Origin` header when redeeming the code. jenkins-mcp is a native CLI and does not send `Origin`. |

```mermaid
sequenceDiagram
  participant Op as Operator browser
  participant CLI as jenkins-mcp login --oidc
  participant Entra as Entra authorize and token
  participant Loop as 127.0.0.1:8400/callback
  participant J as Jenkins jwt-auth-filter :18092

  CLI->>Entra: Open authorize URL (PKCE, resource = GUID)
  Op->>Entra: Sign in and consent
  Entra->>Loop: Redirect with authorization code
  Loop->>CLI: Code on loopback
  CLI->>Entra: POST token (no Origin header, no client secret)
  Entra->>CLI: Access token (aud = API app GUID)
  CLI->>CLI: Exact iss and aud check, store in isolated keyring
  CLI->>J: GET /whoAmI/api/json and /api/json with Bearer
  J->>Entra: Fetch JWKS
  J->>CLI: 200, not anonymous
```

---

## 1. Setup

### 1.1 Azure / Entra account

A free Azure account with **Entra ID Free** is enough. You only need **app
registrations**. You do not need VMs, paid Entra SKUs, or a production Jenkins.

You will sign in as something like `operator@example.com` in that tenant.

### 1.2 Two app registrations (do not merge them)

Register **two** single-tenant apps.

#### App A — Jenkins API (resource)

This app represents Jenkins as a **resource server** (the API that accepts the
access token).

1. Single-tenant.
2. **Expose an API.** Application ID URI: `api://{api-app-id}`.
3. Add a **delegated** scope named `jenkins.access` (admins and users can consent).
4. In the app manifest (Microsoft Graph / new manifest), set
   `api.requestedAccessTokenVersion` to `2`.
5. Token configuration → optional claims on the **access** token:
   `preferred_username` (optionally `name`, `email`). JCasC maps
   `usernameClaim: preferred_username`. Scope `profile` (below) does not
   replace this step.

**Why version 2:** if this is `null` or `1`, Entra issues **v1** access tokens
whose issuer is `https://sts.windows.net/{tenant-id}/`. jenkins-mcp compares the
token issuer **exactly** to the profile issuer (`…/v2.0`) and login fails with
`jwt issuer does not match profile`.

Set this on the **API** app, not the gateway app.

#### App B — MCP public client (gateway)

This app is the **public / native client** that jenkins-mcp uses in the browser.
**No client secret.**

1. Single-tenant. Do not create a client secret.
2. Redirect URIs: `http://127.0.0.1:8400/callback` and optionally
   `http://localhost:8400/callback`.
3. Platform must be **Mobile and desktop applications** (`publicClient`),
   **not** Single-page application.
4. Portal Authentication UI often tries to put `http://127.0.0.1` under **Web**,
   which rejects it. If that happens, edit the **manifest**:
   - `spa.redirectUris`: `[]`
   - `publicClient.redirectUris`: the two loopback URIs
   - `isFallbackPublicClient`: `true`
5. API permissions (delegated): App A `jenkins.access`, plus Microsoft Graph
   `User.Read`.
6. Grant admin consent.

`http://127.0.0.1:8400/callback` is the **documented walkthrough callback**.
jenkins-mcp binds **127.0.0.1 only**; bare `localhost` is not used as the
listener. The binary does not hard-code port 8400 — the profile
`redirectUris` and the Entra registration must match.

**Why not SPA:** jenkins-mcp is a native CLI. It posts the authorization code to
Entra’s token endpoint **without an Origin header**. Codes issued for an SPA may
only be redeemed as cross-origin requests (AADSTS9002327, OAuth error
`invalid_request`). That looks like a broken login even after the browser
callback succeeds.

### 1.3 jenkins-mcp profile (`authMethod: oidc_bearer`)

There is **no** CLI flag for issuer, audience, or client id.
`profile add <id> --url … --auth-method oidc_bearer` fails `Validate()` without
an `oidc` block. Write the JSON yourself.

**Isolated XDG (recommended for a lab)** so operator home config is untouched.
Export these for **every** `jenkins-mcp` command in that shell:

```bash
export XDG_CONFIG_HOME="$PWD/.entra-lab/xdg/config"
export XDG_DATA_HOME="$PWD/.entra-lab/xdg/data"
export XDG_CACHE_HOME="$PWD/.entra-lab/xdg/cache"
export JENKINS_MCP_KEYRING_FILE="$PWD/.entra-lab/keyring.json"
mkdir -p "$XDG_CONFIG_HOME/jenkins-mcp/profiles"
```

If you skip isolation, the default profile path is
`~/.config/jenkins-mcp/profiles/<id>.json` when `XDG_CONFIG_HOME` is unset.

Filename stem must equal `id`. Nested `"oidc"` object (not dotted keys):

```json
{
  "configVersion": 1,
  "id": "entra-lab",
  "jenkinsURL": "http://127.0.0.1:18092/",
  "authMethod": "oidc_bearer",
  "oidc": {
    "issuer": "https://login.microsoftonline.com/{tenant-id}/v2.0",
    "clientId": "{gateway-app-id}",
    "jenkinsAudience": "{api-app-id}",
    "scopes": [
      "openid",
      "profile",
      "api://{api-app-id}/jenkins.access"
    ],
    "redirectUris": [
      "http://127.0.0.1:8400/callback"
    ],
    "tenantId": "{tenant-id}"
  }
}
```

Write that file to `$XDG_CONFIG_HOME/jenkins-mcp/profiles/entra-lab.json`.

| Field | Must be |
|-------|---------|
| `oidc.issuer` | `https://login.microsoftonline.com/{tenant-id}/v2.0` (GUID, not the `.onmicrosoft.com` domain) |
| `oidc.clientId` | `{gateway-app-id}` (public client). Token `azp` must match this. |
| `oidc.jenkinsAudience` | `{api-app-id}` — the **app id GUID**, not `api://{api-app-id}` |
| `oidc.scopes` | `openid`, `profile`, and `api://{api-app-id}/jenkins.access` (the Jenkins scope still uses the URI) |
| `oidc.redirectUris` | Must include `http://127.0.0.1:8400/callback` |
| `oidc.tenantId` | `{tenant-id}` (GUID) |
| `jenkinsURL` | jwt-auth-filter Jenkins (lab default `http://127.0.0.1:18092/`) |

**Why GUID audience:** Entra **v2** access tokens put `aud` = resource app id
(GUID), not the Application ID URI. jenkins-mcp `ValidateAccessToken` is an
**exact** audience match. If the profile still has `api://…`, login fails with
`jwt audience does not include the configured jenkins audience` even though Entra
issued a good token.

Omitting `scopes` defaults to `openid` only — Entra then mints a token that is
not for Jenkins. Include `profile` as a companion; it does not replace App A
optional access-token claims. Omitting `redirectUris` lets the file load but
`login --oidc` fails.

Optional check (secret-free): `jenkins-mcp oauth validate-profile --profile entra-lab`.

---

## 2. Server / deployment notes (Jenkins as a resource server)

Reuse `testdata/jwt-rs-lab` (Makefile `live-jwt-rs-up` / `live-jwt-rs-down`).
Point the plugin at Entra instead of Keycloak. JCasC already substitutes these
env vars (`testdata/jwt-rs-lab/jenkins/casc.yaml`). Username claim is already
`preferred_username`.

| Variable | Entra value |
|----------|-------------|
| `JWT_RS_JWKS_URL` | `https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys` |
| `JWT_RS_AUDIENCE` | `{api-app-id}` (same GUID as `jenkinsAudience`) |
| `JWT_RS_PROTECTED_PATHS` | `/**/api/**` |

Keycloak can stay up unused; it is **not** the JWKS source for this walkthrough.
Do **not** run `make live-jwt-rs-smoke` or `make live-jwt-rs-test` against Entra
JWKS — those mint Keycloak password-grant tokens.

If you previously ran the Keycloak lab, `make live-jwt-rs-down` first (`down -v`
wipes the Jenkins volume) so CASC is not mixed with a prior Keycloak apply.

### Bring-up method A — export then Make

`make live-jwt-rs-up` only prefixes host/port in the recipe. Compose still
reads `JWT_RS_*` from the process environment. `export` **or** a Make
command-line assignment (`JWT_RS_JWKS_URL=… make live-jwt-rs-up`) both work
on GNU Make. Keycloak still starts and must become healthy (`depends_on`)
even though it is unused as JWKS:

```bash
export JWT_RS_JWKS_URL="https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys"
export JWT_RS_AUDIENCE="{api-app-id}"
export JWT_RS_PROTECTED_PATHS="/**/api/**"
make live-jwt-rs-up
```

### Bring-up method B — local compose override

The tracked file is an **example** with placeholders. Copy it, then pass the
**copy**:

```bash
cp testdata/jwt-rs-lab/entra.override.example.yml testdata/jwt-rs-lab/entra.override.yml
# replace {tenant-id} and {api-app-id} in the copy only
docker compose -f testdata/jwt-rs-lab/docker-compose.yml \
  -f testdata/jwt-rs-lab/entra.override.yml up -d --build
```

Do **not** `-f` the tracked `.example.yml` (literals `{tenant-id}` would be
used). Do **not** name the working file `docker-compose.override.yml` (Compose
auto-loads that and would change the default Keycloak lab). The copy
`entra.override.yml` is gitignored.

Jenkins must **reach** `login.microsoftonline.com` to fetch JWKS.

**Environment footnote (not a product requirement):** if the Docker daemon has
no NAT/iptables (bridge DNS fails), Jenkins cannot fetch Entra JWKS from the
compose bridge. Prefer method A/B when the daemon can NAT. `make live-jwt-rs-up`
cannot do host networking (published `18092:8080`, healthcheck on 8080).

Use a **copy** of the host-net example (Docker Compose v2.24+ for `!reset`).
Do **not** `-f` the tracked file (literals `{tenant-id}` would be used):

```bash
cp testdata/jwt-rs-lab/entra.hostnet.override.example.yml \
  testdata/jwt-rs-lab/entra.hostnet.override.yml
# replace {tenant-id} and {api-app-id} in the copy only
docker compose -f testdata/jwt-rs-lab/docker-compose.yml \
  -f testdata/jwt-rs-lab/entra.hostnet.override.yml up -d
```

That override sets `network_mode: host`, clears published ports (and the
default project network), `JENKINS_OPTS=--httpPort=18092 --httpListenAddress=127.0.0.1`
(official image war flags — the base Dockerfile does not set a `command`),
healthcheck on `http://127.0.0.1:18092/login`, and the same Entra JWKS/audience
placeholders as method B. Keycloak may still start on the bridge (`depends_on`)
and stay unused as JWKS. Omit `--build` if NAT is already broken (image build
still uses the daemon build network); use a previously built jwt-rs Jenkins
image. The working copy `entra.hostnet.override.yml` is gitignored.

Wait until Jenkins answers before proving login:

```bash
# first --build can take several minutes (plugin download)
until code=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 \
  http://127.0.0.1:18092/login || true); \
  [[ "$code" == "200" || "$code" == "403" ]]; do sleep 2; done
```

---

## 3. Verification

Prerequisites: `jenkins-mcp` on `PATH`, same `XDG_*` + `JENKINS_MCP_KEYRING_FILE`
exports as when you wrote the profile, and a local GUI browser (`xdg-open` or
`$BROWSER`). The CLI does **not** print the authorize URL. Login waits up to
five minutes. `login --oidc` does **not** call Jenkins.

```bash
jenkins-mcp login --profile entra-lab --oidc
```

If the browser is already signed into Microsoft, this may finish in a couple of
seconds.

**HTTP proof is curl only.** `jenkins-mcp status` only means a token is present.
Online `doctor` / `oauth probe-rs` are **residual / honesty**, not pass/fail for
this walkthrough (they warn on whoAmI fallthrough and print an oic-auth residual
string even when this lab has the plugin).

The CLI never prints the access token. When `JENKINS_MCP_KEYRING_FILE` is set,
the file is JSON: service `go-jenkins-mcp` → account
`profile=entra-lab;method=oidc_tokens` → a **string** whose contents are
TokenBundle JSON (`v`, `access_token`, …). Parse that inner string into a
variable; **do not echo or paste it**. (Without the file backend, tokens are
in the OS keyring and this recipe does not apply.)

```bash
ACCESS_TOKEN="$(jq -r --arg id entra-lab \
  '.["go-jenkins-mcp"]["profile="+$id+";method=oidc_tokens"] | fromjson | .access_token' \
  "$JENKINS_MCP_KEYRING_FILE")"
# do not echo "$ACCESS_TOKEN"
curl -sS -o /tmp/whoami.json -w '%{http_code}\n' \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  http://127.0.0.1:18092/whoAmI/api/json
```

**Pass:** HTTP **200**, `anonymous` is false, `name` is the signed-in Entra user
(not `anonymous`). Do not treat `authenticated=true` alone as success — Jenkins
whoAmI reports `authenticated=true` for anonymous too.

```bash
curl -sS -o /tmp/api.json -w '%{http_code}\n' \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  'http://127.0.0.1:18092/api/json?tree=mode'
```

**Pass:** HTTP **200**. Non-2xx means the filter did not accept the token —
check audience and JWKS.

### Negative checks

Plugin may ignore an invalid JWT and continue. Jenkins
`allowAnonymousRead: false` still denies API data.

| Request | Expected |
|---------|----------|
| `/whoAmI/api/json` with no Authorization or garbage Bearer | HTTP **200** and anonymous (`name=anonymous`) is OK |
| `/api/json` with no Authorization or garbage Bearer | **non-2xx** (typically 403), **not 500** |

---

## 4. Security

- Public client = **no secret** in the profile, compose, or CLI args.
- Tokens live in the OS keyring or `JENKINS_MCP_KEYRING_FILE` (mode 0600). Never
  commit that file, paste tokens into tickets, or put them in chat.
- Isolated XDG keeps this lab out of `~/.config/jenkins-mcp`.
- Treat Jenkins JSON and Entra error pages as untrusted text.
- Do not use Microsoft Graph as `jenkinsAudience`.

---

## 5. Limits / budgets

- This lab protects `/**/api/**` only. Progressive logs, artifacts, and wfapi
  are **site residual** (see
  [jwt-auth-filter qualification](../auth/jwt-auth-filter-qualification.md) §3).
- No refresh token unless you add `offline_access` to scopes (not required for
  the whoAmI proof).
- `serve --gateway` / AgentCore Obtain/OBO remains residual. This walkthrough is
  browser PKCE + Jenkins resource server only.
- Online doctor / probe-rs still report `live_lab_still_required` — expected.

---

## 6. Troubleshooting (gotchas)

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| Browser callback succeeds, then `token endpoint error=invalid_request` | App B registered as **SPA** (or Web), not native public client. CLI drops Entra `error_description` on purpose. | Manifest: `publicClient.redirectUris`, empty `spa.redirectUris`, `isFallbackPublicClient: true`. |
| `jwt issuer does not match profile` | API app token version is null/1 (v1 issuer `sts.windows.net`). | Set `requestedAccessTokenVersion` = `2` on the **API** app. Confirm profile issuer ends with `/v2.0` and uses the GUID. |
| `jwt audience does not include the configured jenkins audience` | Profile `jenkinsAudience` is `api://…` or Graph. | Set profile and `JWT_RS_AUDIENCE` to the API **app id GUID**. Keep the `api://` form on **scopes** only. |
| `jwt authorized party does not match client id` | `oidc.clientId` is the API app, not the public client. | `clientId` = `{gateway-app-id}`. |
| `jwt tenant does not match profile` | `tenantId` or issuer used the domain instead of the GUID. | Use `{tenant-id}` only. |
| Login hangs, then times out | No GUI browser / `xdg-open`. CLI does not print the authorize URL. | Use a local desktop session; set `$BROWSER`. Timeout is 5 minutes. |
| `failed to bind loopback callback` | Something else is using `127.0.0.1:8400`. | Change the port in **both** profile `redirectUris` and the Entra public-client registration. |
| whoAmI 200 but `name=anonymous` with a “good” token | Token omitted `preferred_username`. JCasC hard-codes that claim (do not edit `casc.yaml`). | Entra Token configuration → optional claims on the **access** token for App A: `preferred_username`, `name`, `email`. |
| `/api/json` 403 with a token that passed login | Jenkins JWKS/audience still Keycloak defaults, or container cannot reach Entra JWKS. | Confirm env on the running Jenkins container; recreate with `down -v` after a Keycloak run. |
| `make live-jwt-rs-smoke` fails after pointing at Entra | Smoke mints Keycloak tokens. | Do not run Keycloak smoke against Entra JWKS. |
| Doctor / probe-rs warn about fallthrough or “only oic-auth” | Classifier treats whoAmI 200+anonymous as fallthrough; residual string is honesty. | Expected. Use curl proof above. |
| First whoAmI connection refused | Compose returned before Jenkins was ready. | Wait for `/login` 200 or 403. First build can take several minutes. |

The product still sends RFC 8707 `resource` = `jenkinsAudience` on authorize and
token. Dummy garbage-code posts to Entra v2 did not show AADSTS901002; do **not**
document `resource` as a proven Entra blocker.

---

## 7. Rollback / disable (tear down)

```bash
make live-jwt-rs-down
# or: docker compose -f testdata/jwt-rs-lab/docker-compose.yml down -v --remove-orphans
```

Then, with the same isolated env:

```bash
jenkins-mcp logout --profile entra-lab
rm -f "$JENKINS_MCP_KEYRING_FILE"
rm -rf "$PWD/.entra-lab"
```

Optionally disable or delete the two Entra app registrations. Never commit
tokens, filled override files, or keyring JSON.

Compose `down -v` does **not** remove Entra apps or the isolated profile.

---

## Related

- Default Keycloak lab: [`../../testdata/jwt-rs-lab/README.md`](../../testdata/jwt-rs-lab/README.md)
- Qualification policy: [qualification.md](qualification.md)
- Auth modes: [../integrations/auth-modes.md](../integrations/auth-modes.md)
- OAUTH-009 residuals: [../auth/jwt-auth-filter-qualification.md](../auth/jwt-auth-filter-qualification.md)
- OAUTH-010 / live pin: [../gateway/live-pin-blockers.md](../gateway/live-pin-blockers.md)
- Free-lab bar: [../gateway/free-lab-qualification.md](../gateway/free-lab-qualification.md)
- User `login --oidc`: [../user/README.md](../user/README.md)
- Agent policy: [../../AGENTS.md](../../AGENTS.md)
