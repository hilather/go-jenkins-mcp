# Multi-fleet rollout (config / gitops SoT)

**Status:** Product free-lab multi-fleet pack (2026-08-01)  
**Audience:** platform operators, agents  
**Related:** [policy-rbac.md](../policy-rbac.md) · [policy-bundles.md](../security/policy-bundles.md) · [free-lab-qualification.md](../gateway/free-lab-qualification.md) · fixtures `testdata/fleet-pack/` · **[fleet-mcp-ops.md](fleet-mcp-ops.md)** (opt-in `fleet_*` MCP + any-node fan-out — **Done\* vertical slice**; not multi-pod HA) · **[shared-cache-architecture.md](shared-cache-architecture.md)** (optional peer sealed-log cache — **Planned**, ADR [0016](../adr/0016-fleet-p2p-shared-cache.md); default local plane A)

---

## 1. Model (do not invent a user DB)

| Layer | SoT | Notes |
|-------|-----|--------|
| Who authenticates | **IdP** | Product maps claims; no local password directory |
| Per-host Jenkins connection | **Profiles** (secret-free URL/TLS) | Tokens in Secret Service / file keyring residual |
| Deny-only MCP RBAC | **One shared overlay / signed bundle** | Global + `subjects.users[]` / `subjects.groups[]` (POL-006) |
| Admin group→role / SAML maps | **Config files** (POL-007) | SPA Access is pilot/break-glass only |

Every fleet member loads the **same** signed (or plain pilot) overlay from gitops; credentials never live in the overlay.

---

## 2. Example layout (`testdata/fleet-pack/`)

```text
testdata/fleet-pack/
  profiles/
    site-a.json          # secret-free profile (URL only)
    site-b.json
  policy/
    overlay.json         # deny-only + subjects.users / subjects.groups
    README.md            # how to sign → overlay.bundle.json
  keys/
    README.md            # generate Ed25519; never commit private keys
```

Operator production layout (suggested):

```text
fleet/
  profiles/{member}.json
  policy/overlay.json | overlay.bundle.json
  policy/trusted_keys/*.pem   # public only in git
```

---

## 3. Roll-out steps

1. **Profiles** — one JSON per controller member (no tokens).  
2. **Overlay** — set `force_read_only`, denials, and `subjects` bindings.  
3. **Trust keys** — distribute Ed25519 public keys; set `JENKINS_MCP_POLICY_TRUSTED_KEYS` (dir or list).  
4. **Sign** — `jenkins-mcp policy sign --file overlay.json --key … --key-id … --out overlay.bundle.json` (higher `bundle_seq` than last-good).  
5. **Require signed** — `JENKINS_MCP_REQUIRE_SIGNED_POLICY=1` on fleet hosts (fail closed without keys/valid bundle).  
6. **Login** — each host: `jenkins-mcp login --profile <id>` (keyring).  
7. **Serve** — `jenkins-mcp serve --profile <id> --read-only --stdio`.  
8. **Hot-reload** — overlay/bundle path watched; last-good rejects downgrade `bundle_seq`.

Pilot break-glass: admin console **Access** page / `admin_rbac_*` tools edit **plain** overlay only; refuse when require-signed / signed bundle path is active.

---

## 4. Residual honesty

| Residual | Owner |
|----------|--------|
| HSM / true *t*-of-*n* multi-sig | Operator crypto pipeline (MGR-001 residual) |
| Central fleet telemetry aggregation / SIEM | MGR-002 residual |
| Live Entra / production SAML browser pin | Site IdP (free-lab policy separate) |
| Multi-pod gateway HA | **Out of scope** (HOST-008 **cancelled**) — multi-fleet *is* the scale model; do not plan multi-replica shared vault/rate |
| SPA as fleet SoT | **Never** — config/signed policy remains SoT |
| Cross-member MCP aggregation (`fleet_*`) | **Done\* vertical slice** — [fleet-mcp-ops.md](fleet-mcp-ops.md); opt-in `--fleet-mode` + roster + mesh token; not default pilot; not multi-pod HA |
| Cross-member **log cache** (FLC peer plane) | **Planned residual** — plane A stays **local by default**; optional pure-Go owner-directed peer read of sealed completed console logs (MVP A first; fill/RF2 later). **Not Done.** Audit: [shared-cache-current-state.md](shared-cache-current-state.md). Absolute: [ADR 0016](https://github.com/hilather/go-jenkins-mcp/blob/master/docs/adr/0016-fleet-p2p-shared-cache.md) |

Verify offline: `go test ./internal/policy/ -run 'Fleet|POL006|RequireSigned|LoadFromEnviron'`.  
Example fixtures: `testdata/fleet-pack/`.
