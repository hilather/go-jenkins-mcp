# MCP policy overlay and deny-only RBAC

**Tasks:** CFG-002, POL-002, POL-003, MGR-001, Wave 24 hot-reload, Wave 25 force/budget hot-apply, Wave 26 glob-lite, Wave 28 ListTools live filter, Wave 29 mid-path `**/` + ListTools AuthGate, Wave 30 mutation register / braces / Target normalize, Wave 31 char classes / LiveHardMax ceiling / job path .. reject, Wave 32 nested braces, Wave 35 non-job resource deny patterns (node/view)
**Related:** ADR 0004, ADR 0012, architecture §7, package `internal/policy`,
[`security/policy-bundles.md`](security/policy-bundles.md)

## Model

Effective access is always the **intersection** (never union):

```text
Jenkins allow
  AND global read-only gate
  AND MCP deny-only policy
  AND operation budgets
```

MCP policy **can only deny / restrict**. It never grants Jenkins access, never
synthesizes credentials, and never marks a Jenkins denial as allowed. Jenkins
remains authoritative for controller permissions.

## Enterprise policy overlay (CFG-002)

Versioned, secret-free JSON loaded at `serve` time.

| Source | Path |
|--------|------|
| Env override | `JENKINS_MCP_POLICY_FILE` (plain or signed envelope) |
| Default plain | `$XDG_CONFIG_HOME/jenkins-mcp/policy/overlay.json` |
| Default signed | `…/policy/overlay.bundle.json` (preferred when present) |
| Trusted keys | `…/policy/trusted_keys/` or `JENKINS_MCP_POLICY_TRUSTED_KEYS` |
| Required mode | `JENKINS_MCP_POLICY_REQUIRED=true` fails closed if file missing / unsigned (staging field-presence) |
| Require signed (enterprise) | `JENKINS_MCP_REQUIRE_SIGNED_POLICY=1` requires trusted keys + Ed25519 envelope (gateway pin; staging stub not accepted) |

### Schema (version 1) — plain overlay body

```json
{
  "version": 1,
  "force_read_only": true,
  "mode": "pilot",
  "deny_tools": ["jenkins_get_build_logs"],
  "deny_job_prefixes": ["secret-folder", "team-*/legacy/**"],
  "deny_node_names": ["prod-agent-*"],
  "deny_view_names": ["secret-view", "hr/**"],
  "deny_artifact_paths": ["secrets/**", "*.pem"],
  "deny_branch_names": ["release/*"],
  "max_result_bytes": 65536,
  "max_tools_per_minute": 15,
  "max_tools_burst": 5,
  "fleet_telemetry_force_off": true,
  "subjects": {
    "users": [{"jenkins_user_id": "alice", "deny_tools": ["jenkins_get_build_logs"]}],
    "groups": [{"group_id": "contractors", "deny_job_prefixes": ["legacy/**"]}]
  }
}
```

| Field | Meaning |
|-------|---------|
| `version` | Must be `1` |
| `force_read_only` | When true, cannot be defeated by `--allow-mutations`, profile, or weaker flags |
| `subjects` | Optional POL-006 per-user / per-group deny-only bindings (see [Per-user and per-group bindings](#per-user-and-per-group-bindings-pol-006)) |
| `fleet_telemetry_force_off` | When true, forces fleet health telemetry **off** regardless of `JENKINS_MCP_TELEMETRY` (MGR-002). Fail closed / lower-only: env cannot re-enable while pin is true. Serve applies on load + hot-reload (`Collector.SetForceOff`). Admin pilot apply cannot clear a true pin. See [fleet-telemetry.md](security/fleet-telemetry.md). |
| `mode` | `pilot` (default) or `strict` |
| `deny_tools` | Exact MCP tool names to deny |
| `deny_job_prefixes` | Job full names / folder patterns denied at **call time** when args include `job_name` or seed `name`. See [Job pattern language](#job-pattern-language-deny_job_prefixes-pol-002-wave-26). Empty / overly broad entries fail load. **Wave 37/39:** also omits matching rows from `jenkins_list_jobs` (collect+filter+repaginate when patterns live; `policy_filtered` / `policy_omitted_count`). |
| `deny_node_names` | Node/agent name patterns denied at **call time** when args include `node_name` / `NodeName` (Wave 35). Same pattern language as `deny_job_prefixes`. **Wave 36:** also omits matching rows from list-all `jenkins_get_nodes`. |
| `deny_view_names` | View name patterns denied at **call time** when args include `view_name` / `ViewName` or seed `view` / `View` (Wave 35; e.g. `jenkins_list_jobs`). Same pattern language as jobs. **Wave 38 implemented:** also omits matching rows from list-all `jenkins_list_views`. |
| `deny_artifact_paths` | Relative artifact path patterns denied at **call time** when args include `path` / `Path` or `artifact_path` / `ArtifactPath` (Wave 36; e.g. `jenkins_get_artifact_text`). Same pattern language as jobs. **Wave 37:** page-level omit from `jenkins_list_artifacts` under `max_artifacts`. **Wave 40 implemented:** hard-cap fetch when patterns live, filter, re-slice to caller `max_artifacts` (denied paths do not steal page slots). **Wave 39:** also omit denied paths from `jenkins_compare_builds` artifact diffs. **Wave 41 implemented:** compare/diagnose artifact cache (`getCachedArtifactList`) fetches via `listArtifactsWithPolicyFilter`, fingerprints cache keys with sorted `ArtifactPolicyFingerprintMaterial`, and always post-filters live patterns on return (denied paths never surface on hit or miss). |
| `deny_branch_names` | Branch name patterns denied at **call time** when args include `branch_name` / `BranchName` or seed `branch` / `Branch` (Wave 37). **Wave 38–39:** when `BranchName` is empty and `job_name` / `JobName` is a **multi-segment** path (≥2 `/`-separated segments after normalize), matches `BranchDenyCandidates`: **leaf**, intermediate segments from index 1 (not the first folder alone), multi-segment path **suffixes**, and full JobName — so `team/mb/release/1.2` is denied by `release/*`, exact `release`, or leaf `1.2`. **Single-segment** JobName alone (e.g. root freestyle `main`) does **not** apply branch deny via candidates. Slashy `BranchName` (e.g. `release/1.2`) also matches its leaf and path candidates. Same pattern language as jobs. **Wave 37/39 list privacy:** also omits matching `kind=branch`/`matrix_child` rows from `jenkins_list_jobs` via collect+filter+repaginate (`ApplyJobPolicyFilters` on Name/FullName; not page-level only). Kind gate: folders named like a branch are not hidden by branch deny. |
| `max_result_bytes` | Optional result hard-max bound; mid-serve raise/lower ≤ serve-bootstrap ceiling (Wave 31); never elevates Jenkins rights |
| `max_tools_per_minute` | Optional per-subject tools/min cap (HOST-006); serve applies via `SubjectRateLimiter.LowerRate` **lower only** under `--gateway` (never raises bootstrap env rate; omitted = no change) |
| `max_tools_burst` | Optional per-subject token-bucket burst cap (HOST-006 LowerRate; lower only; omitted = no change) |
| `signature` | Legacy stub on plain files only; production uses signed **envelopes** |

### Fail-closed rules

- File **absent** and not required → no overlay (process continues).
- File **present** but unreadable / invalid JSON / bad version / bad mode → **error** (no partial load).
- Invalid `deny_job_prefixes` / `deny_node_names` / `deny_view_names` / `deny_artifact_paths` entry (empty, `*`, `**`, `/**`, `**/**`, embedded `**` in a segment, traversal, unsupported metacharacters, invalid braces/classes, over-long paths) → **error**.
- Signature verifier rejects → **error**.
- Signed envelope: invalid/expired/untrusted/downgraded → **error** (MGR-001).

### Signature verification (MGR-001)

`SignatureVerifier` implementations:

- `NopSignatureVerifier` — pilot default when **no** trusted keys; plain overlays only (`unverified_pilot`). Signed envelopes are **not** accepted via Nop.
- `RequiringSignatureVerifier` — staging when `JENKINS_MCP_POLICY_REQUIRED` without keys (presence check; not crypto proof).
- `Ed25519SignatureVerifier` — production path when trusted public keys are configured; verifies envelope, expiry, `min_version`, and last-good `bundle_seq`. Supports optional multi-sig lite (`signatures[]` + `MinSignatures` distinct trusted keys; default 1; set 2 for dual-control). Single-sig top-level `signature` remains the MVP path.

Full format, CLI (`policy verify` / `show-effective` / dev `sign`), and operator
rules: [`security/policy-bundles.md`](security/policy-bundles.md) and ADR 0012.

Do not treat `unverified_pilot` or `present_field` as integrity proof.

## Global read-only + force (POL-001 + CFG-002)

Most restrictive wins. Enterprise `force_read_only` is wired through
`policy.DynamicForce` (Wave 25 serve path) / `policy.AsEnterpriseForce(overlay)`
into `ReadOnlyGate`. The gate re-reads Force on every `Effective()` so reload
can flip force mid-session. Tests prove `--allow-mutations` cannot defeat
enterprise force for **Effective** RO (`DenyMutation` / ListTools hide), and
mid-life `DynamicForce.Set` updates `Effective` / `AllowMutationRegistration`.

**Wave 30:** when `--allow-mutations` / `Inputs.AllowMutations` is set,
`ShouldRegisterMutations()` is true even while `Effective()` (e.g. force on),
so mutation tools are **registered** under force RO. ListTools filter +
`DenyMutation` still hide/deny until force clears; then tools reappear without
restart. Without allow-mutations (pilot default), mutations stay omitted at
Register (`AllowMutationsOptIn` false).

## Per-user and per-group bindings (POL-006)

**Status:** **implemented (policy language + evaluator). Admin SPA/BFF binding CRUD
managed via Access SPA / `admin_rbac_*` (**UI-011 implemented pilot). **SAML group source** is **POL-007 implemented offline
(`internal/saml` maps assertion groups → `Subject.Groups`); live IdP pin residual.

Operator-defined **named permission sets per user and per group** attach to the
same overlay document as global denials. Matching is against verified
`policy.Subject` only (Jenkins user, optional external subject, IdP groups from
gateway/JWT/**SAML** bind) — **never** MCP tool arguments.

### Schema (`subjects` on overlay)

```json
{
  "version": 1,
  "force_read_only": true,
  "deny_tools": ["jenkins_get_queue_item"],
  "subjects": {
    "users": [
      {
        "jenkins_user_id": "alice",
        "deny_tools": ["jenkins_get_build_logs"],
        "deny_job_prefixes": ["secret/**"]
      },
      {
        "external_subject": "oidc|alice-sub",
        "max_result_bytes": 8192
      }
    ],
    "groups": [
      {
        "group_id": "contractors",
        "deny_tools": ["jenkins_list_artifacts"],
        "deny_job_prefixes": ["legacy/**"]
      }
    ]
  }
}
```

| Binding | Match |
|---------|--------|
| **User** `jenkins_user_id` | Case-insensitive equality with `Subject.JenkinsUserID` |
| **User** `external_subject` | Exact (trimmed) equality with `Subject.ExternalSubject` |
| **User** both keys set | **AND** (both must match) |
| **Group** `group_id` | Exact (trimmed) equality with one of `Subject.Groups` |

Group membership is **never invented**: empty or missing groups never match a
group binding. Unknown group claims simply do not match (no elevation path).

### Effective decision (most restrictive)

```text
enterprise force_read_only
  AND global overlay denials / lower-only budgets
  AND union of matching user binding denials
  AND union of matching group binding denials
```

- Deny tool/pattern lists are **unioned** (more denials only restrict).
- Budget caps (`max_result_bytes`, `max_tools_per_minute`, `max_tools_burst`) take
  the **minimum positive** value among global + matching bindings.
- **Runtime:** `max_result_bytes` is applied per request at tool dispatch
  (`effectiveBudgetForSubject`) as lower-only vs process/LiveHardMax. Per-subject
  `max_tools_per_minute` / `max_tools_burst` merge is available on
  `EffectiveDocument` but process-wide `LowerRate` at serve remains residual until
  per-subject rate maps land.
- **List-row privacy:** job/node/view/artifact/branch list filters use
  `Deny*ForSubject` (effective patterns), not global-only `Deny*FromEvaluator`.
- `force_read_only` and `mode` are **global only** — bindings cannot clear force RO.
- Group `group_id` match is **exact** after trim (case-sensitive); never invent
  membership from partial claims.
- Package: `policy.SubjectBindings`, `EffectiveDocumentForSubject`,
  `DenyOnlyEvaluator` / `ReloadableDenyOnly.EffectiveDocument`.

### Related tasks

| Task | Scope | Status |
|------|--------|--------|
| **POL-006** | Policy language + evaluator (this section) | **implemented |
| **POL-007** | SAML 2.0 SP path: assertion → subject + groups into policy (not Jenkins-as-IdP); multi-fleet **config-managed** | **implemented offline (ADR 0015, `internal/saml`, admin ACS); live IdP pin residual |
| **UI-011** | Admin Access page + BFF CRUD + `admin_rbac_*` MCP for bindings (pilot/single-host; fleet SoT = config) | **implemented pilot break-glass (2026-08-01); fleet SoT remains signed config |

**Agent non-negotiable** (root `AGENTS.md`): new RBAC controls must be designed so
they can be defined **per verified user** and **per group** — never only as an
undifferentiated global toggle without a residual task id.

Group *claims* from JWT/gateway already attribute identity (OAUTH-006 / GWY-002)
and now drive **POL-006 group bindings** when present on `Subject.Groups`.
Operators manage binding documents via overlay JSON today; admin SPA editor is
**UI-011** implemented pilot Access SPA + BFF + `admin_rbac_*` (fleet SoT still config/signed policy).

### SAML and multi-fleet configuration (POL-007 implemented offline + Keycloak lab)

**Status:** Offline SP validation + attribute map + admin ACS/session + POL-006 group bind **implemented; opt-in Keycloak SAML IdP lab **implemented (`make live-saml-*`).  
**Residual:** live Entra/Okta/ADFS browser pin; full browser ACS + Keycloak XML-DSig interop may need SP hardening; encrypted assertions; multi-pod session HA. **UI-011** Access SPA/BFF/`admin_rbac_*` is **implemented pilot (fleet SoT remains config).  
**Package:** `internal/saml` · ADR 0015 · env `JENKINS_MCP_SAML_CONFIG`.  
**Labs:** offline `make saml-lab-test`; opt-in Keycloak IdP `make live-saml-up` / `live-saml-smoke` / `live-saml-test` / `live-saml-down` (`testdata/saml-lab/`).
**Multi-fleet pack:** [fleet/multi-fleet-rollout.md](fleet/multi-fleet-rollout.md) · fixtures `testdata/fleet-pack/`.

**Does config-file management of SAML users/groups make sense for multi-fleet?**
**Yes — with a precise definition of “manage”.**

| Layer | Multi-fleet SoT | Notes |
|-------|-----------------|-------|
| **Who can authenticate** | **IdP** (Entra/Okta/ADFS) | Product does **not** provision SAML passwords or a local user table |
| **SAML SP settings** | **Versioned config** (file / gitops / signed bundle) | IdP metadata URL or static metadata path, SP entity ID, ACS, attribute map (NameID/`sub`, groups attribute), optional tenant/issuer pin |
| **IdP group → console role** (admin SSO) | **Same config plane** | e.g. map `mcp-admin-ops` → `operator`, `mcp-policy-admins` → `policy_admin`; default deny if no map match |
| **IdP group / user → MCP denials** | **Policy overlay** (`subjects.groups` / `subjects.users`, preferably **signed** MGR-001) | Same deny-only language as POL-006; roll out to fleet via config management + hot-reload / last-good |
| **Secrets** | Secret store / env / file mode 0600 | SP signing/decryption keys, client secrets — **never** in git plain text; never in audit/admin JSON |
| **Single-host SPA / MCP bindings** | **UI-011 implemented pilot break-glass | Useful for lab; **must not** be required for multi-fleet consistency (SoT = signed config) |

**Architectural rules (POL-007 / fleet):**

1. SAML is **SP + attribute map** only — Jenkins is never the SAML IdP/AS (ADR 0003 / **0015**).
2. Config **maps and restricts**; it does not invent membership. Group overage/oversize fail closed.
3. Multi-fleet prefers **immutable config + signed policy** over mutable per-pod DBs.
4. Shared-secret pilot remains when SAML `require=false`; when `require=true`, SAML session is mandatory for gated `/admin/v1/*` (except ACS/login/status). See [admin README](admin/README.md).
5. SPA Access UI / `admin_rbac_*` (UI-011 implemented pilot) stays secret-free and cannot widen enterprise `force_read_only`; refused when require-signed / trusted keys / signed bundle active.

---

## Deny-only RBAC (POL-002)

### Job pattern language (`deny_job_prefixes`, POL-002 Wave 26–32)

Patterns are **relative** Jenkins job full-name paths (`/` separates folders). Matching is
deterministic, bounded (`O(p·j)` DP; pattern depth ≤ **64** segments; brace product ≤ **32**
expanded patterns; brace nest ≤ **4**), and never executes code or network calls
(`MatchDenyJobPattern`).

| Form | Meaning | Examples |
|------|---------|----------|
| **Literal** | Exact full name **or** any child under `prefix/` (path prefix, not bare string prefix) | `secret-folder` denies `secret-folder` and `secret-folder/job-a`; does **not** deny `secret-folder-other` |
| **Trailing `/**`** | Explicit folder + all descendants; same match set as the literal base | `secret/**` ≡ `secret` for matching |
| **Single-segment `*`** | `*` matches zero or more characters **within one** path segment only | `team-*/job` denies `team-a/job` (+ children) |
| **Mid-path `**/`** (Wave 29) | Whole-segment `**` matches **zero or more** path segments | `folder/**/job`; `**/secret` |
| **Brace `{a,b[,…]}`** (Wave 30–32) | Groups expand to the cartesian product of alternatives; deny if **any** expanded pattern matches. Matching-depth `}` + top-level commas only. **Nested braces** allowed (≤ **4** nest depth). ≤ **8** alts/group, ≤ **32** expanded | `team-{blue,green}/app`; `team-{blue,{green,red}}/app`; `{a,{b,c}}-{1,2}`; `folder/**/{job-a,job-b}` |
| **Character class `[…]`** (Wave 31) | Matches **exactly one** path character (byte) at match time — not expanded to alternatives. Forms: `[abc]`, `[a-z]`, `[0-9]`, optional `[^…]` negation. May mix with literals/`*` in a segment | `team-[ab]/job`; `env-[0-9]/**`; `p-[^s]*` |
| **Combined** | `*`, mid-path `**`, braces (incl. nested), classes, optional trailing `/**` | `team-{[ab],{c,d}}/app`; `folder/**/{job-{a,b},other}` |

**Load-time validation (fail closed)** — each entry must pass `ValidateDenyJobPattern`:

| Rejected | Why |
|----------|-----|
| empty / whitespace-only | no-op misconfiguration |
| `*`, `**`, `/**`, `**/**` alone (incl. after brace expand) | overly broad |
| absolute (`/…`) or `..` | not a job full name |
| `**` embedded in a segment (e.g. `a**b`) | `**` must be a whole path segment |
| invalid braces (`{}`, unclosed, empty/single alt, `/` in alt, nest > **4**, product explosion) | bounded brace language |
| invalid classes (`[]`, unclosed `[`, inverted range `z-a`, `/` in class) | fail-closed class language |
| `?`, `\` | unsupported metacharacters |
| pattern deeper than 64 segments / expansion explosion | complexity bound |

**implemented (Wave 32):** bounded nested braces (matching-depth close, nest ≤4, same product budgets).
**implemented (Wave 31):** character classes (`[abc]` / ranges / optional `[^…]`) with match-time checks.
**implemented lite (Wave 35):** non-job resource deny patterns for **nodes** and **views** (`deny_node_names` / `deny_view_names`); same `ValidateDenyJobPattern` / `MatchDenyJobPattern` language; `Target.NodeName` / `ViewName`; reason `resource_pattern_deny`.
**implemented lite (Wave 36):** artifact path deny patterns (`deny_artifact_paths`); `Target.ArtifactPath`; call-time bind from `path` / `artifact_path`; reason `resource_pattern_deny` (`deny_artifact_path:<pat>`). List-row filter for **nodes** (`jenkins_get_nodes`).
**implemented lite (Wave 37–39):** branch resource patterns (`deny_branch_names`); Wave 37 `Target.BranchName`; Wave 38 multi-segment JobName leaf/full when BranchName empty; Wave 39 intermediate segments + slashy path suffixes (`BranchDenyCandidates`). **List privacy implemented:** `jenkins_list_views` + `deny_view_names` (Wave 38); `jenkins_list_jobs` collect+filter+repaginate for `deny_job_prefixes` / `deny_branch_names` (Wave 37/39); `jenkins_list_artifacts` page-level omit vs `deny_artifact_paths` (Wave 37); compare artifact diffs omit (Wave 39).
**Residual:** allow-lists; **Wave 40 implemented — `list_artifacts` hard-cap fetch when deny patterns live; `list_jobs` page tokens bound to live deny patterns (deny patterns in fingerprint); incomplete collect sets non-secret `Message`. **Wave 41 implemented:** `list_jobs` collect max pages operator-tunable (`--list-jobs-collect-max-pages` / `JENKINS_MCP_LIST_JOBS_COLLECT_MAX_PAGES`; default **50**, absolute **200** fail-closed via `ResolveListJobsCollectMaxPages`); large fleets may still hit the **absolute** cap → `truncated=true`; artifact cache path filter + fingerprint key; HTTP deny-anonymous loopback opt-in (`JENKINS_MCP_HTTP_DENY_ANONYMOUS` alias of require-token, **default off**). **Wave 42 implemented:** artifacts hard-cap env/flag resolve (`ResolveArtifactsHardCap` / `ArtifactsHardCap`; default **500**, absolute **2000**); nodes/views collect max pages operator-tunable (`ResolveNodesCollectMaxPages` / `ResolveViewsCollectMaxPages`; default **50**, absolute **200**); multi-sig lite offline self-check canary (`policy_multisig_lite_residual`). **Wave 43 implemented (landed):** artifact list body-bytes resolve (default **2 MiB**, absolute **8 MiB**); doctor `operator_caps_snapshot` (incl. Wave 44 body-bytes detail keys); `adapter_framework_residual` self-check item.
Mid-path `**/` and braces remain **implemented (Wave 29–32).

Implementation: `internal/policy/jobpattern.go` (`ExpandDenyJobBraces`, `NormalizeJobFullName`, character-class parse/match).

### Types

| Type | Role |
|------|------|
| `Subject` | Trusted process identity (profile + Jenkins user) |
| `Action` | Tool name + effect class |
| `Target` | Optional job full name + build number + node/view name + artifact path (call-time scope) |
| `Decision` | `allow` / `deny` + reason code + safe explanation |
| `Document` | In-memory deny set + mode + optional job / node / view / artifact path patterns |
| `DenyOnlyEvaluator` | `Evaluate(subject, action, target) Decision` |
| `ReloadableDenyOnly` | Wave 24 hot-reload wrapper; atomic last-good snapshot + mtime check |
| `DynamicForce` | Wave 25 thread-safe `EnterpriseForce`; `Set` / `SetFromOverlay` for hot-apply |
| `tools.LiveHardMax` | Wave 25/31 atomic result hard max; `SetWithinCeiling` raise/lower ≤ bootstrap ceiling |

### Modes

| Mode | Default |
|------|---------|
| `pilot` | Allow known reads unless an explicit `deny_tools` (or job/node/view/artifact pattern) matches |
| `strict` | Deny **unknown** (non-seed) tools; still apply explicit denials |

### Reason codes (stable)

`ok`, `explicit_deny`, `unknown_tool`, `subject_empty`, `subject_anonymous`,
`subject_unverified`, `subject_invalid`, `no_evaluator`, `job_pattern_deny`,
`resource_pattern_deny` (Wave 35/36 node/view/artifact)

A Jenkins **administrator** is still denied when an MCP deny rule matches — MCP
does not elevate and does not special-case admin principals.

### Job-scoped deny (POL-004 lite)

| Surface | Behavior |
|---------|----------|
| **Discovery / ListTools** | Live filter evaluates with empty `Target{}` so job/node/view/artifact pattern rules do **not** hide tools from ListTools; tool-name / subject denials do hide tools |
| **Dispatch (`addTool`)** | Before the handler: `Target` is built from tool args (`job_name` / `JobName`, seed `name` / `Name` when `JobName` still empty, optional `build_number`, `node_name` / `NodeName`, `view_name` / `ViewName` or seed `view` / `View`, `path` / `Path` or `artifact_path` / `ArtifactPath`). `deny_job_prefixes` → `job_pattern_deny`; `deny_node_names` / `deny_view_names` / `deny_artifact_paths` → `resource_pattern_deny` |
| **Job path parse (Wave 31)** | `contracts.ParseJobFullName` / tool `jobFullName` reject `.` / `..` segments, empty segments, and leading `/` (fail closed before Jenkins). |
| **Job path normalize (Wave 30)** | `Target.JobName` via `policy.NormalizeJobFullName` (same as MatchDenyJobPattern): collapse empty segments / leading `/` so `prod//secret` → `prod/secret`. Exact `.` / `..` path segments fail closed to empty JobName; a `..` *substring* inside a legal segment name (e.g. `release..2024`) stays normalizable so deny patterns still match it |
| **Match rule** | Exact full name **or** folder child / glob-lite / braces. `secret-folder` does **not** match `secret-folder-other` |
| **Adapter tools** | `jenkins_query_external_logs` and `jenkins_get_change_correlation` go through the same middleware; both require `job_name` and therefore carry a job target |
| **Tools without job fields** | Empty target → only tool-name / subject / mode rules apply |
| **Seed `name` job field** | `jenkins_get_job` binds JSON `name` (and optional `job_name` alias) into `Target.JobName`; explicit `job_name` wins when both are set |

Build number is populated on `Target` for completeness; MVP denials key on job full
name only (no per-build deny list yet).

### Non-job resource deny (Wave 35/36 lite)

| Surface | Behavior |
|---------|----------|
| **Overlay** | Optional `deny_node_names` / `deny_view_names` / `deny_artifact_paths` `[]string`; each entry validated with `ValidateDenyJobPattern` (same language as jobs) |
| **Evaluate order** | After `deny_tools` and job-prefix checks: if `Target.NodeName` non-empty and matches → `resource_pattern_deny` (`deny_node_name:<pat>`); then same for `ViewName` (`deny_view_name:<pat>`); then `ArtifactPath` (`deny_artifact_path:<pat>`, Wave 36); then `BranchName` / multi-segment JobName candidates (`deny_branch_name:<pat>`, Wave 37–39) |
| **`deny_branch_names` JobName candidates (Wave 38–39)** | When `BranchName` empty and normalized `JobName` has **≥2** segments: match each `BranchDenyCandidates` entry via `MatchDenyJobPattern` (leaf first, then intermediate segs[1..n-2], multi-segment suffixes, full path). First path segment alone is **not** a candidate. Single-segment JobName does **not** apply branch deny (root freestyle `main` stays allow unless `BranchName` set). Explicit non-empty `BranchName` is matched via its own candidates (full + leaf/suffixes when slashy); no fall-through to JobName candidates |
| **Target binding** | `policyTargetFromArgs`: `node_name`/`NodeName`, `view_name`/`ViewName`; seed `view`/`View` when `ViewName` still empty (`jenkins_list_jobs`); `path`/`Path` or `artifact_path`/`ArtifactPath` → `ArtifactPath` (never overwrites `JobName`) |
| **Artifact path normalize** | Relative only: trim + collapse `//`; absolute-like (`/` prefix, `://`) and `..` → empty target (fail closed no-match, not rewritten to relative) |
| **`jenkins_get_artifact_text` / `jenkins_inspect_artifact`** | Call-time deny when `path` matches `deny_artifact_paths` (handler never runs). Target binding collapses `.` / empty segments via the same clean rules as `SanitizeArtifactPath` so exact denies cannot be bypassed with `exact/./file` forms |
| **`jenkins_get_node` (Wave 36)** | Required `node_name` binds `Target.NodeName`; `deny_node_names` fails closed at dispatch before Jenkins is called |
| **`jenkins_list_jobs` + `view`** | Call-time deny when `view` matches `deny_view_names` (handler never runs) |
| **`jenkins_list_jobs` row filter (Wave 37/39/40 implemented)** | When live `deny_job_prefixes` and/or `deny_branch_names` non-empty: **collect** full ListJobs (paged internally up to safety cap), **drop** matching rows (`ApplyJobPolicyFilters`), recompute `total`, re-apply caller offset/limit/`page_token`. **Wave 40:** page tokens fingerprint live deny patterns (`PolicyFingerprintMaterial`); mid-session tighten fails closed on old tokens; incomplete collect forces `truncated=true` + non-secret `Message`. `policy_filtered` / `policy_omitted_count` stable across pages; denied names never listed. Empty patterns → single-page ListJobs (no multi-fetch cost). **Not** page-level-only omit. |
| **`jenkins_list_views` (Wave 38 implemented)** | List-all views; rows matching live `deny_view_names` omitted after full collect (`policy_filtered` / `policy_omitted_count`). |
| **`jenkins_list_artifacts` (Wave 37 implemented; Wave 40 implemented; Wave 41 implemented; Wave 42 implemented)** | **Wave 40:** when live `deny_artifact_paths` non-empty, fetch up to live hard cap (`ArtifactsHardCap()`, default 500), filter denied paths, re-slice to caller `max_artifacts` so denied rows do not steal page slots; sets `policy_filtered` / `policy_omitted_count`. Empty patterns → single fetch at user max (no hard-cap expansion). **Wave 41:** compare/diagnose cache path (`getCachedArtifactList`) uses the same filter path + live post-filter + policy fingerprint cache key. **Wave 42:** operator-tunable hard cap via `--artifacts-hard-cap` / `JENKINS_MCP_ARTIFACTS_HARD_CAP` (`ResolveArtifactsHardCap`; absolute **2000** fail-closed). **Wave 43 residual:** list JSON body still fixed **2 MiB** (not operator-tunable yet). |
| **`jenkins_get_nodes`** | Args are pagination only (no `node_name`) → **empty** node target at dispatch (list is not denied wholesale). **Wave 36 implemented:** after successful Jenkins fetch, rows whose `name` matches live `deny_node_names` are **omitted** (deny-only privacy); summary recomputed over kept nodes then re-paginated; `policy_filtered` / `policy_omitted_count` (integer only; denied names never listed). Empty evaluator / empty patterns → unchanged. Unauthorized (403) path unchanged. |
| **health / explain_queue** | Surface node **labels** and sample names in results; no per-node tool arg → not gated by `deny_node_names` at dispatch |
| **Hot-reload** | Node/view/artifact pattern lists reload with the Document (counts on `ReloadInfo` / status map) |

## Subject binding (POL-003)

Subjects are built from **process identity**, never from MCP tool arguments:

```go
subject := policy.NewSubject(profileID, jenkinsUserID, verified)
```

| Rule | Behavior |
|------|----------|
| Empty Jenkins user | Evaluation denies (`subject_empty`) |
| `anonymous` | Evaluation denies (`subject_anonymous`) |
| Empty profile id | Evaluation denies (`subject_invalid`) |
| `RequireVerifiedSubject` + `Verified=false` | Denies (`subject_unverified`) |

**AUTH-004 (landed):** production `serve` binds `policy.NewSubject(profileID, principal.ID, true)`
after Jenkins whoAmI, and mid-serve `IdentityReverifyGate` re-checks the bound principal
on TTL (Wave 23) with optional audit on fail-closed (Wave 28). Residual by design:
re-verify is TTL-cached (not every-call whoAmI). **Wave 29 done\***: ListTools consults
`AuthGate` — when set and `Check()` fails, discovery returns an **empty** tool list
(session death; no tool names leaked). CallTool already fails closed. Nil AuthGate
(unit tests) keeps prior policy/RO-only filter behavior. Check errors are not logged
from ListTools (no secret leak / audit flood; sticky gates may audit once on CallTool).

## Tool registry wiring

`tools.RegisterOptions` accepts optional `Policy` + `Subject` + `AuthGate`:

1. **Registration:** read tools are **always registered** when requested (Wave 28). Mutation tools: omitted by default under pilot RO (POL-001); **Wave 30** registers them when `AllowMutations` opt-in is set even if Effective RO (force), so force clear can re-expose without restart. Nil gate stays fail-closed (omit).
2. **Discovery (ListTools):** `InstallListToolsPolicyFilter` receiving middleware filters `tools/list`. **Wave 29:** if `AuthGate` is set and `Check()` fails → empty Tools (do not advertise after session revoke / reverify fail). Otherwise the **live** policy evaluator + RO gate apply: denied tools (deny_tools, empty/anonymous subject, strict unknown when evaluated) and mutations under effective RO are omitted. Job-prefix rules use empty `Target{}` and do **not** hide tools from ListTools.
3. **Dispatch:** handler middleware re-checks AuthGate, then re-evaluates policy with a call-time `Target` from args (defense in depth; job-scoped deny before handler).
4. **Budgets:** overlay `max_result_bytes` is applied via `tools.LowerHardMax` / `LiveHardMax` only.
5. **Cached / mirrored logs + L1 search:** `CheckStoreRead` re-evaluates store reads with the job resource as `Target.JobName` (LOG-004 / POL-004). **Wave 33:** `jenkins_search_logs` also calls `CheckStoreRead` on the resolved job before opening frames (same PEP as read/tail/mirror).

When `Policy` is nil (no overlay), ListTools passes through the registered set
aside from the read-only mutation filter (and AuthGate when set).

## Hot-reload (Wave 24 + Wave 25 hot-apply)

When `serve` loads an enterprise overlay or signed bundle, the deny-only evaluator
is wrapped in `policy.ReloadableDenyOnly`:

| Behavior | Detail |
|----------|--------|
| **Trigger** | On each `Evaluate`, cheap path mtime/size `Stat` after a **min interval of 5s** (not a background ticker). `Reload()` forces a load (tests / future ops). |
| **What reloads (Wave 24/35/36)** | `deny_tools`, `deny_job_prefixes`, `deny_node_names`, `deny_view_names`, `deny_artifact_paths`, `mode` (pilot/strict), document used at **dispatch**, store PEP, and **ListTools** (Wave 28 live filter) |
| **What hot-applies (Wave 25/31)** | `force_read_only` → `DynamicForce.Set`; `max_result_bytes` → `LiveHardMax.SetWithinCeiling` (raise or lower **within serve-bootstrap ceiling**; never above ceiling) |
| **What hot-applies (HOST-006)** | `max_tools_per_minute` / `max_tools_burst` → `gateway.SubjectRateLimiter.LowerRate` (**lower only**; omitted/0 keeps last live; raise needs restart with higher env bootstrap; no-op when rate limiter not wired) |
| **What hot-applies (MGR-002)** | `fleet_telemetry_force_off` → `fleet.Collector.SetForceOff` (env cannot re-enable while true; bootstrap force-off with no collector still needs restart to enable after clear) |
| **Fail closed** | Corrupt JSON, signature fail, downgrade, I/O error → **keep last-good** and log (no secrets). File deleted mid-session → keep last-good (do not silently open access). Never loaded → deny (`no_evaluator`). |
| **Logging** | Success: `deny_tools` count, `deny_job_prefixes` count, `deny_node_names` count, `deny_view_names` count, `deny_artifact_paths` count, `bundle_seq`, `signature_state`, `mode`, `force_read_only`, `fleet_telemetry_force_off`, `max_result_bytes`, `max_tools_per_minute`, `max_tools_burst`. Never signature bytes or key material. |
| **Signed bundles** | Reload re-runs full Ed25519 + last-good anti-rollback path via `LoadFromEnviron`. |

### Residuals (require process restart)

| Surface | Why |
|---------|-----|
| ~~`max_result_bytes` / tool budgets~~ | **Wave 25/31 done*** — `SetWithinCeiling` raise/lower ≤ bootstrap ceiling; raise **above** ceiling still needs restart. |
| ~~`force_read_only` dispatch~~ | **Wave 25 done** — `DynamicForce` + gate recompute; dispatch honors force flips. |
| ~~ListTools `deny_tools` hot-filter~~ | **Wave 28 done*** — read tools always register; `InstallListToolsPolicyFilter` filters `tools/list` with live evaluator. Newly denied tools disappear; newly allowed tools reappear without restart. *Dispatch deny unchanged. |
| ~~ListTools AuthGate fail-closed~~ | **Wave 29 done*** — `InstallListToolsPolicyFilter` consults `AuthGate` once per `tools/list`; Check fail → empty Tools (no name leak). Nil gate unchanged; OK + deny_tools still filters as Wave 28. *Sticky revoke stays empty; non-sticky recover re-lists. |
| ~~Mutation tools omitted at RO register (allow-mutations + force clear)~~ | **Wave 30 done*** — with `--allow-mutations` / `AllowMutations`, mutations **register** even under Effective RO; ListTools + `DenyMutation` hide/deny while force (or other RO) is on; force clear re-lists without restart. *Residual: without allow-mutations (pilot default RO) mutations stay unregistered for the process lifetime (no surprise write tools). |
| ~~Raise `max_result_bytes` after a prior lower~~ | **Wave 31 done*** — `SetWithinCeiling` can raise back up to serve-bootstrap ceiling; above ceiling still restart. |
| Raise subject rate above serve-bootstrap env | **HOST-006 implemented lower-only** — `LowerRate` never raises; restart with higher `JENKINS_MCP_SUBJECT_RATE_*` to raise bootstrap. Process rate ceilings not overlay-tunable. Admin SPA Policy editor can lower overlay `max_tools_*` (policy_admin). |
| ~~**L1 search historical hits**~~ | **Wave 33 done*** — single-generation `jenkins_search_logs` re-checks `deny_job_prefixes` **and** `CheckStoreRead` on the resolved job before any frame scan; mid-session tighten denies on next call. *Not multi-job fan-in (search is one generation). |

## Example overlay (read-only fleet, deny log tools + secret jobs)

```json
{
  "version": 1,
  "force_read_only": true,
  "mode": "pilot",
  "deny_tools": ["jenkins_get_build_logs", "jenkins_get_build_log_tail"],
  "deny_job_prefixes": ["secret-folder", "hr/payroll"],
  "max_result_bytes": 65536
}
```

Cursor config remains secret-free; point the process at the overlay with env:

```json
{
  "mcpServers": {
    "jenkins": {
      "command": "/usr/bin/jenkins-mcp",
      "args": ["serve", "--profile", "corp", "--stdio"],
      "env": {
        "JENKINS_MCP_READ_ONLY": "true",
        "JENKINS_MCP_POLICY_FILE": "/etc/jenkins-mcp/policy/overlay.json"
      }
    }
  }
}
```

## Residual / follow-ups

| Item | Task |
|------|------|
| Signed policy bundles (Ed25519 envelope) | **MGR-001 done (MVP + multi-sig lite + REQUIRE_SIGNED pin)** — full threshold crypto / gateway push / HSM residual |
| Verified Jenkins principal (`Verified=true`) | **AUTH-004 done*** — serve-time whoAmI bind + mid-serve re-verify + Wave 28 audit + **Wave 29** ListTools AuthGate empty-list; residual: TTL window until next re-verify |
| ListTools AuthGate session death | **Wave 29 done*** — discovery empty when `AuthGate.Check` fails; CallTool already fail-closed |
| Multi-layer PEPs (handler target, network classifier, store) | **POL-004 lite done** — call-time job `Target` + `deny_job_prefixes`; network/store PEPs earlier. Residual: richer ACL language; adapter-specific PEPs beyond shared middleware |
| Job/folder pattern language completeness | **Wave 26–32 done*** — mid-path `**/` + `{a,b}` braces (incl. nested ≤4) + character classes `[…]` |
| Non-job resource patterns (node/view/branch) | **Wave 35–42 implemented — call-time + list filters for **nodes** (`get_nodes` + operator collect max pages), **jobs** (`list_jobs` collect+filter + policy-bound page tokens + incomplete `Message` + operator collect max pages), **views** (`list_views` + operator collect max pages), **artifacts** (hard-cap list filter + compare diffs + cache filter + operator hard-cap resolve); JobName `BranchDenyCandidates` + slashy BranchName for `deny_branch_names`. **Residual honesty:** large fleets may hit collect **absolute** caps (jobs/nodes/views **200** pages) → `truncated=true`; HTTP deny-anonymous loopback **opt-in** (default off). |
| Artifact path resource patterns | **Wave 36–43 implemented — list_artifacts hard-cap fetch+filter when deny patterns live + call-time + **compare_builds path diffs** omit denied paths + **cache path** (`getCachedArtifactList` + `ArtifactPolicyFingerprintMaterial`) + operator hard-cap resolve (`ResolveArtifactsHardCap` / `ArtifactsHardCap`; default 500, absolute 2000) + **Wave 43** list JSON body-bytes resolve (`ResolveArtifactsListBodyBytes`; default **2 MiB**, absolute **8 MiB**) — `deny_artifact_paths` + `Target.ArtifactPath` + Evaluate `resource_pattern_deny` (`deny_artifact_path:<pat>`) + `path`/`artifact_path` binding on artifact tools. Absolute body/hard-cap ceilings still apply. |
| Branch name patterns (tools without `branch_name`) | **Wave 38–39 done* lite** — multi-segment `JobName` leaf + intermediate + path suffixes + full when `BranchName` empty; slashy `BranchName` leaf/suffixes; single-segment JobName does not apply branch deny. List-row omit of `kind=branch`/`matrix_child` on `jenkins_list_jobs` is Wave 37/39 collect+filter (not page-level only) |
| Hot-reload of deny tools / job prefixes | **Wave 24 done** — `ReloadableDenyOnly`; see [Hot-reload](#hot-reload-wave-24--wave-25-hot-apply) |
| force_read_only + max_result_bytes on reload | **Wave 25/31 done*** — `DynamicForce` + `SetWithinCeiling` via `OnSuccess` |
| ListTools / discovery `deny_tools` hot-filter | **Wave 28 done*** — live `tools/list` filter; raise budget after lower still restart |
| Mutation tools register for force-RO hot-clear | **Wave 30 done*** — allow-mutations registers under force RO; ListTools/DenyMutation live; residual: no allow-mutations ⇒ never register mutations |
| MUT-001 confirm cooldown + token TTL offline canary | **Wave 48** — `mutation_confirm_cooldown_residual` in `RunSecuritySelfCheck` proves DefaultTokenTTL/DefaultConfirmCooldown and fail-closed re-confirm deny offline; residual: multi-tenant gateway mutations not covered |
| Raise budget above serve ceiling | **Wave 37–38** — serve `--hard-max-bytes` / env bootstrap; **AbsoluteMaxHardMaxBytes 64 MiB** fail-closed; overlay only lowers; re-serve to raise bootstrap (≤64 MiB) |
| L1 log search after mid-session policy change | **Wave 33 done*** — `enforceSearchLogsJobPolicy` resolves the generation job (meta only), then tool `Evaluate` **and** `CheckStoreRead` before `Search`/frame open; either deny wins (fail closed). Covers `job_name`, `generation_id`, and smuggle cases. *Residual: none for single-generation L1 search; multi-job fan-in is N/A (engine is one generation). Other multi-job tools (e.g. mirror related) already re-check per job. |
| Conformance / adversarial suite | **POL-005 MVP + Wave 40–44 implemented — `internal/policy/conformance_test.go` + `wave40`/`wave42`–`wave44_conformance_test.go` (deny-only Document canaries); tools `pol_conformance_test.go` + `wave40`–`wave44_conformance_test.go` hard-assert hard-cap list_artifacts, body-bytes resolve, PolicyFingerprintMaterial, incomplete list_jobs Message, collect max pages, HTTP RequireToken; diagnostics hard-assert `policy_multisig_lite_residual`, `operator_caps_snapshot` (incl. body-bytes keys), `adapter_framework_residual`, `adapter_allowlist_provenance_lite`; mcpserver hard-assert `ResolveHTTPMaxBodyBytes` / `AbsoluteMaxBodyBytes` (16 MiB). Residual: live disposable Jenkins matrix (TST-001 live). |

### L1 search job re-eval (Wave 19 + Wave 33 store PEP)

| Path | Behavior |
|------|----------|
| **Tools with `job_name`** | Call-time middleware builds `Target` from args; `deny_job_prefixes` apply before handler |
| **Tools without `job_name`** | Empty target → only tool-name / subject / mode rules apply (except L1 search generation path below) |
| **L1 log search (`jenkins_search_logs`)** | Before scanning frames, resolve generation (meta only via `search.Engine.Resolve`) and re-evaluate **both** tool `Evaluate` (`deny_job_prefixes` / `deny_tools` for `jenkins_search_logs`) **and** `CheckStoreRead` (store PEP / `store_cached_read`) on the **resolved job**. Covers `generation_id`-only calls and smuggle cases where `generation_id` wins over a public `job_name`. Either PEP deny → `policy_denial` with **no** frame open / no `Search` call |
| **Mirrored log read/tail** | `CheckStoreRead` re-checks job deny before serving local frames |
| **Legacy `name` job field** | Prefer `job_name`; where legacy `name` is still accepted, target extraction uses the same job-string path |

### Gateway subject source (GWY-002)

When `serve --gateway` / `gatewayMode` / `JENKINS_MCP_GATEWAY_MODE` is on,
`gateway.BindSubjectFromEnviron` builds `policy.Subject` from env (plus whoAmI principal):

| Env | Maps to |
|-----|---------|
| `JENKINS_MCP_GATEWAY_SUBJECT` | `ExternalSubject` |
| `JENKINS_MCP_GATEWAY_TENANT` | `Tenant` (required) |
| `JENKINS_MCP_GATEWAY_WORKLOAD` | `WorkloadID` (required) |
| `JENKINS_MCP_GATEWAY_JENKINS_PRINCIPAL` or whoAmI | `JenkinsUserID` |


### Offline self-check (Wave 39 + Wave 40 light polish)

Pure `internal/policy` checks (no tools import cycle); secret-free bool details only:

| Item | What it proves |
|------|----------------|
| `listfilter_deny_only_residual` | `NameDeniedByPatterns` deny-only empty→false; **list-row helper copy-out** present for nodes / jobs / views / artifacts / branches (`Deny*FromEvaluator` nil/empty → nil; live patterns independent of Document) |
| `policy_resource_deny_residual` | `DocumentFromOverlay` copies `deny_view_names` / `deny_artifact_paths` / `deny_branch_names` / `deny_node_names` without elevating; empty overlay → pilot empty denials |

Wave 40 list privacy (hard-cap `list_artifacts`, policy-bound `list_jobs` page tokens, incomplete `Message`) is proven in **tools-layer** unit/MCP/conformance tests (`listArtifactsWithPolicyFilter`, `PolicyFingerprintMaterial`, collect incompleteness) — not re-asserted in pure `internal/policy` self-check (no tools import cycle).

### Wave 40 list privacy (implemented)

- `list_artifacts`: hard-cap fetch when `deny_artifact_paths` live, filter, then re-slice to caller `max_artifacts` (`listArtifactsWithPolicyFilter`).
- `list_jobs` collect path: page_token fingerprint includes sorted live `deny_job_prefixes` / `deny_branch_names` (`PolicyFingerprintMaterial`); incomplete collect sets non-secret `Message`.

### Wave 41 (historical)

- Artifact cache path: `getCachedArtifactList` applies `deny_artifact_paths` via `listArtifactsWithPolicyFilter` + live post-filter; cache keys use `ArtifactPolicyFingerprintMaterial` (compare/diagnose).
- `list_jobs` collect max pages: operator-tunable via `--list-jobs-collect-max-pages` / `JENKINS_MCP_LIST_JOBS_COLLECT_MAX_PAGES` (`ResolveListJobsCollectMaxPages`; default 50, absolute 200 fail-closed).
- HTTP deny-anonymous loopback: `JENKINS_MCP_HTTP_DENY_ANONYMOUS` opt-in alias of `--http-require-token` / `JENKINS_MCP_HTTP_REQUIRE_TOKEN` (same `RequireToken` path; **default off**).

### Wave 42 (historical)

- Artifacts hard-cap resolve: env/flag raise of list hard cap (`--artifacts-hard-cap` / `JENKINS_MCP_ARTIFACTS_HARD_CAP` via `ResolveArtifactsHardCap`; default **500**, absolute **2000** fail-closed; live `ArtifactsHardCap()`).
- Nodes/views collect max pages: operator-tunable like list_jobs (`ResolveNodesCollectMaxPages` / `ResolveViewsCollectMaxPages`; default **50**, absolute **200**).
- Multi-sig self-check: offline `policy_multisig_lite_residual` canary (see below).

### Wave 43 (historical)

- Artifact list body bytes resolve: `ResolveArtifactsListBodyBytes` / `jenkins.SetArtifactListBodyBytes` (default **2 MiB**, absolute **8 MiB** fail-closed).
- Doctor / offline `operator_caps_snapshot` item: secret-free snapshot of live process caps (collect pages, hard max, artifacts hard cap).
- Adapter framework residual self-check item (`adapter_framework_residual`): offline canary present (default-off + production-backend residual honesty).

### Wave 44 (historical)

- Operator caps body-bytes fields: `artifacts_list_body_bytes` / `default_artifacts_list_body_bytes` / `absolute_max_artifacts_list_body_bytes` in `operator_caps_snapshot`.
- Adapter allowlist Ed25519 provenance lite: `LoadAllowlistFileWithKeys` + env `JENKINS_MCP_ADAPTER_ALLOWLIST_TRUSTED_KEYS`; self-check `adapter_allowlist_provenance_lite` (cosign/SBOM/HSM residual).
- HTTP MaxBodyBytes resolve: `ResolveHTTPMaxBodyBytes` / `--http-max-body-bytes` / `JENKINS_MCP_HTTP_MAX_BODY_BYTES` (default **4 MiB**, absolute **16 MiB** fail-closed).


### Wave 45 (historical)

- Adapter allowlist MinSignatures dual-control lite: `ResolveAllowlistMinSignatures` / `--adapter-allowlist-min-signatures` / `JENKINS_MCP_ADAPTER_ALLOWLIST_MIN_SIGNATURES` (default **1**, absolute **16**); multi-sig requires ≥N distinct trusted key_ids.
- Operator caps: HTTP body constants (4/16 MiB) + identity re-verify TTL bounds (10s–30m) in `operator_caps_snapshot`.
- Offline NET-003 self-check: `jenkins_resilience_residual` (GET/HEAD retry + circuit; POST never auto-retry; live chaos residual).

### Offline multi-sig self-check (Wave 42 implemented)

- `policy_multisig_lite_residual` — proves multi-sig lite MinSignatures 2-of-2 verify + 1-of-2 fail-closed; details mark `residual_true_threshold=false` and `residual_hsm=false` (true t-of-n / HSM not implemented).
