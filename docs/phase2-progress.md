# Phase 2 progress (waves 6–53)

Enterprise Jenkins MCP through Waves 26–53 (resource deny, list privacy,
operator caps, allowlist provenance, body/retry/circuit/concurrent/backoff
resolves, soft TargetBytes absolute 64 MiB + clamp log honesty, survey/diagnose
operator_caps, fleet ForceOff, LKG residual, mutation cooldown/rate/token-TTL
operator resolve, circuit open duration, cache maintenance bounds, NET-001
origin pin pure canary).

## Wave 53 highlights

| Track | Task | Status | Notes |
|-------|------|--------|-------|
| **A** | TokenTTL operator resolve | Done* | Default **2m**; min **10s**; abs **15m**; `--mutation-token-ttl` / `JENKINS_MCP_MUTATION_TOKEN_TTL`; process live `SetTokenTTL` |
| **B** | operator_caps min/abs mutation honesty | Done* | ConfirmCooldown min/abs + MaxPreviews abs + TokenTTL min/abs offline integers |
| **C** | SoftTargetClampApplied log honesty | Done* | Serve logs `target_bytes_clamped` / `target_bytes_resolved` when resolve soft > bootstrap hard |
| **D** | residual docs + Wave 53 conformance | Done* | Wave 52 hard asserts + Wave 53 hard paths after merge |

## Wave 52 highlights

| Track | Task | Status | Notes |
|-------|------|--------|-------|
| **A** | ConfirmCooldown operator resolve | Done* | Default **5s**; min **1s**; abs **5m**; `--mutation-confirm-cooldown` / `JENKINS_MCP_MUTATION_CONFIRM_COOLDOWN`; process live `SetConfirmCooldown` |
| **B** | operator_caps min/abs backoff + mutation defaults | Done* | `min_*` / `absolute_max_*` backoff ms + offline mutation cooldown/rate/TTL constants |
| **C** | MaxPreviewsPerMinute operator resolve | Done* | Default **30**; abs **300**; `--mutation-max-previews-per-minute` / env; 0→default (not unlimited) |
| **D** | residual docs + Wave 52 conformance | Done* | Wave 51 hard asserts + Wave 52 hard paths after merge |

## Wave 51 highlights

| Track | Task | Status | Notes |
|-------|------|--------|-------|
| **A** | InitialBackoff + MaxBackoff resolve | Done* | Initial default **100ms** min **10ms** abs **2s**; Max default **5s** min **100ms** abs **1m**; max ≥ initial fail-closed; `--initial-backoff` / `--max-backoff` |
| **B** | operator_caps survey/diagnose hard ceilings | Done* | Offline `default_*` / `hard_*` survey+diagnose package constants (secret-free integers) |
| **C** | AbsoluteMaxTargetBytes → AbsoluteMaxHardMaxBytes | Done* | Soft target absolute **64 MiB**; still clamped to live hard max at enforce |
| **D** | residual docs + Wave 51 conformance | Done* | Wave 50 hard asserts + Wave 51 hard paths after merge |

## Wave 50 highlights

| Track | Task | Status | Notes |
|-------|------|--------|-------|
| **A** | MaxConcurrent resolve | Done* | Default **0** unlimited; absolute **256**; `--max-concurrent` / `JENKINS_MCP_MAX_CONCURRENT` |
| **B** | operator_caps absolute concurrent + backoff honesty | Done* | `absolute_max_concurrent`, initial/max backoff ms |
| **C** | jenkins_origin_pin_residual | Done* | NET-001 NormalizeBaseURL+SameOrigin pure offline; live reverse-proxy residual |
| **D** | residual docs + Wave 50 conformance | Done* | Wave 49 hard asserts + Wave 50 hard paths after merge |

## Wave 49 highlights

| Track | Task | Status | Notes |
|-------|------|--------|-------|
| **A** | CircuitOpenDuration resolve | Done* | Default **15s**; min **1s**; absolute **5m** |
| **B** | operator_caps open-duration min/abs + max concurrent honesty | Done* | min/absolute open; concurrent 0 unlimited |
| **C** | Cache maintenance interval absolute resolve | Done* | Default **5m**; **30s–1h** |
| **D** | docs + conformance | Done* | Wave 48 hard asserts |

## Verify

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make test
make lint
```

## Residuals

- Live Entra / jwt-auth-filter lab / AgentCore Obtain production pin
- Cursor product binary host CI
- Raising serve-bootstrap hard max still needs **re-serve** (≤ 64 MiB absolute)
- Without `--allow-mutations`, mutations never register for process lifetime
- Loopback HTTP without require-token / deny-anonymous still open by **default** (prefer stdio)
- True t-of-n threshold crypto / production HSM
- Production OTLP / Splunk / ELK / Jira SaaS adapter clients
- Adapter allowlist cosign / SBOM / HSM supply-chain provenance
- Live multi-controller chaos / network matrix
- Live reverse-proxy path-prefix origin pin matrix (pure pin helpers Done*)
- Signed-policy fleet enterprise pin (ForceOff **lite** Done*)
- LKG auto-install / binary rollback (operator-owned)
- Soft TargetBytes absolute lifted to **64 MiB** (`AbsoluteMaxHardMaxBytes`) Wave 51 Track C; still clamped to live hard max at enforce; resolve may yield target > bootstrap hard — serve clamps after Normalize and logs `target_bytes_clamped` / `target_bytes_resolved` (Wave 53 Track C). Overlay re-clamp not separately flagged.
- Production multi-tenant gateway mutation isolation
- Absolute collect/body/hard-cap / HTTP / MaxJSON / retry / circuit / concurrent / backoff ceilings still apply
- Mutation ConfirmCooldown / MaxPreviews / TokenTTL operator resolve Done* (Waves 52–53); library Config negative still disables cooldown / unlimited previews for tests only; operator path cannot set 0/disable; ConfirmCooldown vs TokenTTL independent (serve does not fail closed when cooldown ≥ TTL)
- Commit + tag when requested
