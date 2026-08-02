# Cache pins CLI (ARC-007 track)

| Field | Value |
|-------|--------|
| **Task** | ARC-007 (pin surface / Wave 25) |
| **Status** | CLI + Meta APIs implemented |
| **Store** | `store.Meta` `PinGeneration` / `UnpinGeneration` / `PinPack` / `UnpinPack` / `ListPins` |

## Operator commands

```bash
jenkins-mcp cache pin generation --profile <id> --generation <id>
jenkins-mcp cache unpin generation --profile <id> --generation <id>
jenkins-mcp cache pin pack --profile <id> --pack <id>
jenkins-mcp cache unpin pack --profile <id> --pack <id>
jenkins-mcp cache pins --profile <id> [--json]
```

| Rule | Detail |
|------|--------|
| **Profile** | `--profile` required; missing profile fails closed |
| **Data dir** | Must already exist (serve or prior cache open); pin CLI does **not** create an empty tree |
| **Generation id** | SQLite `log_generations.id` (positive int) |
| **Pack id** | Single path segment (no `/`, `\`, or `..`) |
| **List output** | Text or JSON: `kind`, `target_id`, `pinned_at` only — no secrets, no token material |
| **Idempotency** | Re-pin refreshes `pinned_at`; unpin of absent pin is success |

## Effect

- Quota eviction (`QuotaManager`) skips pinned generations/packs.
- L1 release / packing maintenance respects pins (see `store.Releaser`, `app.Maintainer`).
- Pins are durable rows in profile `metadata.sqlite` (`pins` table).

## Residuals

| Residual | Notes |
|----------|--------|
| **Manual delete-all** | Pins do **not** protect against `rm -rf` of the profile data directory, profile remove cleanup, or wiping XDG data |
| **Existence check** | Pin does not require the generation/pack row or pack file to exist (id-level pin) |
| **MCP tool surface** | Pin/unpin via MCP tools not in this track (CLI operator path only) |
| **Full ARC-007** | Per-outcome retention knobs and low-disk probe on offline CLI remain broader residual; dry-run plan + confirm-gated apply are in [`eviction.md`](eviction.md) |

Related: eviction CLI [`eviction.md`](eviction.md); unified operator guide [`caching.md`](../caching.md).

## Verify

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./cmd/jenkins-mcp/ -count=1 -run CachePin
make test && make lint
```
