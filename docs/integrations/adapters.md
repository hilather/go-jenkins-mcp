# Integration — adapter framework

**Support status:** Opt-in supported · built-ins deny-by-default

## Setup

```bash
jenkins-mcp serve --profile corp --enable-adapter=ext-logs \
  --adapter-ext-logs-backend=mock
```

Unsigned third-party IDs require `--adapter-allowlist`.

| Adapter ID | Status |
|------------|--------|
| `clock` / `noop` | Stub/demo |
| `ext-logs` | Opt-in; mock backend free-lab; real SaaS residual |
| `work-items` | Opt-in; metadata-oriented |
| `otel-export` | Opt-in; mock backend |
| `otel-correlate` | Opt-in |

## Verification

```bash
go test ./internal/adapter/ -count=1
```

Doctor residual canaries for deny-by-default registry.

## Security

No Jenkins client in adapter host by default; budgets; allowlist signatures optional dual-control.

## Rollback

Remove `--enable-adapter` flags; restart.

## Related

- [../adapters/README.md](../adapters/README.md)
