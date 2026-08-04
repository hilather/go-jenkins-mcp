# Feature — mutations

**Support status:** Opt-in supported (default **off**)

## Setup

```bash
jenkins-mcp serve --profile corp --stdio --allow-mutations
# --read-only / force_read_only still wins for execute
```

Preview → confirmation token → execute. Agents must not invent tokens.

## Verification

With flag off: mutate tools absent or denied.  
With flag on: preview returns token; confirm executes once; audit events emit.

## Security

Allowlists, cooldown, audit. See user guide mutations section and tool-contracts.

## Rollback

Remove `--allow-mutations`; restart serve.
