# Architecture — integrations

**Support status:** Opt-in supported (built-in adapters deny-by-default)

```mermaid
flowchart LR
  Serve[jenkins-mcp serve] -->|--enable-adapter| Reg[adapter.Registry]
  Reg --> Ext[ext-logs]
  Reg --> WI[work-items]
  Reg --> OTel[otel-export / correlate]
  Ext -->|optional HTTPS| Backend[External backend]
```

Adapters receive a restricted host surface — **no** Jenkins client or keyring by
default. See [../integrations/adapters.md](../integrations/adapters.md).
