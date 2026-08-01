# internal/jenkins

Jenkins HTTP API client for go-jenkins-mcp. **Must not import MCP packages** (FND-004).

## Network stack (NET-001 / NET-002 / NET-003 / NET-004)

| Layer | Behavior |
|-------|----------|
| **Origin pin (NET-001)** | Credentials only to normalized base origin; cross-origin redirects refused |
| **Shared transport (NET-002)** | One pooled `http.Transport` per client/profile via `NewHTTPClients` / `WithTransport` |
| **Body limits (NET-003)** | JSON/API paths: default **32 MiB** (`MaxJSONBodyBytes`) via `limitedBody`; operator `--max-json-body-bytes` / `JENKINS_MCP_MAX_JSON_BODY_BYTES` (absolute **128 MiB** fail-closed) |
| **Log paths (LOG-001)** | Progressive reads use request length + early close; **not** the MaxJSONBodyBytes JSON cap |
| **Retries (NET-003)** | **GET/HEAD only**; exponential backoff + full jitter; honors bounded `Retry-After` |
| **No mutation retry** | **POST** build trigger / stop never auto-retried |
| **Throttle** | Optional `MaxConcurrent` semaphore (0 = unlimited) |
| **Circuit breaker** | Opens after N consecutive 5xx/transport failures; `Client.CircuitState()`; open transitions → `MetricsHook.IncCircuitOpenEvent` (`jenkins_circuit_open_events_total`) |
| **Custom CA (NET-004)** | System trust + optional `CABundlePath` / `CABundlePEM` append |
| **Proxy (NET-004)** | Env `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` by default; profile/`ProxyURL` override; `NoProxy` bypass; `direct`/`none` disables |
| **mTLS (NET-004)** | Optional `ClientCertFile` + `ClientKeyFile` PEM path references (never log key material) |
| **TLS diagnostics** | `FormatTLSError` explains chain/hostname failures without promoting permanent skip-verify |

### Construction

```go
// Production defaults (pooled transport + resilience; system TLS trust; env proxy).
c := jenkins.NewClient(baseURL, user, token)

// Custom CA / proxy / mTLS (NET-004):
cfg := jenkins.DefaultTransportConfig()
cfg.CABundlePath = "/etc/ssl/corp-ca.pem"
cfg.ProxyURL = "http://proxy.corp:8080"
cfg.NoProxy = []string{"localhost", ".corp.internal"}
cfg.ClientCertFile = "/etc/ssl/client.crt"
cfg.ClientKeyFile = "/etc/ssl/client.key"
c, err := jenkins.NewClientWithTransport(baseURL, user, token, cfg)

// Or compose:
c := &jenkins.Client{URL: baseURL, User: user, Token: token}
_, err = c.WithTransport(cfg)
c.WithResilience(jenkins.DefaultResilienceConfig())
```

CLI / profile wiring (`cmd/jenkins-mcp`):

- Profile fields: `caBundlePath`, `proxyURL`, `noProxy`, `clientCertFile`, `clientKeyFile` (paths only; absolute).
- Serve flags: `--ca-bundle`, `--proxy` (override profile); never persist `insecureSkipVerify`.
- Login and serve use the same transport config so whoAmI works against enterprise CAs.

`CallJenkins` / progressive log helpers use the wired client. Tests may inject `httptest` clients and still get resilience defaults on first request unless `WithResilience` is set.

### TLS verification policy (NET-004)

- **Default:** full certificate verification (TLS 1.2+). Never a silent production skip.
- **Custom CA:** append to the system pool; wrong CA fails closed.
- **Diagnostic insecure TLS:** only when **both** `TransportConfig.DiagnosticInsecureTLS` is set (e.g. serve `--diag-insecure-tls`) **and** process env `JENKINS_MCP_DIAG_INSECURE_TLS=1`. Loudly logged. Cannot be enabled from profile JSON alone (`ApplyInsecureTLSGate`).
- Operator-facing TLS failures: use `FormatTLSError` — fix CA/hostname; do not leave verification disabled.

### Gzip (opt-in)

Default **`AcceptGzip: false`**. Transparent `net/http` gzip is disabled so progressive log wire accounting stays honest and compression is explicit.

Set `TransportConfig.AcceptGzip = true` only after controller/proxy interoperability checks. When enabled, wire vs decoded bytes are counted separately via `ByteCounters` (telemetry hook; no body content retained).

### Residuals

- Encoded-wire size is not independently hard-capped yet (decoded 32 MiB bound still stops compression-bomb growth of application buffers).
- Request/byte/error/circuit-open counters: optional `MetricsHook` on `Client` (OBS-001 Wave 24–27; adapter in tools/cmd — this package does not import telemetry). Residual: compression ratio, decoder CPU, latency histograms, circuit gauges / half-open+closed transition counters.
- Per-host rate limit beyond concurrency semaphore is not implemented (optional NET-003).
- OS certificate-store client cert selection (beyond PEM path references) deferred; keyring-held client keys later if needed.
