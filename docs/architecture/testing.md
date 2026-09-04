# Architecture — testing and qualification

```mermaid
flowchart TB
  UT[Unit / contract make test] --> Gate[Merge gate]
  Race[Race Ubuntu] --> Gate
  Vuln[govulncheck] --> Gate
  SPA[Admin SPA admin-ui-check] --> Gate
  Labs[Free Docker labs opt-in] --> Qual[Product qualification]
  Site[Customer Entra / prod Jenkins] --> Ops[Optional operator validation]
```

| Layer | Required for merge? |
|-------|---------------------|
| `make test` / lint / build / package / vuln | Yes (CI job `lint-test-build` + `govulncheck`) |
| `make admin-ui-check` | Yes (CI job `admin-ui`; Node 22; compiles `web/admin` TSX) |
| Free labs | When changing integration boundaries |
| Customer production pin | No — optional |

See [../testing/qualification.md](../testing/qualification.md).
