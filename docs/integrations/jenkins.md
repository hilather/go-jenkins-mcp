# Integration — Jenkins controller

**Support status:** Supported · Free-lab validated (`testdata/jenkins-compose`)

## Setup

Profile URL → personal login → HTTPS client in `internal/jenkins`.

## Verification

`jenkins-mcp status` / doctor; RO tools against disposable lab:

```bash
make live-jenkins-test
```

## Security

TLS verification; no secrets in logs; treat job data as untrusted.

## Limits

Client timeouts, progressive log budgets, artifact path sanitization.

## Troubleshooting / rollback

Doctor checks; logout; remove profile. Lab: `make live-jenkins-down`.
