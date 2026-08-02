# Fleet shared policy example

`overlay.json` is a **plain pilot** overlay with POL-006 `subjects`.

## Sign for fleet hosts (never commit private keys)

```bash
# Generate (once, offline / HSM residual)
openssl genpkey -algorithm Ed25519 -out fleet-policy-private.pem
openssl pkey -in fleet-policy-private.pem -pubout -out testdata/fleet-pack/keys/fleet-policy-public.pem

export PATH="$HOME/.local/go/bin:$PATH"
jenkins-mcp policy sign \
  --file testdata/fleet-pack/policy/overlay.json \
  --key fleet-policy-private.pem \
  --key-id fleet-2026 \
  --out /tmp/overlay.bundle.json

# On each fleet host:
#   JENKINS_MCP_POLICY_FILE=/path/overlay.bundle.json
#   JENKINS_MCP_POLICY_TRUSTED_KEYS=/path/keys
#   JENKINS_MCP_REQUIRE_SIGNED_POLICY=1
```

Public keys may live under `testdata/fleet-pack/keys/` (see that README).  
Private keys **must not** be committed.
