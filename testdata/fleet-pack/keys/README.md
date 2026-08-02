# Trusted public keys (example)

Place **public** Ed25519 PEMs here for local labs.

- Do **not** commit private signing keys.
- Production: distribute public keys via org secret store / gitops; sign with HSM residual.

Generate a lab keypair:

```bash
openssl genpkey -algorithm Ed25519 -out /tmp/fleet-policy-private.pem
openssl pkey -in /tmp/fleet-policy-private.pem -pubout -out fleet-policy-public.pem
# Keep private key outside the repo
```
