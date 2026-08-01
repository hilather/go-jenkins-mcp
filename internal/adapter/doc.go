// Package adapter provides a capability-scoped integration adapter framework
// (INT-001 MVP).
//
// Design principles:
//
//   - Deny by default: no adapters load unless explicitly enabled and approved.
//   - Auth isolation: adapters do not receive a Jenkins client by default;
//     only narrow optional interfaces may be injected later (INT-002+).
//   - Core independence: the Jenkins MCP path has no hard dependency on
//     optional adapters (see internal/depgraph tests).
//   - Panic isolation: Start/Stop/Health and Call recover panics so a bad
//     adapter cannot crash the core process.
//   - Budgets: optional per-adapter token-bucket rate limits.
//
// Built-in factories:
//   - "noop", "clock" — framework examples
//   - "otel-correlate" — INT-002 lifecycle marker (build-metadata correlation; no OTLP)
//   - "otel-export" — INT-002 metadata-only export framework stub (noop/mock/optional HTTPS JSON; no OTLP protobuf)
//   - "ext-logs" — INT-003 external log query framework (noop/mock/optional HTTPS JSON)
//   - "work-items" — INT-004 ticket lookup stub (refs only; no network)
//
// Production OTLP / Splunk / ELK / Jira SaaS clients remain residual.
//
// Allowlist provenance (Wave 44–45 lite): optional Ed25519 verification of the
// --adapter-allowlist file when JENKINS_MCP_ADAPTER_ALLOWLIST_TRUSTED_KEYS is
// set. Multi-sig dual-control lite via MinSignatures (env
// JENKINS_MCP_ADAPTER_ALLOWLIST_MIN_SIGNATURES / flag
// --adapter-allowlist-min-signatures; default 1; set 2 for 2-of-N distinct
// trusted keys). Cosign / SBOM / HSM / true t-of-n threshold crypto remain residual.
package adapter
