// Package diagnostics provides local support and triage helpers:
//
//   - DIAG-001: deterministic error extraction and signatures from build logs
//   - OPS-001: doctor / cache status / safe support-bundle surfaces without leaking secrets
//   - OPS-001 Wave 23: support-bundle offline members (security self-check, release-evidence
//     lite version/runtime, RS qualification summary; optional LogSample → signature hashes only)
//   - OPS support-bundle residual lite: always-on gateway-residual-status.json
//     (BuildGatewayResidualStatus + sanitize; residual honesty even when doctor fails)
//   - ARC-008: cache verify / repair reports (pack/entry/checksum/catalog/index kinds)
//
// Parsers are conservative; doctor and support bundles never emit tokens, cookies,
// or private keys. Support bundles exclude full logs, raw log samples, and artifact
// bodies by design.
package diagnostics
