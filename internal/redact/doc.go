// Package redact strips secrets, tokens, cookies, control sequences, and
// sensitive parameters from strings destined for logs, errors, MCP results,
// and support bundles (SEC-002 / SEC-003).
//
// Layered redaction (architecture §14.3):
//  1. Exact known-secret matchers (SetKnownSecrets) — session tokens, etc.
//  2. Structured field redaction for maps/JSON (sensitive parameter names).
//  3. Built-in detectors (AWS, PEM, JWT, basic/bearer, connection strings,
//     GitHub/GitLab tokens, common password/token forms).
//  4. Enterprise-configured patterns (EnterprisePatterns hook) — optional
//     JSON file via JENKINS_MCP_REDACT_PATTERNS_FILE (ApplyEnterprisePatternsFromEnviron
//     at serve start; invalid file fails closed).
//  5. Bare high-entropy hex / base64url (CategoryBareToken) — unlabeled
//     tokens that slip Bearer / api_token= prefixes (KD-004 residual).
//
// Apply redaction after evidence selection and before MCP serialization.
// Budget truncation runs after redaction. Return category counts, never values.
// Never log match samples or secret material from enterprise patterns.
//
// SEC-003: StripControlSequences removes ANSI CSI/OSC and unsafe controls;
// SanitizeForModel combines control strip + RedactText for model-facing text.
// Label untrusted build excerpts with Untrusted / content_kind metadata.
//
// KD-004: NewWriter wraps an io.Writer with RedactText (serve log.SetOutput).
// Writer line-buffers incomplete data after the last '\n' so secrets split
// across Write chunks are redacted once the line completes (or on Flush/Close).
// On size force-flush (pending > 256 KiB without '\n'), a 256-byte carry tail
// is retained so secrets straddling that boundary rejoin on the next Write.
// Bare-token heuristic thresholds and residual FP notes live in bare.go.
package redact
