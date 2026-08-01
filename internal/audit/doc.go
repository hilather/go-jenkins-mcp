// Package audit records security-relevant events (auth, policy decisions,
// serve lifecycle) for local review without storing content.
//
// AUD-001: sinks must never store tokens, passwords, raw log bodies, or
// Authorization headers. Prefer tool names, decision codes, hashed targets,
// and byte/duration counters over free-form payloads.
//
// Audit emit failures are best-effort and never authorize mutations.
package audit
