// Package audit records security-relevant events (auth, policy decisions,
// serve lifecycle) for local review without storing content.
//
// AUD-001: sinks must never store tokens, passwords, raw log bodies, or
// Authorization headers. Prefer tool names, decision codes, hashed targets,
// and byte/duration counters over free-form payloads.
//
// Multi-user correlation foundation: optional ExternalSubject (IdP label) and
// SubjectKeyHash (HashOpaque of tenant|subject|profile). Never store raw
// subject keys or vault material. Multi-pod audit aggregation remains residual.
//
// Audit emit failures are best-effort and never authorize mutations.
//
// Agent policy (AGENTS.md): when adding security-relevant paths (authz deny,
// authn fail, mutations, admin destructive writes, vault/consent changes),
// emit via Emit/existing wrappers in the same change or leave an explicit
// AUD-T residual — never silent omission. See docs/security/audit-trail-review.md.
//
// New event types must also update KnownEventTypes (types_catalog.go),
// DefaultTypeFilter, admin GET/PUT …/audit/settings catalog, SPA Audit
// toggles/hints, and docs/observability.md in the same change. OpenProfileSink
// wraps File with ReloadingFilterSink so operators can enable/disable types
// without restart (type_filter.json under profile audit/).
package audit
