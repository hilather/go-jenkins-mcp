// Package admin implements the local operator admin BFF (UI-002–UI-009 / ADR 0014).
//
// jenkins-mcp admin serve binds a loopback-only HTTP server that exposes
// secret-free JSON under /admin/v1/* for the operator SPA. Admin HTTP is off
// until the explicit CLI subcommand is used. Shared-secret gate is optional on
// loopback (pilot residual) and required for non-local residual binds.
//
// UI-003 console RBAC roles (viewer / operator / policy_admin) are process-wide
// via --admin-role and separate from MCP deny-only subjects. Admin never
// defeats enterprise force_read_only (CanWidenForceReadOnly is always false).
//
// UI-008: all responses get strict CSP + security headers; http.Server uses
// Read/Write/Idle timeouts; SPA assets resolve from --assets-dir, packaged
// /usr/share/jenkins-mcp/admin-ui, web/admin/dist (dev), or uiembed FS.
//
// Agent policy: keep this package (and web/admin + docs/admin/api-v1.md) in
// sync when product features affect operator day-2 surfaces. Do not reimplement
// policy/auth/budgets here — wrap existing libraries. See root AGENTS.md
// “keep the admin console current”.
//
// Responses never include tokens, keyring material, Authorization headers,
// full logs, or job parameters. Errors use apperr stable codes.
package admin
