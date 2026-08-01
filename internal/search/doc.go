// Package search provides local literal and RE2-compatible regex search over
// mirrored L1 independent Zstandard log frames (SEARCH-001 / SEARCH-002).
//
// Search streams committed frames only (via store.LogReader + chunk metadata),
// matches line-oriented patterns with bounded before/after context, enforces
// match and bytes-scanned caps, and respects context cancellation.
//
// Levels (architecture §13.1):
//  1. Literal (default) — no false negatives for base path
//  2. RE2-safe regex via Go regexp (no catastrophic backtracking)
//
// Residual: optional chunk Bloom/token summaries; multi-line regex spanning
// lines; MCP tool jenkins_search_log full wiring (library is primary).
//
// Boundaries (FND-004): may import store, apperr, contracts — not mcpserver.
// tools may import search. Secrets never appear in match excerpts beyond
// what is already in the caller-selected log evidence (SEC-002 redacts later).
package search
