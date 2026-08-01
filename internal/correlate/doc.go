// Package correlate provides pure extractors for work-item IDs and SCM host
// references from Jenkins build metadata (INT-004 MVP).
//
// Sources (explicit identifiers only; no broad project scrape):
//   - Build parameters (non-sensitive keys)
//   - Commit messages and commit SHAs from SCM changeSets
//   - Repo URLs (host + path) from changeSets
//   - Optional free-text fields (e.g. cause shortDescription)
//
// Extractors perform no network I/O. Ticket-system lookup is residual (work-items
// adapter stub returns refs only).
package correlate
