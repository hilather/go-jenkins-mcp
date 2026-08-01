// Package app owns process lifecycle: wiring config, profiles, MCP server,
// and graceful shutdown. cmd/jenkins-mcp is a thin entrypoint that calls app.
//
// Cache maintenance (ARC-007 + ARC-005 residual + ARC-011 lite): Maintainer runs
// a background loop while `jenkins-mcp serve --profile` has an open data dir.
// Each tick recovers the eviction journal, plans/applies eviction when over
// quota, packs sealed unpinned L1 generations into L2 grouped by job affinity
// (profile=…|job=…), and optionally releases L1 frames after verified pack
// (age since packed_at, high disk pressure, or ReleaseAfterPack for tests).
// Operator tick interval: ResolveMaintenanceInterval (default 5m, min 30s,
// absolute max 1h fail-closed; flag/env). Disable with --no-cache-maintenance.
//
// Boundaries (FND-004): app may wire store, logmirror, archive, and telemetry;
// it must not import tools or mcpserver (cmd does that).
package app
