// Package fleetmcp implements opt-in fleet-wide read aggregation for MCP
// (FLEET-MCP vertical slice).
//
// Design SoT: docs/fleet/fleet-mcp-ops.md
//
//   - Namespace fleet_* (distinct from jenkins_* and admin_*).
//   - Register only when fleet mode + valid roster + mesh trust + member id.
//   - Roster is membership SoT; tool args cannot invent peer hosts.
//   - Coordinator fans out to peers over authenticated HTTP (/fleet/v1/*).
//   - Partial peer failures → incomplete + per-member residuals (no invented OK).
//   - Secret-free forever; not multi-pod HA (HOST-008 cancelled).
//   - v1 is read-only (no fleet-wide writes).
package fleetmcp
