// Package adminops implements day-2 operator management operations shared by
// MCP admin_* tools (MCP-OPS) and (optionally) the admin BFF.
//
// Design (MCP-OPS-001):
//   - Namespace admin_* for management; jenkins_* for Jenkins data plane.
//   - Call shared libraries (diagnostics, policy, profile, audit, gateway, store).
//   - Do not HTTP-call admin serve from MCP tools.
//   - Secret-free results forever (no tokens, vault material, Authorization).
//   - Console-equivalent RBAC (viewer / operator / policy_admin) on the process role.
//   - Destructive ops require exact confirm tokens (EVICT, CLEAR_ALL, APPLY).
//   - Writes emit AUD-001 best-effort (MCP-OPS-008).
//   - Default off at serve: --enable-admin-mcp (MCP-OPS-004).
//
// POL-006/007 RBAC user/group binding tools remain residual until those tasks land.
package adminops
