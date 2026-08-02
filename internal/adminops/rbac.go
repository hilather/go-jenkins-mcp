package adminops

import (
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/admin"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Role aliases admin console roles for MCP ops (same strings as UI-003).
type Role = admin.Role

// Permission aliases admin console permissions.
type Permission = admin.Permission

const (
	RoleViewer      = admin.RoleViewer
	RoleOperator    = admin.RoleOperator
	RolePolicyAdmin = admin.RolePolicyAdmin

	PermRead             = admin.PermRead
	PermPolicyWrite      = admin.PermPolicyWrite
	PermCacheDestructive = admin.PermCacheDestructive
	PermGatewayOps       = admin.PermGatewayOps
)

// Confirm tokens (must match BFF).
const (
	ConfirmEVICT     = admin.EvictConfirmToken           // "EVICT"
	ConfirmCLEAR_ALL = admin.ConsentClearAllConfirmToken // "CLEAR_ALL"
	ConfirmAPPLY     = "APPLY"                           // policy apply (MCP + future BFF parity)
)

// ParseRole parses viewer|operator|policy_admin (empty → viewer).
func ParseRole(s string) (Role, error) {
	return admin.ParseRole(s)
}

// RequirePermission fails closed when role lacks perm.
func RequirePermission(role Role, perm Permission) error {
	if role.Can(perm) {
		return nil
	}
	return apperr.New(apperr.CodeAuthorization,
		"admin mcp: role lacks required permission")
}

// RoleFromEnviron reads JENKINS_MCP_ADMIN_ROLE (same as admin serve).
func RoleFromEnviron(getenv func(string) string) (Role, error) {
	if getenv == nil {
		getenv = func(k string) string { return "" }
	}
	raw := strings.TrimSpace(getenv("JENKINS_MCP_ADMIN_ROLE"))
	if raw == "" {
		// Fall back empty → viewer (fail closed for writes).
		return RoleViewer, nil
	}
	return ParseRole(raw)
}
