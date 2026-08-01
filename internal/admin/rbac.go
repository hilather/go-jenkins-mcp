package admin

import (
	"fmt"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Role is an admin-console operator role (UI-003). Separate from MCP deny-only
// subjects (ADR 0004): console roles authorize the BFF/SPA only and never
// elevate Jenkins or MCP tool rights.
type Role string

const (
	// RoleViewer is read-only admin API (all current GET routes).
	RoleViewer Role = "viewer"
	// RoleOperator is day-2 ops (cache evict + support-bundle; UI-007).
	// Same as viewer for all read routes.
	RoleOperator Role = "operator"
	// RolePolicyAdmin is future policy apply; same as viewer for reads today.
	// Still cannot widen enterprise force_read_only.
	RolePolicyAdmin Role = "policy_admin"
)

// Permission is a fine-grained admin console capability.
type Permission string

const (
	// PermRead allows all current read-only admin API routes.
	PermRead Permission = "read"
	// PermPolicyWrite is future policy draft/validate/apply (UI-004).
	// Granted to policy_admin only; still cannot defeat force_read_only.
	PermPolicyWrite Permission = "policy_write"
	// PermCacheDestructive gates destructive cache eviction and support-bundle
	// create (UI-007). Granted to operator only. Requires body confirm for evict.
	PermCacheDestructive Permission = "cache_destructive"
)

// ParseRole parses a role name (viewer|operator|policy_admin). Empty defaults
// to viewer. Invalid names fail closed.
func ParseRole(s string) (Role, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return RoleViewer, nil
	}
	switch Role(s) {
	case RoleViewer, RoleOperator, RolePolicyAdmin:
		return Role(s), nil
	default:
		return "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("invalid admin role %q (want viewer, operator, or policy_admin)", s))
	}
}

// String returns the stable role name.
func (r Role) String() string {
	if r == "" {
		return string(RoleViewer)
	}
	return string(r)
}

// Can reports whether r grants perm. Empty and unknown roles deny all
// (fail closed). Middleware always attaches a validated Role.
func (r Role) Can(perm Permission) bool {
	switch r {
	case RoleViewer:
		return perm == PermRead
	case RoleOperator:
		return perm == PermRead || perm == PermCacheDestructive
	case RolePolicyAdmin:
		return perm == PermRead || perm == PermPolicyWrite
	default:
		return false
	}
}

// Permissions returns the stable list of permissions granted to r for /me.
func (r Role) Permissions() []Permission {
	switch r {
	case RoleOperator:
		return []Permission{PermRead, PermCacheDestructive}
	case RolePolicyAdmin:
		return []Permission{PermRead, PermPolicyWrite}
	case RoleViewer:
		return []Permission{PermRead}
	default:
		// Empty/unknown: no grants (fail closed). ValidateConfig rejects unknown.
		return []Permission{}
	}
}

// PermissionStrings returns permission names for JSON (e.g. /me).
func (r Role) PermissionStrings() []string {
	perms := r.Permissions()
	out := make([]string, len(perms))
	for i, p := range perms {
		out[i] = string(p)
	}
	return out
}

// CanWidenForceReadOnly reports whether the role may disable or weaken
// enterprise force_read_only. Always false for every admin console role —
// admin never defeats enterprise force RO (ADR 0004 / ADR 0014 / UI-003).
func CanWidenForceReadOnly(role Role) bool {
	_ = role
	return false
}
