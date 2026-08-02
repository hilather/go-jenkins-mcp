package saml

import (
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// ResolveAdminRole maps IdP groups to an admin console role using Config.GroupRoles.
// Most privileged match wins among {policy_admin > operator > viewer}.
// Unmapped groups → fail closed (empty role + error). Never invents membership.
func ResolveAdminRole(cfg Config, groups []string) (role string, matchedGroup string, err error) {
	if !cfg.Enabled {
		return "", "", apperr.New(apperr.CodeAuthentication, "saml is disabled")
	}
	if len(cfg.GroupRoles) == 0 {
		return "", "", apperr.New(apperr.CodeAuthorization, "saml group_roles map is empty (fail closed)")
	}
	bestRank := -1
	bestRole := ""
	bestGroup := ""
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		raw, ok := cfg.GroupRoles[g]
		if !ok {
			// Case-insensitive group key match for operator convenience.
			for k, v := range cfg.GroupRoles {
				if strings.EqualFold(k, g) {
					raw = v
					ok = true
					break
				}
			}
		}
		if !ok {
			continue
		}
		r := strings.TrimSpace(strings.ToLower(raw))
		rank := roleRank(r)
		if rank < 0 {
			continue
		}
		if rank > bestRank {
			bestRank = rank
			bestRole = r
			bestGroup = g
		}
	}
	if bestRole == "" {
		return "", "", apperr.New(apperr.CodeAuthorization, "saml identity has no mapped admin role (fail closed)")
	}
	return bestRole, bestGroup, nil
}

func roleRank(r string) int {
	switch r {
	case "viewer":
		return 1
	case "operator":
		return 2
	case "policy_admin":
		return 3
	default:
		return -1
	}
}
