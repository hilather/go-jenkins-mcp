package saml

import (
	"sort"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// AttributeValues is a multi-map of assertion attribute names → values.
type AttributeValues map[string][]string

// MapIdentity maps NameID + attributes through Config.AttributeMap into Identity.
// Does not perform signature/time validation — call Validate first or use ValidateAndMap.
func MapIdentity(cfg Config, nameID string, attrs AttributeValues, issuer string) (Identity, error) {
	if !cfg.Enabled {
		return Identity{}, apperr.New(apperr.CodeAuthentication, "saml is disabled")
	}
	subjectAttr := strings.TrimSpace(cfg.AttributeMap.SubjectAttribute)
	var subject string
	if subjectAttr == "" {
		subject = strings.TrimSpace(nameID)
	} else {
		subject = firstAttr(attrs, subjectAttr)
		if subject == "" {
			// Fall back to NameID when configured attribute missing.
			subject = strings.TrimSpace(nameID)
		}
	}
	subject = CapSubject(subject)
	if subject == "" {
		return Identity{}, apperr.New(apperr.CodeAuthentication, "saml subject is empty after map")
	}

	groupsAttr := strings.TrimSpace(cfg.AttributeMap.GroupsAttribute)
	var groups []string
	if groupsAttr != "" {
		groups = attrs[groupsAttr]
		// Also try URI-style keys ending with the short name (fixture flexibility).
		// Deterministic: smallest matching key wins (Go map iteration order is
		// random, and the chosen groups feed role mapping — authz-relevant).
		if len(groups) == 0 {
			var keys []string
			for k := range attrs {
				if strings.EqualFold(k, groupsAttr) || strings.HasSuffix(strings.ToLower(k), "/"+strings.ToLower(groupsAttr)) {
					keys = append(keys, k)
				}
			}
			if len(keys) > 0 {
				sort.Strings(keys)
				groups = attrs[keys[0]]
			}
		}
	}
	bounded, code := BoundGroups(groups, cfg.EffectiveMaxGroups())
	if code != "" {
		return Identity{}, apperr.New(apperr.CodeAuthentication, "saml group membership overage or oversize name (fail closed)")
	}

	tenant := strings.TrimSpace(cfg.Tenant)
	if ta := strings.TrimSpace(cfg.AttributeMap.TenantAttribute); ta != "" {
		if v := firstAttr(attrs, ta); v != "" {
			tenant = CapSubject(v)
		}
	}

	return Identity{
		Subject:         subject,
		Groups:          bounded,
		Issuer:          strings.TrimSpace(issuer),
		Tenant:          tenant,
		SubjectRedacted: RedactSubject(subject),
	}, nil
}

func firstAttr(attrs AttributeValues, name string) string {
	if attrs == nil {
		return ""
	}
	vals := attrs[name]
	if len(vals) == 0 {
		// Case-insensitive key match; deterministic smallest key wins (Go map
		// iteration order is random and the result is identity-relevant).
		var keys []string
		for k, v := range attrs {
			if strings.EqualFold(k, name) && len(v) > 0 {
				keys = append(keys, k)
			}
		}
		if len(keys) == 0 {
			return ""
		}
		sort.Strings(keys)
		vals = attrs[keys[0]]
	}
	return strings.TrimSpace(vals[0])
}
