package saml

import (
	"strings"
	"unicode/utf8"

	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// MaxSubjectBytes caps mapped subject labels (never store full assertion NameID blobs).
const MaxSubjectBytes = 256

// Identity is the secret-free result of a successful SAML assertion map.
// Never includes assertion XML, signatures, or oversize NameIDs.
type Identity struct {
	// Subject is the mapped principal label (capped).
	Subject string
	// Groups are deduped, capped IdP group ids (fail-closed on overage).
	Groups []string
	// Issuer is the IdP entityID that issued the assertion.
	Issuer string
	// Tenant optional tenant pin.
	Tenant string
	// SubjectRedacted is a length-safe display form (prefix + ellipsis) for admin UI.
	SubjectRedacted string
}

// Reason codes (stable, non-secret).
const (
	ReasonOK              = "ok"
	ReasonBadSignature    = "bad_signature"
	ReasonUntrustedIssuer = "untrusted_issuer"
	ReasonBadAudience     = "bad_audience"
	ReasonBadRecipient    = "bad_recipient"
	ReasonExpired         = "expired"
	ReasonNotYetValid     = "not_yet_valid"
	ReasonEmptySubject    = "empty_subject"
	ReasonGroupOverage    = "group_overage"
	ReasonEmptyGroupsAttr = "empty_groups_required"
	ReasonInvalidXML      = "invalid_xml"
	ReasonMissingSig      = "missing_signature"
	ReasonConfigDisabled  = "saml_disabled"
	ReasonRoleUnmapped    = "role_unmapped"
)

// PolicySubject builds a verified policy.Subject for POL-006 evaluation.
// jenkinsUser may be empty when only external subject is known — for MCP serve
// bind, callers should set a non-anonymous Jenkins principal when available.
// profileID and jenkinsUser must come from process/profile context, not tool args.
func (id Identity) PolicySubject(profileID contracts.ProfileID, jenkinsUser string) policy.Subject {
	ju := strings.TrimSpace(jenkinsUser)
	if ju == "" {
		// Use external subject as provisional Jenkins label only when non-empty
		// and not anonymous — still Verified=true because SAML assertion passed.
		ju = id.Subject
	}
	s := policy.NewSubject(profileID, ju, true)
	s = s.WithExternal(id.Subject)
	s = s.WithGateway(id.Tenant, "", id.Groups)
	return s
}

// RedactSubject returns a short secret-free label for display/audit (no full NameID dump).
func RedactSubject(subject string) string {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return ""
	}
	if utf8.RuneCountInString(subject) <= 12 {
		return subject
	}
	// Keep first 8 runes + ellipsis.
	r := []rune(subject)
	return string(r[:8]) + "…"
}

// CapSubject truncates oversize subjects (fail closed for empty after trim).
func CapSubject(subject string) string {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return ""
	}
	if len(subject) <= MaxSubjectBytes {
		return subject
	}
	// Rune-safe truncate.
	var b strings.Builder
	n := 0
	for _, r := range subject {
		rn := utf8.RuneLen(r)
		if n+rn > MaxSubjectBytes {
			break
		}
		b.WriteRune(r)
		n += rn
	}
	return b.String()
}

// BoundGroups applies SAML fail-closed group capping (always FailOnOverage).
func BoundGroups(groups []string, max int) (out []string, errCode string) {
	if max <= 0 {
		max = auth.MaxStoredGroups
	}
	seen := make(map[string]struct{}, len(groups))
	out = make([]string, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if len(g) > auth.MaxGroupNameBytes {
			return nil, ReasonGroupOverage // oversize name fail closed (no truncate-collide)
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		if len(out) >= max {
			return nil, ReasonGroupOverage
		}
		out = append(out, g)
	}
	return out, ""
}
