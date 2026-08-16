package policy

import (
	"fmt"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// MutationPolicy is MUT-017 optional allowlisting for mutation tools/jobs/modes.
// Nil or empty fields mean "no extra restriction beyond RO / deny_tools".
// When AllowTools is non-empty, only those mutation tools register/execute.
type MutationPolicy struct {
	// AllowTools lists tool names (e.g. jenkins_start_job). Empty = all classified mutations.
	AllowTools []string
	// AllowInterruptModes lists stop|term|kill. Empty = all three allowed for interrupt tool.
	AllowInterruptModes []string
	// AllowJobPrefixes: when non-empty, job full name must match at least one prefix.
	AllowJobPrefixes []string
}

// MutationPolicyFromOverlay builds a MutationPolicy from overlay fields (nil-safe).
func MutationPolicyFromOverlay(o *Overlay) *MutationPolicy {
	if o == nil {
		return nil
	}
	p := &MutationPolicy{
		AllowTools:          append([]string(nil), o.AllowMutationTools...),
		AllowInterruptModes: append([]string(nil), o.AllowInterruptModes...),
		AllowJobPrefixes:    append([]string(nil), o.AllowMutationJobPrefixes...),
	}
	if len(p.AllowTools) == 0 && len(p.AllowInterruptModes) == 0 && len(p.AllowJobPrefixes) == 0 {
		return nil
	}
	return p
}

// MutationToolAllowed reports whether a mutation tool may register under policy.
// Nil policy or empty AllowTools → allow all classified mutation tools.
func MutationToolAllowed(p *MutationPolicy, tool string) bool {
	tool = strings.TrimSpace(tool)
	if tool == "" || !IsMutationTool(tool) {
		return false
	}
	if p == nil || len(p.AllowTools) == 0 {
		return true
	}
	for _, a := range p.AllowTools {
		if strings.TrimSpace(a) == tool {
			return true
		}
	}
	return false
}

// CheckInterruptModeAllowed fails closed when mode is not in AllowInterruptModes
// (when that list is non-empty). Empty list allows stop|term|kill only (validated elsewhere).
func CheckInterruptModeAllowed(p *MutationPolicy, mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "stop", "term", "kill":
	default:
		return apperr.New(apperr.CodeInvalidArgument, "mode must be stop, term, or kill")
	}
	if p == nil || len(p.AllowInterruptModes) == 0 {
		return nil
	}
	for _, a := range p.AllowInterruptModes {
		if strings.ToLower(strings.TrimSpace(a)) == mode {
			return nil
		}
	}
	return apperr.New(apperr.CodePolicyDenial, fmt.Sprintf("interrupt mode %q is not allowlisted", mode))
}

// CheckMutationJobAllowed fails closed when AllowJobPrefixes is set and job does not match.
func CheckMutationJobAllowed(p *MutationPolicy, jobFullName string) error {
	job := strings.TrimSpace(jobFullName)
	if p == nil || len(p.AllowJobPrefixes) == 0 {
		return nil
	}
	for _, pref := range p.AllowJobPrefixes {
		pref = strings.TrimSpace(pref)
		if pref == "" {
			continue
		}
		// Segment-boundary match (same contract as the deny-side pattern
		// language): bare prefix "team-a" must not allow "team-audit/job".
		pref = strings.TrimSuffix(pref, "/")
		if pref == "" {
			continue
		}
		if job == pref || strings.HasPrefix(job, pref+"/") {
			return nil
		}
	}
	return apperr.New(apperr.CodePolicyDenial, "job is not allowlisted for mutations")
}
