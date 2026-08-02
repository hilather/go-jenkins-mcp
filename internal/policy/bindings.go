package policy

import (
	"fmt"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// SubjectBindings is the POL-006 container for per-user and per-group deny-only
// rules on an enterprise overlay. Global overlay denials always apply; matching
// user and group bindings only add denials / lower caps (never elevate).
//
// Identity for matching comes from verified process authn (Jenkins principal,
// external subject, IdP groups) — never from MCP tool arguments.
type SubjectBindings struct {
	// Users are deny-only bindings for individual verified principals.
	Users []UserBinding `json:"users,omitempty"`
	// Groups are deny-only bindings for IdP/SAML/OIDC group ids.
	// Membership is never invented: only groups present on Subject.Groups match.
	Groups []GroupBinding `json:"groups,omitempty"`
}

// UserBinding attaches deny-only rules to a verified user (POL-006).
// At least one of JenkinsUserID or ExternalSubject must be set.
// When both are set, both must match (AND) so dual-keyed bindings stay precise.
type UserBinding struct {
	// JenkinsUserID matches Subject.JenkinsUserID (case-insensitive, trimmed).
	JenkinsUserID string `json:"jenkins_user_id,omitempty"`
	// ExternalSubject matches Subject.ExternalSubject (exact after trim).
	ExternalSubject string `json:"external_subject,omitempty"`

	// Deny-only fields (same semantics as global Overlay fields).
	DenyTools         []string `json:"deny_tools,omitempty"`
	DenyJobPrefixes   []string `json:"deny_job_prefixes,omitempty"`
	DenyNodeNames     []string `json:"deny_node_names,omitempty"`
	DenyViewNames     []string `json:"deny_view_names,omitempty"`
	DenyArtifactPaths []string `json:"deny_artifact_paths,omitempty"`
	DenyBranchNames   []string `json:"deny_branch_names,omitempty"`
	MaxResultBytes    *int     `json:"max_result_bytes,omitempty"`
	MaxToolsPerMinute *int     `json:"max_tools_per_minute,omitempty"`
	MaxToolsBurst     *int     `json:"max_tools_burst,omitempty"`
}

// GroupBinding attaches deny-only rules to a group claim value (POL-006).
// GroupID is matched exactly (after trim) against Subject.Groups entries.
// Unknown / missing group membership never invents a match (fail closed).
type GroupBinding struct {
	// GroupID is the stable group claim / attribute value (required).
	GroupID string `json:"group_id"`

	DenyTools         []string `json:"deny_tools,omitempty"`
	DenyJobPrefixes   []string `json:"deny_job_prefixes,omitempty"`
	DenyNodeNames     []string `json:"deny_node_names,omitempty"`
	DenyViewNames     []string `json:"deny_view_names,omitempty"`
	DenyArtifactPaths []string `json:"deny_artifact_paths,omitempty"`
	DenyBranchNames   []string `json:"deny_branch_names,omitempty"`
	MaxResultBytes    *int     `json:"max_result_bytes,omitempty"`
	MaxToolsPerMinute *int     `json:"max_tools_per_minute,omitempty"`
	MaxToolsBurst     *int     `json:"max_tools_burst,omitempty"`
}

// Validate checks structural constraints for subject bindings (no network).
func (b *SubjectBindings) Validate() error {
	if b == nil {
		return nil
	}
	for i := range b.Users {
		if err := b.Users[i].Validate(i); err != nil {
			return err
		}
	}
	for i := range b.Groups {
		if err := b.Groups[i].Validate(i); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks a user binding.
func (u *UserBinding) Validate(index int) error {
	if u == nil {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("subjects.users[%d] is nil", index))
	}
	u.JenkinsUserID = strings.TrimSpace(u.JenkinsUserID)
	u.ExternalSubject = strings.TrimSpace(u.ExternalSubject)
	if u.JenkinsUserID == "" && u.ExternalSubject == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("subjects.users[%d]: jenkins_user_id or external_subject required", index))
	}
	if u.JenkinsUserID != "" && strings.EqualFold(u.JenkinsUserID, AnonymousJenkinsUser) {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("subjects.users[%d]: anonymous is not a valid binding target", index))
	}
	prefix := fmt.Sprintf("subjects.users[%d]", index)
	return validateBindingDenies(prefix, u.DenyTools, u.DenyJobPrefixes, u.DenyNodeNames,
		u.DenyViewNames, u.DenyArtifactPaths, u.DenyBranchNames,
		u.MaxResultBytes, u.MaxToolsPerMinute, u.MaxToolsBurst)
}

// Validate checks a group binding.
func (g *GroupBinding) Validate(index int) error {
	if g == nil {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("subjects.groups[%d] is nil", index))
	}
	g.GroupID = strings.TrimSpace(g.GroupID)
	if g.GroupID == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("subjects.groups[%d]: group_id is required", index))
	}
	prefix := fmt.Sprintf("subjects.groups[%d]", index)
	return validateBindingDenies(prefix, g.DenyTools, g.DenyJobPrefixes, g.DenyNodeNames,
		g.DenyViewNames, g.DenyArtifactPaths, g.DenyBranchNames,
		g.MaxResultBytes, g.MaxToolsPerMinute, g.MaxToolsBurst)
}

func validateBindingDenies(
	prefix string,
	denyTools, jobs, nodes, views, arts, branches []string,
	maxBytes, maxTPM, maxBurst *int,
) error {
	for i, name := range denyTools {
		name = strings.TrimSpace(name)
		if name == "" {
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("%s.deny_tools[%d] is empty", prefix, i))
		}
		denyTools[i] = name
	}
	for i, p := range jobs {
		p = strings.TrimSpace(p)
		if err := validateDenyPatternIndex(prefix+".deny_job_prefixes", i, p); err != nil {
			return err
		}
		jobs[i] = p
	}
	for i, p := range nodes {
		p = strings.TrimSpace(p)
		if err := validateDenyPatternIndex(prefix+".deny_node_names", i, p); err != nil {
			return err
		}
		nodes[i] = p
	}
	for i, p := range views {
		p = strings.TrimSpace(p)
		if err := validateDenyPatternIndex(prefix+".deny_view_names", i, p); err != nil {
			return err
		}
		views[i] = p
	}
	for i, p := range arts {
		p = strings.TrimSpace(p)
		if err := validateDenyPatternIndex(prefix+".deny_artifact_paths", i, p); err != nil {
			return err
		}
		arts[i] = p
	}
	for i, p := range branches {
		p = strings.TrimSpace(p)
		if err := validateDenyPatternIndex(prefix+".deny_branch_names", i, p); err != nil {
			return err
		}
		branches[i] = p
	}
	if maxBytes != nil && *maxBytes <= 0 {
		return apperr.New(apperr.CodeInvalidArgument,
			prefix+".max_result_bytes must be positive when set")
	}
	if maxTPM != nil && *maxTPM <= 0 {
		return apperr.New(apperr.CodeInvalidArgument,
			prefix+".max_tools_per_minute must be positive when set")
	}
	if maxBurst != nil && *maxBurst <= 0 {
		return apperr.New(apperr.CodeInvalidArgument,
			prefix+".max_tools_burst must be positive when set")
	}
	return nil
}

// MatchesUser reports whether this binding applies to subject (POL-006).
func (u UserBinding) MatchesUser(subject Subject) bool {
	ju := strings.TrimSpace(u.JenkinsUserID)
	ext := strings.TrimSpace(u.ExternalSubject)
	if ju == "" && ext == "" {
		return false
	}
	if ju != "" {
		if !strings.EqualFold(ju, strings.TrimSpace(subject.JenkinsUserID)) {
			return false
		}
	}
	if ext != "" {
		if ext != strings.TrimSpace(subject.ExternalSubject) {
			return false
		}
	}
	return true
}

// MatchesGroup reports whether subject carries group_id (exact, trimmed).
// Never invents membership: empty Subject.Groups never matches.
func (g GroupBinding) MatchesGroup(subject Subject) bool {
	want := strings.TrimSpace(g.GroupID)
	if want == "" {
		return false
	}
	for _, have := range subject.Groups {
		if strings.TrimSpace(have) == want {
			return true
		}
	}
	return false
}

// EffectiveDocumentForSubject returns a Document that is the most-restrictive
// merge of the base document and every matching user/group binding (POL-006).
//
// Merge rules (deny-only / lower-only):
//   - Deny tool/pattern lists are unioned
//   - Budget caps take the minimum positive value
//   - Mode, ForceReadOnly, RequireVerified, Version stay base-only
//   - Group membership is never invented
func EffectiveDocumentForSubject(base Document, subject Subject) Document {
	// Always clone so callers cannot mutate the evaluator's live DenyTools map.
	out := cloneDocument(base)
	if len(base.UserBindings) == 0 && len(base.GroupBindings) == 0 {
		return out
	}
	for _, u := range base.UserBindings {
		if u.MatchesUser(subject) {
			mergeBindingIntoDoc(&out, u.DenyTools, u.DenyJobPrefixes, u.DenyNodeNames,
				u.DenyViewNames, u.DenyArtifactPaths, u.DenyBranchNames,
				u.MaxResultBytes, u.MaxToolsPerMinute, u.MaxToolsBurst)
		}
	}
	for _, g := range base.GroupBindings {
		if g.MatchesGroup(subject) {
			mergeBindingIntoDoc(&out, g.DenyTools, g.DenyJobPrefixes, g.DenyNodeNames,
				g.DenyViewNames, g.DenyArtifactPaths, g.DenyBranchNames,
				g.MaxResultBytes, g.MaxToolsPerMinute, g.MaxToolsBurst)
		}
	}
	return out
}

func cloneDocument(d Document) Document {
	out := d
	if d.DenyTools != nil {
		out.DenyTools = make(map[string]struct{}, len(d.DenyTools))
		for k := range d.DenyTools {
			out.DenyTools[k] = struct{}{}
		}
	}
	out.DenyJobPrefixes = copyStrings(d.DenyJobPrefixes)
	out.DenyNodeNames = copyStrings(d.DenyNodeNames)
	out.DenyViewNames = copyStrings(d.DenyViewNames)
	out.DenyArtifactPaths = copyStrings(d.DenyArtifactPaths)
	out.DenyBranchNames = copyStrings(d.DenyBranchNames)
	// Bindings themselves are not needed on the effective doc for evaluation.
	out.UserBindings = nil
	out.GroupBindings = nil
	return out
}

func copyStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func mergeBindingIntoDoc(
	doc *Document,
	denyTools, jobs, nodes, views, arts, branches []string,
	maxBytes, maxTPM, maxBurst *int,
) {
	if doc.DenyTools == nil && len(denyTools) > 0 {
		doc.DenyTools = make(map[string]struct{})
	}
	for _, t := range denyTools {
		t = strings.TrimSpace(t)
		if t != "" {
			doc.DenyTools[t] = struct{}{}
		}
	}
	doc.DenyJobPrefixes = unionStrings(doc.DenyJobPrefixes, jobs)
	doc.DenyNodeNames = unionStrings(doc.DenyNodeNames, nodes)
	doc.DenyViewNames = unionStrings(doc.DenyViewNames, views)
	doc.DenyArtifactPaths = unionStrings(doc.DenyArtifactPaths, arts)
	doc.DenyBranchNames = unionStrings(doc.DenyBranchNames, branches)
	doc.MaxResultBytes = minPositiveCap(doc.MaxResultBytes, maxBytes)
	doc.MaxToolsPerMinute = minPositiveCap(doc.MaxToolsPerMinute, maxTPM)
	doc.MaxToolsBurst = minPositiveCap(doc.MaxToolsBurst, maxBurst)
}

func unionStrings(base, extra []string) []string {
	if len(extra) == 0 {
		return base
	}
	seen := make(map[string]struct{}, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, s := range base {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range extra {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// minPositiveCap returns the most restrictive (minimum) positive cap.
// base is the current document int (0 = unset). extra nil = no change.
func minPositiveCap(base int, extra *int) int {
	if extra == nil || *extra <= 0 {
		return base
	}
	if base <= 0 {
		return *extra
	}
	if *extra < base {
		return *extra
	}
	return base
}
