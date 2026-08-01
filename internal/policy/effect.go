package policy

// EffectClass classifies a tool or Jenkins request by side effect (POL-001).
// Unclassified future tools must be treated as fail-closed for mutations
// until explicitly classified (POL-004).
type EffectClass string

const (
	// EffectRead is a non-mutating observation (GET-like tools, waits that poll).
	EffectRead EffectClass = "read"
	// EffectMutate changes Jenkins state (build trigger, stop, cancel, etc.).
	EffectMutate EffectClass = "mutate"
	// EffectAuth is credential/token exchange traffic; not blocked by read-only.
	EffectAuth EffectClass = "auth"
)

// Known mutation tool names for the seed registry (POL-001).
// Waits (queue/build) are read; only start/stop/cancel-queue mutate.
const (
	ToolStartJob        = "jenkins_start_job"
	ToolStopBuild       = "jenkins_stop_build"
	ToolCancelQueueItem = "jenkins_cancel_queue_item"
)

// MutationToolNames is the closed set of seed tools omitted under read-only.
func MutationToolNames() []string {
	return []string{ToolStartJob, ToolStopBuild, ToolCancelQueueItem}
}

// IsMutationTool reports whether name is a classified mutation tool.
func IsMutationTool(name string) bool {
	switch name {
	case ToolStartJob, ToolStopBuild, ToolCancelQueueItem:
		return true
	default:
		return false
	}
}

// ToolEffect returns the effect class for a registered tool name.
// Unknown names default to EffectRead for discovery classification of
// current read tools; mutation registration still requires an explicit
// mutate path (registerMutationTool). Future unclassified mutations must
// fail closed at the Jenkins request classifier (POL-004 / NET).
func ToolEffect(name string) EffectClass {
	if IsMutationTool(name) {
		return EffectMutate
	}
	return EffectRead
}

// IsExplicitlyClassified reports whether name has an explicit seed effect class.
// Newly introduced tools must be added to knownSeedTools / MutationToolNames
// before they are treated as classified; strict MCP policy denies unknowns
// (POL-004 fail closed for unclassified tools).
func IsExplicitlyClassified(name string) bool {
	return IsKnownSeedTool(name)
}
