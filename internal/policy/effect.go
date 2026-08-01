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

// Known mutation tool names for the seed registry (POL-001 / power-user backlog).
// Waits (queue/build) are read; only listed tools mutate.
const (
	ToolStartJob               = "jenkins_start_job"
	ToolStopBuild              = "jenkins_stop_build"
	ToolCancelQueueItem        = "jenkins_cancel_queue_item"
	ToolInterruptBuild         = "jenkins_interrupt_build"
	ToolRebuildBuild           = "jenkins_rebuild_build"
	ToolReplayPipeline         = "jenkins_replay_pipeline"
	ToolSetJobBuildable        = "jenkins_set_job_buildable"
	ToolSetBuildKeepForever    = "jenkins_set_build_keep_forever"
	ToolSetBuildDescription    = "jenkins_set_build_description"
	ToolCancelQueueItemsForJob = "jenkins_cancel_queue_items_for_job"
)

// MutationToolNames is the closed set of mutation tools omitted under read-only.
func MutationToolNames() []string {
	return []string{
		ToolStartJob,
		ToolStopBuild,
		ToolCancelQueueItem,
		ToolInterruptBuild,
		ToolRebuildBuild,
		ToolReplayPipeline,
		ToolSetJobBuildable,
		ToolSetBuildKeepForever,
		ToolSetBuildDescription,
		ToolCancelQueueItemsForJob,
	}
}

// IsMutationTool reports whether name is a classified mutation tool.
func IsMutationTool(name string) bool {
	switch name {
	case ToolStartJob, ToolStopBuild, ToolCancelQueueItem,
		ToolInterruptBuild, ToolRebuildBuild, ToolReplayPipeline,
		ToolSetJobBuildable, ToolSetBuildKeepForever, ToolSetBuildDescription,
		ToolCancelQueueItemsForJob:
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
