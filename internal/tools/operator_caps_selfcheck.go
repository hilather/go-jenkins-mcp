package tools

import (
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
	"github.com/simonfxr/go-jenkins-mcp/internal/mutation"
)

// Wave 43: register offline operator caps snapshot with diagnostics.
// tools already imports diagnostics (doctor/diagnose); registration avoids a
// diagnostics → tools import cycle while reporting live package getters.
// Wave 45 Track B: also reports Streamable HTTP body + identity re-verify TTL
// package constants (auth + mcpserver are cycle-free leaf imports here).
// Wave 46 Track B: Jenkins NET-003 resilience constants (JSON body, retries,
// circuit failure threshold) from jenkins package (already imported).
// Wave 48 Track B: absolute retries/circuit ceilings + default open duration.
// Wave 49 Track B: circuit open min/absolute duration + MaxConcurrent honesty.
// Wave 50 Track B: absolute max concurrent + retry backoff honesty (ms).
// Wave 51 Track B: survey/diagnose package hard ceilings (offline constants).
// Wave 52 Track B: Wave 51 backoff resolve bounds (min + absolute) + mutation
// package honesty constants (offline only; no live Manager state).
// Wave 53 Track B: Wave 52 mutation operator-resolve bounds (ConfirmCooldown
// min/absolute + AbsoluteMaxPreviewsPerMinute). TokenTTL min/absolute remain
// progressive residual until Wave 53 Track A lands MinTokenTTL/AbsoluteMaxTokenTTL.
func init() {
	diagnostics.RegisterOperatorCapsCanary(operatorCapsSnapshotItem)
}

// operatorCapsSnapshotItem reports secret-free integer/bool process caps for
// operators (security self-check / doctor / support-bundle). Control MCP-001.
//
// LiveHardMax is mid-serve only; offline self-check has no serve instance, so
// hard-max details use DefaultHardMaxBytes + AbsoluteMaxHardMaxBytes constants
// (not a live process hard-max). Soft TargetBytes is serve-bootstrap only (no
// process-level live getter offline) — report DefaultTargetBytes +
// AbsoluteMaxTargetBytes with live_target_bytes_available_offline=false.
// Collect page caps, artifacts hard cap, and artifact list body bytes use
// package-level live getters (defaults when serve has not Set*). Streamable
// HTTP MaxBodyBytes, identity re-verify TTL bounds, and Jenkins NET-003
// resilience knobs are package constants only (no live serve HTTP/auth/client
// circuit state offline — honesty like live_hard_max). Survey/diagnose budgets
// are package hard ceilings only (no serve flags in this track). Wave 52
// backoff resolve bounds and mutation package defaults are offline constants
// only (no live client backoff config or mutation Manager state). Wave 53
// Track B adds Wave 52 mutation resolve bounds (ConfirmCooldown min/abs +
// AbsoluteMaxPreviewsPerMinute); TokenTTL min/abs not exposed until Track A.
func operatorCapsSnapshotItem() diagnostics.SelfCheckItem {
	const name = "operator_caps_snapshot"
	const control = "MCP-001"

	listJobsPages := ListJobsCollectMaxPages()
	nodesPages := NodesCollectMaxPages()
	viewsPages := ViewsCollectMaxPages()
	artifactsCap := ArtifactsHardCap()
	artifactsListBody := jenkins.ArtifactListBodyBytes()

	// Offline constants (seconds for durations; bytes for body caps).
	defaultHTTPBody := int(mcpserver.DefaultMaxBodyBytes)
	absoluteHTTPBody := int(mcpserver.AbsoluteMaxBodyBytes)
	minIdentityTTLSec := int(auth.MinIdentityReverifyTTL.Seconds())
	maxIdentityTTLSec := int(auth.MaxIdentityReverifyTTL.Seconds())
	defaultIdentityTTLSec := int(auth.DefaultIdentityCacheTTL.Seconds())
	// Wave 46–49 Track B / NET-003: Jenkins client resilience package constants.
	defaultMaxJSONBody := int(jenkins.DefaultMaxJSONBodyBytes)
	absoluteMaxJSONBody := int(jenkins.AbsoluteMaxJSONBodyBytes)
	defaultMaxRetries := jenkins.DefaultMaxRetries
	absoluteMaxRetries := jenkins.AbsoluteMaxRetries
	defaultCircuitThreshold := jenkins.DefaultCircuitFailureThreshold
	absoluteCircuitThreshold := jenkins.AbsoluteMaxCircuitFailureThreshold
	defaultCircuitOpenSec := int(jenkins.DefaultCircuitOpenDuration.Seconds())
	// Wave 49 Track B: circuit open duration bounds + MaxConcurrent honesty.
	minCircuitOpenSec := int(jenkins.MinCircuitOpenDuration.Seconds())
	absoluteCircuitOpenSec := int(jenkins.AbsoluteMaxCircuitOpenDuration.Seconds())
	defaultMaxConcurrent := jenkins.DefaultMaxConcurrent
	// Wave 50 Track B: absolute max concurrent + retry backoff honesty (ms).
	absoluteMaxConcurrent := jenkins.AbsoluteMaxConcurrent
	defaultInitialBackoffMs := int(jenkins.DefaultInitialBackoff.Milliseconds())
	defaultMaxBackoffMs := int(jenkins.DefaultMaxBackoff.Milliseconds())
	// Wave 52 Track B: Wave 51 backoff resolve bounds (min + absolute, ms).
	minInitialBackoffMs := int(jenkins.MinInitialBackoff.Milliseconds())
	absoluteMaxInitialBackoffMs := int(jenkins.AbsoluteMaxInitialBackoff.Milliseconds())
	minMaxBackoffMs := int(jenkins.MinMaxBackoff.Milliseconds())
	absoluteMaxMaxBackoffMs := int(jenkins.AbsoluteMaxMaxBackoff.Milliseconds())
	// Wave 52 Track B: mutation package honesty (offline constants only).
	defaultMutationConfirmCooldownMs := int(mutation.DefaultConfirmCooldown.Milliseconds())
	defaultMutationMaxPreviewsPerMinute := mutation.DefaultMaxPreviewsPerMinute
	defaultMutationTokenTTLMs := int(mutation.DefaultTokenTTL.Milliseconds())
	// Wave 53 Track B: Wave 52 Done* mutation operator-resolve bounds (offline).
	// ConfirmCooldown: MinConfirmCooldown / AbsoluteMaxConfirmCooldown.
	// MaxPreviews: AbsoluteMaxPreviewsPerMinute (default already ≥ 1).
	// Wave 53 Track A: TokenTTL MinTokenTTL / AbsoluteMaxTokenTTL.
	minMutationConfirmCooldownMs := int(mutation.MinConfirmCooldown.Milliseconds())
	absoluteMaxMutationConfirmCooldownMs := int(mutation.AbsoluteMaxConfirmCooldown.Milliseconds())
	absoluteMaxMutationMaxPreviewsPerMinute := mutation.AbsoluteMaxPreviewsPerMinute
	minMutationTokenTTLMs := int(mutation.MinTokenTTL.Milliseconds())
	absoluteMaxMutationTokenTTLMs := int(mutation.AbsoluteMaxTokenTTL.Milliseconds())
	// Wave 51 Track B: survey / diagnose package hard ceilings (offline only).
	// tools already owns these constants (survey_recent_failures.go, diagnose_build.go).
	defaultSurveyMaxTotalBuilds := DefaultSurveyMaxTotalBuilds
	hardSurveyMaxTotalBuilds := HardSurveyMaxTotalBuilds
	defaultSurveyMaxJobs := DefaultSurveyMaxJobs
	hardSurveyMaxJobs := HardSurveyMaxJobs
	defaultSurveyMaxLogBytesTotal := DefaultSurveyMaxLogBytesTotal
	hardSurveyMaxLogBytesTotal := HardSurveyMaxLogBytesTotal
	defaultSurveyMaxWallSeconds := DefaultSurveyMaxWallSeconds
	hardSurveyMaxWallSeconds := HardSurveyMaxWallSeconds
	defaultDiagnoseLogBytes := DefaultDiagnoseLogBytes
	hardDiagnoseLogBytes := HardDiagnoseLogBytes
	defaultDiagnoseMaxFindings := DefaultDiagnoseMaxFindings
	hardDiagnoseMaxFindings := HardDiagnoseMaxFindings

	// Fail if any live getter is non-positive (mis-set / zeroed process state).
	if listJobsPages <= 0 || nodesPages <= 0 || viewsPages <= 0 || artifactsCap <= 0 || artifactsListBody <= 0 {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: one or more live caps non-positive",
			Control: control,
			Details: map[string]any{
				"list_jobs_collect_max_pages": listJobsPages,
				"nodes_collect_max_pages":     nodesPages,
				"views_collect_max_pages":     viewsPages,
				"artifacts_hard_cap":          artifactsCap,
				"artifacts_list_body_bytes":   artifactsListBody,
			},
		}
	}

	// Constants must stay positive and absolute ≥ default / live defaults.
	if DefaultHardMaxBytes <= 0 || AbsoluteMaxHardMaxBytes < DefaultHardMaxBytes {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: hard-max constants invalid",
			Control: control,
			Details: map[string]any{
				"default_hard_max_bytes":      DefaultHardMaxBytes,
				"absolute_max_hard_max_bytes": AbsoluteMaxHardMaxBytes,
			},
		}
	}
	// Wave 47 Track B / Wave 51 Track C: soft target constants (absolute = AbsoluteMaxHardMaxBytes / 64 MiB).
	if DefaultTargetBytes <= 0 || AbsoluteMaxTargetBytes < DefaultTargetBytes {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: target-bytes constants invalid",
			Control: control,
			Details: map[string]any{
				"default_target_bytes":      DefaultTargetBytes,
				"absolute_max_target_bytes": AbsoluteMaxTargetBytes,
			},
		}
	}
	if jenkins.AbsoluteMaxArtifactsHardCap < jenkins.DefaultArtifactsHardCap {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: artifacts absolute max below default",
			Control: control,
			Details: map[string]any{
				"default_artifacts_hard_cap":      jenkins.DefaultArtifactsHardCap,
				"absolute_max_artifacts_hard_cap": jenkins.AbsoluteMaxArtifactsHardCap,
			},
		}
	}
	if jenkins.AbsoluteMaxArtifactListBodyBytes < jenkins.DefaultArtifactListBodyBytes {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: artifacts list body absolute max below default",
			Control: control,
			Details: map[string]any{
				"default_artifacts_list_body_bytes":      jenkins.DefaultArtifactListBodyBytes,
				"absolute_max_artifacts_list_body_bytes": jenkins.AbsoluteMaxArtifactListBodyBytes,
			},
		}
	}
	// Wave 45 Track B: Streamable HTTP body constants (default 4 MiB, absolute 16 MiB).
	if defaultHTTPBody <= 0 || absoluteHTTPBody <= 0 || absoluteHTTPBody < defaultHTTPBody {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: HTTP max body constants invalid",
			Control: control,
			Details: map[string]any{
				"default_http_max_body_bytes":      defaultHTTPBody,
				"absolute_max_http_max_body_bytes": absoluteHTTPBody,
			},
		}
	}
	// Wave 45 Track B: identity re-verify TTL bounds (min 10s, max 30m) + default.
	// Require min ≤ default ≤ max so operators can trust the snapshot ordering.
	if minIdentityTTLSec <= 0 || maxIdentityTTLSec <= 0 || defaultIdentityTTLSec <= 0 ||
		maxIdentityTTLSec < minIdentityTTLSec ||
		defaultIdentityTTLSec < minIdentityTTLSec ||
		defaultIdentityTTLSec > maxIdentityTTLSec {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: identity re-verify TTL constants invalid",
			Control: control,
			Details: map[string]any{
				"min_identity_reverify_ttl_seconds":     minIdentityTTLSec,
				"max_identity_reverify_ttl_seconds":     maxIdentityTTLSec,
				"default_identity_reverify_ttl_seconds": defaultIdentityTTLSec,
			},
		}
	}
	// Wave 46–50 Track B / NET-003: Jenkins JSON body absolute ≥ default; retries
	// default ≥ 0 (0 disables auto-retry; default is 2 extra GET/HEAD attempts)
	// and absolute ≥ default; circuit failure threshold default/absolute positive
	// with absolute ≥ default; circuit open duration min/default/absolute positive
	// with min ≤ default ≤ absolute; MaxConcurrent default is 0 (unlimited) with
	// positive AbsoluteMaxConcurrent ceiling; backoff defaults positive with
	// max ≥ initial. No live client circuit / concurrency state offline.
	if defaultMaxJSONBody <= 0 || absoluteMaxJSONBody <= 0 || absoluteMaxJSONBody < defaultMaxJSONBody {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: Jenkins MaxJSONBodyBytes constants invalid",
			Control: control,
			Details: map[string]any{
				"default_max_json_body_bytes":  defaultMaxJSONBody,
				"absolute_max_json_body_bytes": absoluteMaxJSONBody,
			},
		}
	}
	if defaultMaxRetries < 0 {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: DefaultMaxRetries must be non-negative",
			Control: control,
			Details: map[string]any{
				"default_max_retries": defaultMaxRetries,
			},
		}
	}
	if absoluteMaxRetries < 0 || absoluteMaxRetries < defaultMaxRetries {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: AbsoluteMaxRetries must be ≥ DefaultMaxRetries and non-negative",
			Control: control,
			Details: map[string]any{
				"default_max_retries":  defaultMaxRetries,
				"absolute_max_retries": absoluteMaxRetries,
			},
		}
	}
	if defaultCircuitThreshold <= 0 || absoluteCircuitThreshold <= 0 ||
		absoluteCircuitThreshold < defaultCircuitThreshold {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: circuit failure threshold constants invalid",
			Control: control,
			Details: map[string]any{
				"default_circuit_failure_threshold":      defaultCircuitThreshold,
				"absolute_max_circuit_failure_threshold": absoluteCircuitThreshold,
			},
		}
	}
	if defaultCircuitOpenSec <= 0 {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: DefaultCircuitOpenDuration must be positive",
			Control: control,
			Details: map[string]any{
				"default_circuit_open_duration_seconds": defaultCircuitOpenSec,
			},
		}
	}
	// Wave 49 Track B: min/absolute circuit open duration (seconds) must be
	// positive with absolute ≥ min, and default must sit within [min, absolute].
	if minCircuitOpenSec <= 0 || absoluteCircuitOpenSec <= 0 ||
		absoluteCircuitOpenSec < minCircuitOpenSec ||
		defaultCircuitOpenSec < minCircuitOpenSec ||
		defaultCircuitOpenSec > absoluteCircuitOpenSec {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: circuit open duration min/absolute constants invalid",
			Control: control,
			Details: map[string]any{
				"min_circuit_open_duration_seconds":          minCircuitOpenSec,
				"default_circuit_open_duration_seconds":      defaultCircuitOpenSec,
				"absolute_max_circuit_open_duration_seconds": absoluteCircuitOpenSec,
			},
		}
	}
	// MaxConcurrent default is 0 = unlimited; reject negative package default.
	// Absolute max concurrent must still be positive (ceiling when a semaphore
	// is installed) even though the default is unlimited.
	if defaultMaxConcurrent < 0 {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: DefaultMaxConcurrent must be non-negative",
			Control: control,
			Details: map[string]any{
				"default_max_concurrent": defaultMaxConcurrent,
			},
		}
	}
	// Wave 50 Track B: absolute concurrent ceiling must be positive.
	if absoluteMaxConcurrent < 1 {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: AbsoluteMaxConcurrent must be positive",
			Control: control,
			Details: map[string]any{
				"default_max_concurrent":  defaultMaxConcurrent,
				"absolute_max_concurrent": absoluteMaxConcurrent,
			},
		}
	}
	// Wave 50–52 Track B: retry backoff defaults and resolve bounds must be
	// positive with min ≤ default ≤ absolute for initial and max, absolute max
	// backoff ≥ absolute max initial (sanity), and default max ≥ default initial.
	if defaultInitialBackoffMs <= 0 || defaultMaxBackoffMs <= 0 ||
		minInitialBackoffMs <= 0 || absoluteMaxInitialBackoffMs <= 0 ||
		minMaxBackoffMs <= 0 || absoluteMaxMaxBackoffMs <= 0 ||
		defaultMaxBackoffMs < defaultInitialBackoffMs ||
		defaultInitialBackoffMs < minInitialBackoffMs ||
		defaultInitialBackoffMs > absoluteMaxInitialBackoffMs ||
		defaultMaxBackoffMs < minMaxBackoffMs ||
		defaultMaxBackoffMs > absoluteMaxMaxBackoffMs ||
		absoluteMaxMaxBackoffMs < absoluteMaxInitialBackoffMs {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: retry backoff constants invalid",
			Control: control,
			Details: map[string]any{
				"min_initial_backoff_ms":          minInitialBackoffMs,
				"default_initial_backoff_ms":      defaultInitialBackoffMs,
				"absolute_max_initial_backoff_ms": absoluteMaxInitialBackoffMs,
				"min_max_backoff_ms":              minMaxBackoffMs,
				"default_max_backoff_ms":          defaultMaxBackoffMs,
				"absolute_max_max_backoff_ms":     absoluteMaxMaxBackoffMs,
			},
		}
	}
	// Wave 52–53 Track B: mutation package honesty — positive defaults and
	// resolve bounds; confirm cooldown must be strictly less than token TTL
	// (MUT-001 expire window); min ≤ default ≤ absolute for confirm cooldown
	// and token TTL; 1 ≤ default max previews ≤ absolute max previews.
	if defaultMutationConfirmCooldownMs <= 0 ||
		defaultMutationMaxPreviewsPerMinute <= 0 ||
		defaultMutationTokenTTLMs <= 0 ||
		minMutationConfirmCooldownMs <= 0 ||
		absoluteMaxMutationConfirmCooldownMs <= 0 ||
		absoluteMaxMutationMaxPreviewsPerMinute <= 0 ||
		minMutationTokenTTLMs <= 0 ||
		absoluteMaxMutationTokenTTLMs <= 0 ||
		defaultMutationConfirmCooldownMs >= defaultMutationTokenTTLMs ||
		defaultMutationConfirmCooldownMs < minMutationConfirmCooldownMs ||
		defaultMutationConfirmCooldownMs > absoluteMaxMutationConfirmCooldownMs ||
		absoluteMaxMutationConfirmCooldownMs < minMutationConfirmCooldownMs ||
		defaultMutationMaxPreviewsPerMinute < 1 ||
		defaultMutationMaxPreviewsPerMinute > absoluteMaxMutationMaxPreviewsPerMinute ||
		defaultMutationTokenTTLMs < minMutationTokenTTLMs ||
		defaultMutationTokenTTLMs > absoluteMaxMutationTokenTTLMs ||
		absoluteMaxMutationTokenTTLMs < minMutationTokenTTLMs {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: mutation package constants invalid",
			Control: control,
			Details: map[string]any{
				"min_mutation_confirm_cooldown_ms":              minMutationConfirmCooldownMs,
				"default_mutation_confirm_cooldown_ms":          defaultMutationConfirmCooldownMs,
				"absolute_max_mutation_confirm_cooldown_ms":     absoluteMaxMutationConfirmCooldownMs,
				"default_mutation_max_previews_per_minute":      defaultMutationMaxPreviewsPerMinute,
				"absolute_max_mutation_max_previews_per_minute": absoluteMaxMutationMaxPreviewsPerMinute,
				"min_mutation_token_ttl_ms":                     minMutationTokenTTLMs,
				"default_mutation_token_ttl_ms":                 defaultMutationTokenTTLMs,
				"absolute_max_mutation_token_ttl_ms":            absoluteMaxMutationTokenTTLMs,
			},
		}
	}
	// Wave 51 Track B: survey/diagnose package hard ceilings must be positive
	// with hard ≥ default (no intentional zero defaults for these budgets).
	if defaultSurveyMaxTotalBuilds <= 0 || hardSurveyMaxTotalBuilds <= 0 ||
		hardSurveyMaxTotalBuilds < defaultSurveyMaxTotalBuilds {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: survey max total builds constants invalid",
			Control: control,
			Details: map[string]any{
				"default_survey_max_total_builds": defaultSurveyMaxTotalBuilds,
				"hard_survey_max_total_builds":    hardSurveyMaxTotalBuilds,
			},
		}
	}
	if defaultSurveyMaxJobs <= 0 || hardSurveyMaxJobs <= 0 ||
		hardSurveyMaxJobs < defaultSurveyMaxJobs {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: survey max jobs constants invalid",
			Control: control,
			Details: map[string]any{
				"default_survey_max_jobs": defaultSurveyMaxJobs,
				"hard_survey_max_jobs":    hardSurveyMaxJobs,
			},
		}
	}
	if defaultSurveyMaxLogBytesTotal <= 0 || hardSurveyMaxLogBytesTotal <= 0 ||
		hardSurveyMaxLogBytesTotal < defaultSurveyMaxLogBytesTotal {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: survey max log bytes total constants invalid",
			Control: control,
			Details: map[string]any{
				"default_survey_max_log_bytes_total": defaultSurveyMaxLogBytesTotal,
				"hard_survey_max_log_bytes_total":    hardSurveyMaxLogBytesTotal,
			},
		}
	}
	if defaultSurveyMaxWallSeconds <= 0 || hardSurveyMaxWallSeconds <= 0 ||
		hardSurveyMaxWallSeconds < defaultSurveyMaxWallSeconds {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: survey max wall seconds constants invalid",
			Control: control,
			Details: map[string]any{
				"default_survey_max_wall_seconds": defaultSurveyMaxWallSeconds,
				"hard_survey_max_wall_seconds":    hardSurveyMaxWallSeconds,
			},
		}
	}
	if defaultDiagnoseLogBytes <= 0 || hardDiagnoseLogBytes <= 0 ||
		hardDiagnoseLogBytes < defaultDiagnoseLogBytes {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: diagnose log bytes constants invalid",
			Control: control,
			Details: map[string]any{
				"default_diagnose_log_bytes": defaultDiagnoseLogBytes,
				"hard_diagnose_log_bytes":    hardDiagnoseLogBytes,
			},
		}
	}
	if defaultDiagnoseMaxFindings <= 0 || hardDiagnoseMaxFindings <= 0 ||
		hardDiagnoseMaxFindings < defaultDiagnoseMaxFindings {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "operator caps snapshot: diagnose max findings constants invalid",
			Control: control,
			Details: map[string]any{
				"default_diagnose_max_findings": defaultDiagnoseMaxFindings,
				"hard_diagnose_max_findings":    hardDiagnoseMaxFindings,
			},
		}
	}

	return diagnostics.SelfCheckItem{
		Name:    name,
		Status:  diagnostics.SelfCheckOK,
		Message: "operator caps snapshot (secret-free integers)",
		Control: control,
		Details: map[string]any{
			// Hard-max: offline constants only (LiveHardMax is mid-serve).
			"default_hard_max_bytes":      DefaultHardMaxBytes,
			"absolute_max_hard_max_bytes": AbsoluteMaxHardMaxBytes,
			// Wave 47 Track B: soft target offline constants only (serve-bootstrap).
			"default_target_bytes":      DefaultTargetBytes,
			"absolute_max_target_bytes": AbsoluteMaxTargetBytes,
			// Live process collect page caps (defaults until serve Set*).
			"list_jobs_collect_max_pages":              listJobsPages,
			"absolute_max_list_jobs_collect_max_pages": AbsoluteMaxListJobsCollectMaxPages,
			"nodes_collect_max_pages":                  nodesPages,
			"absolute_max_nodes_collect_max_pages":     AbsoluteMaxNodesCollectMaxPages,
			"views_collect_max_pages":                  viewsPages,
			"absolute_max_views_collect_max_pages":     AbsoluteMaxViewsCollectMaxPages,
			// Live artifacts hard cap + absolute bound.
			"artifacts_hard_cap":              artifactsCap,
			"default_artifacts_hard_cap":      jenkins.DefaultArtifactsHardCap,
			"absolute_max_artifacts_hard_cap": jenkins.AbsoluteMaxArtifactsHardCap,
			// Live artifacts list JSON body bound + default/absolute constants.
			"artifacts_list_body_bytes":              artifactsListBody,
			"default_artifacts_list_body_bytes":      jenkins.DefaultArtifactListBodyBytes,
			"absolute_max_artifacts_list_body_bytes": jenkins.AbsoluteMaxArtifactListBodyBytes,
			// Wave 45 Track B: Streamable HTTP MaxBodyBytes constants only (no live serve).
			"default_http_max_body_bytes":      defaultHTTPBody,
			"absolute_max_http_max_body_bytes": absoluteHTTPBody,
			// Wave 45 Track B: identity re-verify TTL bounds (seconds; no live gate TTL offline).
			"min_identity_reverify_ttl_seconds":     minIdentityTTLSec,
			"max_identity_reverify_ttl_seconds":     maxIdentityTTLSec,
			"default_identity_reverify_ttl_seconds": defaultIdentityTTLSec,
			// Wave 46–50 Track B / NET-003: Jenkins resilience package constants only
			// (no live client circuit/retry/concurrency state offline).
			"default_max_json_body_bytes":            defaultMaxJSONBody,
			"absolute_max_json_body_bytes":           absoluteMaxJSONBody,
			"default_max_retries":                    defaultMaxRetries,
			"absolute_max_retries":                   absoluteMaxRetries,
			"default_circuit_failure_threshold":      defaultCircuitThreshold,
			"absolute_max_circuit_failure_threshold": absoluteCircuitThreshold,
			"default_circuit_open_duration_seconds":  defaultCircuitOpenSec,
			// Wave 49 Track B: circuit open duration min/absolute + MaxConcurrent honesty.
			"min_circuit_open_duration_seconds":          minCircuitOpenSec,
			"absolute_max_circuit_open_duration_seconds": absoluteCircuitOpenSec,
			// 0 = unlimited concurrency (not a missing value); absolute is the
			// positive ceiling when a semaphore is installed (Wave 50 Track B).
			"default_max_concurrent":           defaultMaxConcurrent,
			"absolute_max_concurrent":          absoluteMaxConcurrent,
			"max_concurrent_unlimited_default": defaultMaxConcurrent == 0,
			// Wave 50–52 Track B: retry backoff defaults + resolve bounds (ms).
			"min_initial_backoff_ms":          minInitialBackoffMs,
			"default_initial_backoff_ms":      defaultInitialBackoffMs,
			"absolute_max_initial_backoff_ms": absoluteMaxInitialBackoffMs,
			"min_max_backoff_ms":              minMaxBackoffMs,
			"default_max_backoff_ms":          defaultMaxBackoffMs,
			"absolute_max_max_backoff_ms":     absoluteMaxMaxBackoffMs,
			// Wave 52–53 Track B: mutation package honesty + resolve bounds
			// (offline constants only; no live Manager).
			"min_mutation_confirm_cooldown_ms":              minMutationConfirmCooldownMs,
			"default_mutation_confirm_cooldown_ms":          defaultMutationConfirmCooldownMs,
			"absolute_max_mutation_confirm_cooldown_ms":     absoluteMaxMutationConfirmCooldownMs,
			"default_mutation_max_previews_per_minute":      defaultMutationMaxPreviewsPerMinute,
			"absolute_max_mutation_max_previews_per_minute": absoluteMaxMutationMaxPreviewsPerMinute,
			"min_mutation_token_ttl_ms":                     minMutationTokenTTLMs,
			"default_mutation_token_ttl_ms":                 defaultMutationTokenTTLMs,
			"absolute_max_mutation_token_ttl_ms":            absoluteMaxMutationTokenTTLMs,
			// Wave 51 Track B: survey package hard ceilings (offline constants only).
			"default_survey_max_total_builds":    defaultSurveyMaxTotalBuilds,
			"hard_survey_max_total_builds":       hardSurveyMaxTotalBuilds,
			"default_survey_max_jobs":            defaultSurveyMaxJobs,
			"hard_survey_max_jobs":               hardSurveyMaxJobs,
			"default_survey_max_log_bytes_total": defaultSurveyMaxLogBytesTotal,
			"hard_survey_max_log_bytes_total":    hardSurveyMaxLogBytesTotal,
			"default_survey_max_wall_seconds":    defaultSurveyMaxWallSeconds,
			"hard_survey_max_wall_seconds":       hardSurveyMaxWallSeconds,
			// Wave 51 Track B: diagnose package hard ceilings (offline constants only).
			"default_diagnose_log_bytes":    defaultDiagnoseLogBytes,
			"hard_diagnose_log_bytes":       hardDiagnoseLogBytes,
			"default_diagnose_max_findings": defaultDiagnoseMaxFindings,
			"hard_diagnose_max_findings":    hardDiagnoseMaxFindings,
			// Honesty: not mid-serve LiveHardMax / resolved soft target / live circuit.
			"live_hard_max_available_offline":     false,
			"live_target_bytes_available_offline": false,
		},
	}
}
