// Package tools registers MCP tools; handlers call the Jenkins client and do not build raw HTTP.
package tools

import (
	"context"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/mutation"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

// AuthGate fails closed when the serve session is no longer usable (token
// revoked, OIDC refresh failed, logout residual Disable, or mid-serve whoAmI
// principal drift). Implemented by *auth.SessionGuard, *auth.LiveSessionSource,
// *auth.IdentityReverifyGate, and *auth.MultiGate. Nil ⇒ no session gate
// (legacy / unit tests). Production serve always attaches at least whoAmI re-verify.
type AuthGate interface {
	Check() error
}

// RegisterOptions configures POL-001 read-only gating, MCP-001 budgets, and
// optional deny-only MCP RBAC (POL-002/003).
// Nil options (or Register with nil opts) use pilot defaults: read-only true,
// 64 KiB / 1 MiB budgets, no RBAC evaluator (tools not filtered by policy).
type RegisterOptions struct {
	// Gate is the global read-only kill switch. Nil ⇒ fail-closed read-only.
	Gate *policy.ReadOnlyGate
	// Budgets enforces central result size limits. Zero value uses defaults.
	// Overlay max_result_bytes may lower HardMaxBytes at bootstrap (LowerHardMax).
	Budgets Budgets
	// LiveHardMax is an optional shared hard max for result enforcement (Wave 25/31/37).
	// When set, tool dispatch uses this live value instead of Budgets.HardMaxBytes
	// so policy reload can SetWithinCeiling mid-serve (raise/lower ≤ bootstrap ceiling
	// from ResolveHardMaxBytes / --hard-max-bytes / JENKINS_MCP_HARD_MAX_BYTES).
	// Nil ⇒ Budgets.HardMaxBytes only. Soft TargetBytes is clamped to the live hard max.
	LiveHardMax *LiveHardMax
	// PreferBudgetError, when true, returns CodeQuota instead of a truncated
	// summary when the hard max is exceeded (tests / strict mode).
	PreferBudgetError bool
	// Policy is an optional deny-only MCP RBAC evaluator (POL-002).
	// When set, tools denied for Subject are filtered from ListTools via live
	// middleware (Wave 28) and re-checked at dispatch. Read tools stay registered
	// so deny_tools hot-reload can re-expose them without restart. Nil ⇒ no MCP
	// RBAC filter (RO gate still applies).
	Policy policy.PolicyEvaluator
	// Subject is the trusted identity for Policy evaluation (POL-003).
	// Must be built from verified/provisional process identity, never tool args.
	// Empty subject causes Policy to deny when Policy is non-nil.
	Subject policy.Subject
	// AuthGate is optional session continuity (revocation / refresh fail / logout /
	// AUTH-004 mid-serve whoAmI re-verify). When set, Check() runs before every
	// tool handler (fail closed) and before tools/list filtering (Wave 29: empty
	// discovery on session death so names are not advertised after revoke).
	// Production serve wires IdentityReverifyGate for api_token and
	// MultiGate(Live, Reverify) for OIDC. Nil ⇒ no session gate (unit tests).
	AuthGate AuthGate
	// Logs is optional local logmirror/store access (LOG-004). When non-nil,
	// jenkins_get_build_logs / jenkins_get_build_log_tail prefer EnsureMirrored
	// + local ReadRange/Tail, with CheckStoreRead before cache reads. Falls back
	// to the direct Jenkins client on mirror failure (compat).
	// When Logs implements MultiLogAcquirer with a live Coordinator (e.g.
	// *MirrorLogAccess with Coord), jenkins_mirror_logs is also registered.
	Logs LogAccess
	// MultiLog optionally enables jenkins_mirror_logs without relying on the
	// LogAccess type assertion (tests / alternate wiring). Nil ⇒ derive from Logs.
	MultiLog MultiLogAcquirer
	// LogSearch enables jenkins_search_logs over local L1 frames (SEARCH-001/002).
	// Nil ⇒ tool is not registered.
	LogSearch LogSearcher
	// Diagnostics optional helpers for jenkins_diagnose_build (DIAG-002).
	Diagnostics DiagnoseHelpers
	// Doctor optional doctor runner for jenkins_doctor MCP tool (OPS-001).
	Doctor DoctorFunc
	// Audit is an optional privacy-preserving audit sink (AUD-001).
	Audit audit.Sink
	// Metrics is an optional in-process metrics bag (OBS-001).
	Metrics *telemetry.Metrics
	// Logger is an optional structured stderr logger (OBS-001). When nil, tool
	// dispatch falls back to telemetry.Global().Logger if set (serve wires both).
	// Levels: tool_ok/debug, tool_deny/warn, tool_error/error — secret-free only.
	Logger *telemetry.Logger
	// ProfileID / PrincipalID for audit attribution (non-secret).
	ProfileID   string
	PrincipalID string
	// Mutations is the MUT-001 preview/confirm gate. When nil and mutations are
	// registered, handlers create a default manager bound to Gate/Audit/identity.
	Mutations *mutation.Manager
	// DiagCache is the PERF-003 shared fetch cache for diagnose/compare/graph.
	// Nil ⇒ a new per-Register cache (process-scoped for a single MCP serve).
	DiagCache *FetchCache
	// DiagOpBudgets optionally lowers per-operation remote call/byte/wall ceilings
	// for diagnostic tools (PERF-003). Zero fields keep tool defaults.
	DiagOpBudgets DiagBudgetConfig
	// Meta is the optional profile SQLite metadata store (schema v7+). When set,
	// jenkins_survey_recent_failures uses durable compact signature summaries
	// (hashes + short redacted text only — never log bodies). Nil ⇒ process TTL
	// cache only. Serve wires store.Open(dataDir) when a profile data dir is open.
	Meta *store.Meta
	// EnableTraceRefs registers jenkins_get_trace_refs and optional diagnose
	// enrichment (INT-002). Default false. Pure extraction from Jenkins build
	// parameters; no OTLP export. Serve sets true when otel-correlate adapter is enabled.
	EnableTraceRefs bool
	// TraceExporter enables jenkins_export_trace_refs (INT-002 export stub). Nil ⇒
	// tool not registered. Serve wires the otel-export adapter when
	// --enable-adapter=otel-export. Metadata envelopes only; no log text / OTLP protobuf.
	TraceExporter TraceExporter
	// ExternalLogs enables jenkins_query_external_logs (INT-003). Nil ⇒ tool not
	// registered. Serve wires the ext-logs adapter when --enable-adapter=ext-logs.
	ExternalLogs ExternalLogQuerier
	// EnableChangeCorrelation registers jenkins_get_change_correlation (INT-004).
	// Default false. Pure extraction from Jenkins params/changeSets. Serve sets
	// true when work-items adapter is enabled.
	EnableChangeCorrelation bool
	// WorkItemLookup is optional work-items adapter stub (refs only; no network).
	// Used only when EnableChangeCorrelation is true.
	WorkItemLookup WorkItemLookuper
}

// regState is the effective configuration for one Register call.
type regState struct {
	gate            *policy.ReadOnlyGate
	budget          Budgets
	liveHardMax     *LiveHardMax
	strict          bool
	policy          policy.PolicyEvaluator
	subject         policy.Subject
	authGate        AuthGate
	enableTraceRefs bool
	traceExporter   TraceExporter
	logs            LogAccess
	multiLog        MultiLogAcquirer

	externalLogs            ExternalLogQuerier
	enableChangeCorrelation bool
	workItemLookup          WorkItemLookuper

	audit       audit.Sink
	metrics     *telemetry.Metrics
	logger      *telemetry.Logger
	profileID   string
	principalID string
	logSearch   LogSearcher
	diagnose    DiagnoseHelpers
	doctor      DoctorFunc
	mutations   *mutation.Manager

	// PERF-003
	fetchCache *FetchCache
	diagBudget DiagBudgetConfig

	// Profile Meta for durable survey compact cache (schema v7); optional.
	meta *store.Meta
}

func resolveRegisterOptions(opts *RegisterOptions) regState {
	st := regState{
		gate:       policy.NewDefaultReadOnlyGate(),
		budget:     DefaultBudgets(),
		fetchCache: NewFetchCache(FetchCacheConfig{}),
	}
	if opts == nil {
		return st
	}
	if opts.Gate != nil {
		st.gate = opts.Gate
	}
	if opts.Budgets != (Budgets{}) {
		st.budget = opts.Budgets.Normalize()
	}
	st.liveHardMax = opts.LiveHardMax
	st.strict = opts.PreferBudgetError
	st.policy = opts.Policy
	st.subject = opts.Subject
	st.authGate = opts.AuthGate
	st.enableTraceRefs = opts.EnableTraceRefs
	st.traceExporter = opts.TraceExporter
	st.logs = opts.Logs
	st.multiLog = opts.MultiLog
	st.externalLogs = opts.ExternalLogs
	st.enableChangeCorrelation = opts.EnableChangeCorrelation
	st.workItemLookup = opts.WorkItemLookup
	st.logSearch = opts.LogSearch
	st.diagnose = opts.Diagnostics
	st.doctor = opts.Doctor
	st.audit = opts.Audit
	st.metrics = opts.Metrics
	st.logger = opts.Logger
	st.profileID = opts.ProfileID
	st.principalID = opts.PrincipalID
	st.mutations = opts.Mutations
	if opts.DiagCache != nil {
		st.fetchCache = opts.DiagCache
	}
	st.diagBudget = opts.DiagOpBudgets
	st.meta = opts.Meta
	// MUT-001: process-scoped manager so preview tokens survive until confirm.
	// Create once when mutations may register and caller did not inject one.
	// Wave 30: also create under AllowMutations opt-in while Effective RO so
	// force-clear can use the same manager once ListTools re-exposes tools.
	// Rate/cooldown zeros → production defaults (process live after serve
	// Resolve+Set when positive, else 30 previews/min and 5s confirm cooldown).
	if st.mutations == nil && st.gate != nil && st.gate.ShouldRegisterMutations() {
		st.mutations = mutation.NewManager(mutation.Config{
			Gate:        st.gate,
			Audit:       st.audit,
			ProfileID:   st.profileID,
			PrincipalID: st.principalID,
		})
	}
	return st
}

// effectiveBudget returns budgets for EnforceBudget, applying LiveHardMax when set.
// Soft target is clamped to the live hard max. Budgets value type is not mutated.
func (st regState) effectiveBudget() Budgets {
	b := st.budget.Normalize()
	if st.liveHardMax == nil {
		return b
	}
	if n := st.liveHardMax.Get(); n > 0 {
		b.HardMaxBytes = n
		if b.TargetBytes > b.HardMaxBytes {
			b.TargetBytes = b.HardMaxBytes
		}
	}
	return b
}

// LowerHardMax returns budgets with HardMaxBytes reduced to maxBytes when
// maxBytes is positive and smaller than the current hard max (policy can only
// lower limits). Soft target is clamped accordingly.
func LowerHardMax(b Budgets, maxBytes int) Budgets {
	b = b.Normalize()
	if maxBytes <= 0 {
		return b
	}
	if maxBytes < b.HardMaxBytes {
		b.HardMaxBytes = maxBytes
	}
	if b.TargetBytes > b.HardMaxBytes {
		b.TargetBytes = b.HardMaxBytes
	}
	return b
}

// Register attaches seed Jenkins MCP tools to the server.
// Mutation tools are omitted by default under pilot RO (POL-001). Wave 30:
// when AllowMutations opt-in is set, mutations are registered even if
// Effective RO (e.g. force_read_only) so a later force clear can re-expose
// them via ListTools; DenyMutation still denies dispatch while Effective.
// All structured results pass through EnforceBudget (MCP-001).
func Register(s *mcp.Server, client *jenkins.Client, opts *RegisterOptions) {
	st := resolveRegisterOptions(opts)

	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_get_jobs",
		Description: "Get paginated list of root Jenkins jobs with status (offset/limit or opaque page_token; prefer jenkins_list_jobs for folders)"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetJobsToolArgs) (*mcp.CallToolResult, jenkins.GetJobsToolResponse, error) {
			// MCP-001: opaque page_token + offset/limit; EnforceBudget still caps full response size.
			res, err := client.GetJobs(ctx, args)
			if err != nil {
				return nil, jenkins.GetJobsToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*res)
		})

	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_get_job",
		Description: "Get detailed information about a specific Jenkins job by full name (folder/job path; not an http URL). Accepts name (seed) or job_name (alias); job_name wins when both are set."},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetJobToolArgs) (*mcp.CallToolResult, jenkins.Job, error) {
			// MCP-002: name / job_name → JobRef.FullName; reject absolute URLs.
			// Prefer job_name when both present (aligns with policyTargetFromArgs).
			raw, field := args.Name, "name"
			if jn := strings.TrimSpace(args.JobName); jn != "" {
				raw, field = jn, "job_name"
			}
			name, err := jobFullName(field, raw)
			if err != nil {
				return nil, jenkins.Job{}, err
			}
			if args.MaxBuilds <= 0 {
				args.MaxBuilds = 20
			}
			job, err := client.GetJenkinsJob(ctx, name, args.MaxBuilds)
			if err != nil {
				return nil, jenkins.Job{}, mapToolErr(err)
			}
			return structuredResult(*job)
		})
	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_get_running_builds",
		Description: "Get list of currently running Jenkins builds"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetRunningBuildsToolArgs) (*mcp.CallToolResult, jenkins.GetRunningBuildsToolResponse, error) {
			runningBuilds, err := client.GetRunningBuilds(ctx)
			if err != nil {
				return nil, jenkins.GetRunningBuildsToolResponse{}, mapToolErr(err)
			}
			queuedBuilds, err := client.GetQueuedBuilds(ctx)
			if err != nil {
				// Degrade gracefully if queue endpoint is unavailable
				queuedBuilds = nil
			}
			return structuredResult(jenkins.GetRunningBuildsToolResponse{Builds: runningBuilds, Queued: queuedBuilds})
		})

	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_get_build",
		Description: "Get detailed information about a specific Jenkins build by job full name and build number"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetBuildToolArgs) (*mcp.CallToolResult, jenkins.GetBuildToolResponse, error) {
			// MCP-002: job_name + build_number → BuildRef.
			bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
			if err != nil {
				return nil, jenkins.GetBuildToolResponse{}, err
			}
			build, err := client.GetBuildDetailsByJob(ctx, bref.Job.FullName, int(bref.Number))
			if err != nil {
				return nil, jenkins.GetBuildToolResponse{}, mapToolErr(err)
			}
			b := prepareBuildForModel(*build)
			return structuredResult(b)
		})

	addReadTool(s, st, &mcp.Tool{
		Name: "jenkins_get_build_logs",

		Description: "Get build logs for a job full name and build number starting at a given offset (LogEvidence range; not a URL)"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetBuildLogsToolArgs) (*mcp.CallToolResult, any, error) {
			// MCP-002: flattened LogEvidenceRef (job_name, build_number, offset, length).
			le, err := logEvidence("job_name", args.Name, "build_number", args.BuildNumber, args.Offset, args.Length, DefaultLogLength)
			if err != nil {
				return nil, nil, err
			}
			job := le.Build.Job.FullName
			build := int(le.Build.Number)
			// LOG-004: prefer local logmirror/store when configured.
			if st.logs != nil {
				if resp, ok, err := readLogsViaAccess(ctx, st, job, build, int(le.Offset), int(le.Length)); err != nil {
					return nil, nil, err
				} else if ok {
					return structuredResult(resp)
				}
				// Mirror unavailable / incomplete — fall back to direct client.
			}
			logsResponse, err := client.GetBuildLogs(ctx, job, build, int(le.Offset), int(le.Length))
			if err != nil {
				return nil, jenkins.GetBuildLogsToolResponse{}, mapToolErr(err)
			}
			return structuredResult(PrepareBuildLogsForModel(logsResponse))
		})

	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_get_build_log_tail",
		Description: "Get the tail of build logs for a job full name and build number"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetBuildLogTailToolArgs) (*mcp.CallToolResult, any, error) {
			bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
			if err != nil {
				return nil, nil, err
			}
			if args.MaxLength <= 0 {
				args.MaxLength = 8192
			}
			job := bref.Job.FullName
			build := int(bref.Number)
			// LOG-004: prefer local tail from committed frames when configured.
			if st.logs != nil {
				if resp, ok, err := tailLogsViaAccess(ctx, st, job, build, args.MaxLength); err != nil {
					return nil, nil, err
				} else if ok {
					return structuredResult(resp)
				}
			}
			logsResponse, err := client.GetBuildLogTail(ctx, job, build, args.MaxLength)
			if err != nil {
				return nil, jenkins.GetBuildLogTailToolResponse{}, mapToolErr(err)
			}
			return structuredResult(PrepareBuildLogsForModel(logsResponse))
		})

	// POL-001 + MUT-001/002: mutation tools only when gate allows registration.
	// Without confirmation_token → preview; with valid token → single execute.
	addMutationTool(s, st, &mcp.Tool{
		Name:        policy.ToolStartJob,
		Description: "Preview or trigger a Jenkins job build (MUT-002). Without confirmation_token returns a short-lived preview token; with a valid token enqueues once. Secret-named parameters are rejected. Pilot only when --allow-mutations and not forced RO."},
		startJobHandler(client, st))

	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_get_queue_item",
		Description: "Get the current state of a Jenkins queue item, including the assigned build when available"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetQueueItemToolArgs) (*mcp.CallToolResult, jenkins.QueueItem, error) {
			// MCP-002: queue_id (+ optional profile) → QueueItemRef.
			qref, err := queueItemRef("queue_id", args.QueueID, args.Profile)
			if err != nil {
				return nil, jenkins.QueueItem{}, err
			}
			item, err := client.GetQueueItem(ctx, int(qref.ID))
			if err != nil {
				return nil, jenkins.QueueItem{}, mapToolErr(err)
			}
			return structuredResult(*item)
		})

	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_wait_for_queue_item",
		Description: "Wait for a Jenkins queue item to receive a build assignment, be cancelled, or timeout"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.WaitForQueueItemToolArgs) (*mcp.CallToolResult, jenkins.WaitForQueueItemToolResponse, error) {
			qref, err := queueItemRef("queue_id", args.QueueID, args.Profile)
			if err != nil {
				return nil, jenkins.WaitForQueueItemToolResponse{}, err
			}
			if args.TimeoutSeconds <= 0 {
				args.TimeoutSeconds = 30
			}
			if args.PollIntervalSec <= 0 {
				args.PollIntervalSec = 2
			}
			res, err := client.WaitForQueueItem(ctx, int(qref.ID), args.TimeoutSeconds, args.PollIntervalSec)
			if err != nil {
				return nil, jenkins.WaitForQueueItemToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*res)
		})

	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_search_builds",
		Description: "Search Jenkins builds by result and/or build parameters. Use to find e.g. the latest successful ARM build or a build without a specific feature branch."},

		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.SearchBuildsToolArgs) (*mcp.CallToolResult, jenkins.SearchBuildsToolResponse, error) {
			name, err := jobFullName("job_name", args.JobName)
			if err != nil {
				return nil, jenkins.SearchBuildsToolResponse{}, err
			}
			args.JobName = name
			if args.Limit <= 0 {
				args.Limit = 5
			}
			if args.MaxLookback <= 0 {
				args.MaxLookback = 100
			}
			res, err := client.SearchBuilds(ctx, args)
			if err != nil {
				return nil, jenkins.SearchBuildsToolResponse{}, mapToolErr(err)
			}
			out := prepareSearchBuildsForModel(res)
			return structuredResult(out)
		})

	// POL-001 + MUT-001/003: stop requires confirmation; finished builds refused.
	addMutationTool(s, st, &mcp.Tool{
		Name:        policy.ToolStopBuild,
		Description: "Preview or stop a running Jenkins build (MUT-003). Without confirmation_token returns a short-lived preview token; with a valid token stops once. Finished builds return a clear error. Pilot only when --allow-mutations and not forced RO."},
		stopBuildHandler(client, st))

	// POL-001 + MUT-003: queue cancel is a separate action from build stop.
	addMutationTool(s, st, &mcp.Tool{
		Name:        policy.ToolCancelQueueItem,
		Description: "Preview or cancel a Jenkins queue item (MUT-003). Without confirmation_token returns a short-lived preview token; with a valid token cancels once via /queue/cancelItem. Missing/already-left/already-cancelled items return a clear error (not success). Pilot only when --allow-mutations and not forced RO."},
		cancelQueueItemHandler(client, st))

	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_wait_for_running_build",
		Description: "Wait for a running Jenkins build to complete or timeout"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.WaitForRunningBuildToolArgs) (*mcp.CallToolResult, jenkins.WaitForRunningBuildToolResponse, error) {
			bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
			if err != nil {
				return nil, jenkins.WaitForRunningBuildToolResponse{}, err
			}
			if args.TimeoutSeconds <= 0 {
				args.TimeoutSeconds = 600
			}
			resObj, err := client.WaitForRunningBuild(ctx, bref.Job.FullName, int(bref.Number), args.TimeoutSeconds)
			if err != nil {
				return nil, jenkins.WaitForRunningBuildToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*resObj)
		})
	registerSearchLogsTool(s, st)
	registerMirrorLogsTool(s, client, st)
	registerJenPipeTestTools(s, client, st)
	registerHealthTools(s, client, st)
	registerViewsTools(s, client, st)
	registerDoctorTool(s, st, st.doctor)
	registerDiagnoseBuildTool(s, client, st)
	registerTraceRefsTool(s, client, st)
	registerExportTraceRefsTool(s, st, client)
	registerExternalLogsTool(s, st, client)
	registerChangeCorrelationTool(s, client, st)
	registerCompareBuildsTool(s, client, st)
	registerFindRegressionWindowTool(s, client, st)
	registerTraceFailureGraphTool(s, client, st)
	registerSurveyRecentFailuresTool(s, client, st)

	// Wave 28+29: live ListTools filter for AuthGate / deny_tools / subject / RO.
	InstallListToolsPolicyFilter(s, st)
}

// addReadTool registers a non-mutating tool with budget enforcement.
// Read tools are always registered when requested; deny_tools filtering is
// applied live on tools/list (InstallListToolsPolicyFilter) so policy reload
// can re-expose tools without re-Register (Wave 28). Dispatch still re-checks.
func addReadTool[In, Out any](s *mcp.Server, st regState, t *mcp.Tool, h func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, Out, error)) {
	addTool(s, st, t, policy.EffectRead, h)
}

// addMutationTool registers a mutation tool when the gate allows registration.
// Wave 30: register when fully write-enabled OR AllowMutations opt-in (even if
// Effective RO), so force_read_only clear can re-list without restart.
// Handlers always re-check DenyMutation so dispatch fails closed under RO.
// deny_tools does not skip registration (ListTools filter + dispatch handle it).
// Nil gate ⇒ fail-closed omit (default RO; no surprise mutations).
func addMutationTool[In, Out any](s *mcp.Server, st regState, t *mcp.Tool, h func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, Out, error)) {
	if st.gate == nil || !st.gate.ShouldRegisterMutations() {
		// POL-001: omit when no write opt-in and Effective RO (or nil gate).
		// Without AllowMutations, force clear cannot invent unregistered tools.
		emitToolDeny(context.Background(), st, t.Name, string(policy.EffectMutate), "read_only", time.Now())
		return
	}
	addTool(s, st, t, policy.EffectMutate, h)
}

// RegisterMutationToolsForTest registers mutation tools even under read-only,
// wrapping handlers so invocations are denied with policy_denial. Used to
// prove crafted/direct dispatch fail closed (POL-001). Production Register
// never calls this. Installs ListTools filter so force-registered mutations
// still disappear from discovery while the gate is effectively RO.
func RegisterMutationToolsForTest(s *mcp.Server, client *jenkins.Client, gate *policy.ReadOnlyGate) {
	if gate == nil {
		gate = policy.NewDefaultReadOnlyGate()
	}
	st := regState{
		gate:      gate,
		budget:    DefaultBudgets(),
		mutations: mutation.NewManager(mutation.Config{Gate: gate}),
	}
	// Force-register with mutate effect (gate deny at call time before handler).
	forceAddMutation(s, st, &mcp.Tool{
		Name:        policy.ToolStartJob,
		Description: "Trigger a Jenkins job build with optional parameters"},
		startJobHandler(client, st))
	forceAddMutation(s, st, &mcp.Tool{
		Name:        policy.ToolStopBuild,
		Description: "Stop a running Jenkins build by job name and build number"},
		stopBuildHandler(client, st))
	forceAddMutation(s, st, &mcp.Tool{
		Name:        policy.ToolCancelQueueItem,
		Description: "Cancel a Jenkins queue item by queue id"},
		cancelQueueItemHandler(client, st))
	InstallListToolsPolicyFilter(s, st)
}

func forceAddMutation[In, Out any](s *mcp.Server, st regState, t *mcp.Tool, h func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, Out, error)) {
	addTool(s, st, t, policy.EffectMutate, h)
}

func addTool[In, Out any](
	s *mcp.Server,
	st regState,
	t *mcp.Tool,
	effect policy.EffectClass,
	h func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, Out, error),
) {
	if t.InputSchema == nil {
		t.InputSchema = jsonschemaForExt[In]()
	}
	// Out type is any so budget truncation can return TruncatedResult summaries
	// without fighting per-tool output schemas (MCP-001).
	mcp.AddTool(s, t, func(ctx context.Context, req *mcp.CallToolRequest, args In) (*mcp.CallToolResult, any, error) {
		start := time.Now()
		// OBS-001: count every dispatch attempt (including denials).
		// Outcome counters (ok/error/deny) are separate — no per-tool name labels.
		if st.metrics != nil {
			st.metrics.Inc(telemetry.MetricToolCalls, 1)
		}
		// Pilot offline analysis (debug): tool name + effect only — never args/secrets.
		logToolDebug(st, "tool_dispatch_start",
			"tool", t.Name,
			"effect", string(effect),
		)
		// Session continuity (wave 14): fail closed before policy/handler when
		// the OIDC session is revoked, refresh-failed, or logged out.
		if st.authGate != nil {
			if err := st.authGate.Check(); err != nil {
				mapped := mapToolErr(err)
				emitToolDeny(ctx, st, t.Name, string(effect), "session_gate", start)
				logToolError(st, "tool_dispatch_error", mapped,
					"tool", t.Name, "effect", string(effect), "phase", "session_gate",
					"duration_ms", durationMS(start),
				)
				return nil, nil, mapped
			}
		}
		// POL-001: mutation re-check at dispatch.
		if effect == policy.EffectMutate {
			if err := st.gate.DenyMutation(t.Name); err != nil {
				emitToolDeny(ctx, st, t.Name, string(effect), "read_only", start)
				return nil, nil, err
			}
		}
		// POL-002/003/004: deny-only RBAC re-check at dispatch (defense in depth).
		// Subject is process-bound; tool arguments never choose the subject.
		// Job-scoped Target is populated from args (job_name / build_number) so
		// deny_job_prefixes apply before the handler; ListTools discovery uses
		// empty Target (see InstallListToolsPolicyFilter / listToolsAllows).
		if st.policy != nil {
			target := policyTargetFromArgs(args)
			d := st.policy.Evaluate(st.subject, policy.Action{ToolName: t.Name, Class: effect}, target)
			if err := d.Err(); err != nil {
				reason := d.ReasonCode
				if reason == "" {
					reason = policy.ReasonExplicitDeny
				}
				emitToolDeny(ctx, st, t.Name, string(effect), reason, start)
				return nil, nil, err
			}
		}
		res, out, err := h(ctx, req, args)
		if err != nil {
			if st.metrics != nil {
				st.metrics.Inc(telemetry.MetricMCPToolError, 1)
			}
			mapped := mapToolErr(err)
			logToolError(st, "tool_dispatch_error", mapped,
				"tool", t.Name, "effect", string(effect), "phase", "handler",
				"duration_ms", durationMS(start),
			)
			return res, nil, mapped
		}
		enforced, _, berr := EnforceBudgetOrError(out, st.effectiveBudget(), st.strict)
		if berr != nil {
			if st.metrics != nil {
				st.metrics.Inc(telemetry.MetricMCPToolError, 1)
			}
			mapped := mapToolErr(berr)
			logToolError(st, "tool_dispatch_error", mapped,
				"tool", t.Name, "effect", string(effect), "phase", "budget",
				"duration_ms", durationMS(start),
			)
			return nil, nil, mapped
		}
		if st.metrics != nil {
			st.metrics.Inc(telemetry.MetricMCPToolOK, 1)
		}
		logToolDebug(st, "tool_dispatch_ok",
			"tool", t.Name,
			"effect", string(effect),
			"duration_ms", durationMS(start),
		)
		return res, enforced, nil
	})
}

func structuredResult[T any](v T) (*mcp.CallToolResult, T, error) {
	return &mcp.CallToolResult{}, v, nil
}

// ForceRegisterReadToolForTest registers a read tool without going through
// Register's full inventory (POL-004/005 dispatch tests). Production Register
// always registers reads and filters ListTools live; this helper does not
// install the ListTools filter (call Install via Register or tests that need
// discovery).
func ForceRegisterReadToolForTest[In, Out any](
	s *mcp.Server,
	opts *RegisterOptions,
	t *mcp.Tool,
	h func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, Out, error),
) {
	st := resolveRegisterOptions(opts)
	addTool(s, st, t, policy.EffectRead, h)
}
