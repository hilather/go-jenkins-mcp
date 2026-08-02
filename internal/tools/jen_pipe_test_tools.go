package tools

import (
	"context"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerJenPipeTestTools registers JEN/PIPE/TEST/GRAPH/ART/SCM read tools.
func registerJenPipeTestTools(s *mcp.Server, client *jenkins.Client, st regState) {
	// JEN-001: controller capability discovery (version, Pipeline REST, JUnit).
	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_get_capabilities",
		Description: "Discover Jenkins controller capabilities (version, Pipeline REST API, JUnit) with cache freshness metadata"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetCapabilitiesToolArgs) (*mcp.CallToolResult, jenkins.GetCapabilitiesToolResponse, error) {
			var (
				set jenkins.CapabilitySet
				err error
			)
			if args.Refresh {
				set, err = client.RefreshCapabilities(ctx)
			} else {
				set, err = client.Capabilities(ctx)
			}
			if err != nil {
				return nil, jenkins.GetCapabilitiesToolResponse{}, mapToolErr(err)
			}
			return structuredResult(set)
		})

	// JEN-002: paginated job discovery (folders, multibranch/matrix kinds, filters).
	// Wave 37/39: omit rows matching deny_job_prefixes and/or deny_branch_names
	// (collect+filter+repaginate when patterns live; single ListJobs when empty).
	addReadTool(s, st, &mcp.Tool{
		Name: "jenkins_list_jobs",
		Description: "List Jenkins jobs with typed full-name paths, optional folder/name/view filters, and offset/limit or opaque page_token pagination (no nested graphs by default). " +
			"Jobs matching MCP deny_job_prefixes and branch/matrix_child rows matching deny_branch_names are omitted (privacy filter; full-list when patterns live)."},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.ListJobsToolArgs) (*mcp.CallToolResult, jenkins.ListJobsToolResponse, error) {
			if args.FolderPrefix != "" {
				if _, err := jobFullName("folder_prefix", args.FolderPrefix); err != nil {
					return nil, jenkins.ListJobsToolResponse{}, err
				}
			}
			// MCP-001: page_token wins over offset/limit; invalid tokens fail closed.
			// Wave 39: collect+filter+repaginate when deny patterns live.
			res, err := listJobsWithPolicyFilter(ctx, client, st, args)
			if err != nil {
				return nil, jenkins.ListJobsToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*res)
		})

	// JEN-003: paginated build history.
	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_list_builds",
		Description: "List recent builds for a job with limit/offset or opaque page_token and since_build/result filters; secret parameters are never returned"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.ListBuildsToolArgs) (*mcp.CallToolResult, any, error) {
			name, err := jobFullName("job_name", args.JobName)
			if err != nil {
				return nil, nil, err
			}
			args.JobName = name
			// MCP-001: page_token wins over offset/limit; invalid tokens fail closed.
			// HOST-004: subject-bound page tokens when SubjectKey is set at serve.
			res, err := listBuildsWithSubject(ctx, client, st, args)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			return structuredResult(prepareListBuildsForModel(res))
		})

	// JEN-003: baseline resolution helper.
	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_resolve_baseline",
		Description: "Resolve last successful/failed/unstable/completed/last build number for a job (deterministic baseline)"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.ResolveBaselineToolArgs) (*mcp.CallToolResult, jenkins.ResolveBaselineToolResponse, error) {
			name, err := jobFullName("job_name", args.JobName)
			if err != nil {
				return nil, jenkins.ResolveBaselineToolResponse{}, err
			}
			kind, err := jenkins.ParseBaselineKind(args.Baseline)
			if err != nil {
				return nil, jenkins.ResolveBaselineToolResponse{}, mapToolErr(err)
			}
			res, err := client.ResolveBaseline(ctx, name, kind)
			if err != nil {
				return nil, jenkins.ResolveBaselineToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*res)
		})

	// GRAPH-001: bounded upstream/downstream build graph.
	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_get_build_graph",
		Description: "Traverse bounded upstream/downstream related builds from a root build (depth/node/cycle limits; degrades when cause data is missing)"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetBuildGraphToolArgs) (*mcp.CallToolResult, jenkins.GetBuildGraphToolResponse, error) {
			bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
			if err != nil {
				return nil, jenkins.GetBuildGraphToolResponse{}, err
			}
			args.JobName = bref.Job.FullName
			args.BuildNumber = int(bref.Number)
			res, err := client.GetBuildGraph(ctx, args)
			if err != nil {
				return nil, jenkins.GetBuildGraphToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*res)
		})

	// PIPE-001: Pipeline stage graph when Pipeline REST is available.
	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_get_pipeline_stages",
		Description: "Get Pipeline stage graph (status, duration, parallel children) for a job full name and build number when Pipeline REST is available"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetPipelineStagesToolArgs) (*mcp.CallToolResult, jenkins.GetPipelineStagesToolResponse, error) {
			bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
			if err != nil {
				return nil, jenkins.GetPipelineStagesToolResponse{}, err
			}
			ps, err := client.GetPipelineStages(ctx, bref.Job.FullName, int(bref.Number))
			if err != nil {
				return nil, jenkins.GetPipelineStagesToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*ps)
		})

	// TEST-001: JUnit test report summary + bounded failed cases.
	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_get_test_report",
		Description: "Get JUnit test report summary and bounded failed tests for a job full name and build number"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetTestReportToolArgs) (*mcp.CallToolResult, any, error) {
			bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
			if err != nil {
				return nil, nil, err
			}
			rep, err := client.GetTestReport(ctx, bref.Job.FullName, int(bref.Number), args.MaxFailed)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			return structuredResult(PrepareTestReportForModel(rep))
		})

	// PIPE-002 / TEST-002 / ART-001
	addReadTool(s, st, &mcp.Tool{
		Name: "jenkins_get_stage_log",
		Description: "Get bounded Pipeline stage/node log text by stage_id or stage_name " +
			"(Pipeline REST wfapi/log). Optional mirror writes under a distinct local log key " +
			"(job#stage:id) without touching console generations"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetStageLogToolArgs) (*mcp.CallToolResult, any, error) {
			bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
			if err != nil {
				return nil, nil, err
			}
			sl, err := client.GetStageLog(ctx, bref.Job.FullName, int(bref.Number),
				args.StageID, args.StageName, args.MaxLength)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			// Optional mirror under distinct stage key (PIPE-002).
			if args.Mirror {
				if mir := asStageLogMirror(st.logs); mir != nil {
					if merr := mir.MirrorStageLogBytes(ctx, bref.Job.FullName, bref.Number, sl.StageID, []byte(sl.Logs)); merr == nil {
						sl.Mirrored = true
					}
					// Mirror failure is non-fatal: still return fetched text.
				}
			}
			return structuredResult(PrepareStageLogForModel(sl))
		})

	addReadTool(s, st, &mcp.Tool{
		Name: "jenkins_analyze_tests",
		Description: "Classify current failed tests as new_failure, flaky, known_failure, " +
			"or duration_regression using a bounded lookback of prior compact test outcomes " +
			"(no full history dump; includes sample size and confidence)"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.AnalyzeTestsToolArgs) (*mcp.CallToolResult, any, error) {
			bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
			if err != nil {
				return nil, nil, err
			}
			an, err := client.AnalyzeTests(ctx, bref.Job.FullName, int(bref.Number), args.Lookback, args.MaxResults)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			return structuredResult(PrepareTestAnalysisForModel(an))
		})

	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_list_artifacts",
		Description: "List build artifact paths and metadata without downloading bytes"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.ListArtifactsToolArgs) (*mcp.CallToolResult, jenkins.ListArtifactsToolResponse, error) {
			bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
			if err != nil {
				return nil, jenkins.ListArtifactsToolResponse{}, err
			}
			// Wave 37/40: omit deny_artifact_paths; hard-cap fetch when patterns live
			// so denied paths do not steal max_artifacts page slots.
			list, err := listArtifactsWithPolicyFilter(ctx, client, st, bref.Job.FullName, int(bref.Number), args.MaxArtifacts)
			if err != nil {
				return nil, jenkins.ListArtifactsToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*list)
		})

	addReadTool(s, st, &mcp.Tool{
		Name: "jenkins_get_artifact_text",
		Description: "Download a small text artifact (max 256KiB) with path-traversal protection " +
			"and binary/exec extension refusal; returns sanitized content and SHA-256 of returned bytes"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetArtifactTextToolArgs) (*mcp.CallToolResult, any, error) {
			bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
			if err != nil {
				return nil, nil, err
			}
			at, err := client.GetArtifactText(ctx, bref.Job.FullName, int(bref.Number), args.Path, args.MaxBytes)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			return structuredResult(PrepareArtifactTextForModel(at))
		})

	// ART-002: safe text/JSON/XML inspect + archive inventory (no extract/execute).
	addReadTool(s, st, &mcp.Tool{
		Name: "jenkins_inspect_artifact",
		Description: "Inspect a build artifact safely: bounded text/JSON/XML parse, or zip/tar " +
			"inventory only (zip-slip/symlink/device/bomb blocked; never execute)"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.InspectArtifactToolArgs) (*mcp.CallToolResult, any, error) {
			bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
			if err != nil {
				return nil, nil, err
			}
			ins, err := client.InspectArtifact(ctx, bref.Job.FullName, int(bref.Number),
				args.Path, args.MaxBytes, args.MaxMembers)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			return structuredResult(PrepareArtifactInspectionForModel(ins))
		})

	// SCM-001: build changes / revisions since baseline.
	addReadTool(s, st, &mcp.Tool{
		Name: "jenkins_get_build_changes",
		Description: "Get bounded SCM changeSets/revisions for a build, optionally aggregated since " +
			"a baseline build; credentials stripped from repo URLs; multi-SCM explicit; " +
			"culprits labeled as Jenkins-reported correlation only"},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetBuildChangesToolArgs) (*mcp.CallToolResult, any, error) {
			bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
			if err != nil {
				return nil, nil, err
			}
			args.JobName = bref.Job.FullName
			args.BuildNumber = int(bref.Number)
			res, err := client.GetBuildChanges(ctx, args)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			return structuredResult(PrepareBuildChangesForModel(res))
		})

}
