package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/mutation"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// interruptBuildHandler implements MUT-010: mode stop|term|kill under preview/confirm.
func interruptBuildHandler(client *jenkins.Client, st regState) func(context.Context, *mcp.CallToolRequest, jenkins.InterruptBuildToolArgs) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.InterruptBuildToolArgs) (*mcp.CallToolResult, any, error) {
		bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
		if err != nil {
			return nil, nil, err
		}
		job := bref.Job.FullName
		buildNum := int(bref.Number)
		mode := strings.ToLower(strings.TrimSpace(args.Mode))
		if err := policy.CheckInterruptModeAllowed(st.mutationPolicy, mode); err != nil {
			return nil, nil, err
		}
		if err := policy.CheckMutationJobAllowed(st.mutationPolicy, job); err != nil {
			return nil, nil, err
		}

		build, err := client.GetBuildDetailsByJob(ctx, job, buildNum)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		if build == nil {
			return nil, nil, apperr.New(apperr.CodeNotFound, fmt.Sprintf("job %q build #%d not found", job, buildNum))
		}
		if !build.Building {
			result := strings.TrimSpace(build.Result)
			if result == "" {
				result = "finished"
			}
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf(
				"build already finished (job=%q build=#%d result=%s); interrupt refused",
				job, buildNum, result))
		}

		mgr := ensureMutationManager(st)
		intent := mutation.Intent{
			Action:        mutation.ActionInterruptBuild,
			ToolName:      policy.ToolInterruptBuild,
			JobName:       job,
			BuildNumber:   buildNum,
			Mode:          mode,
			EndpointClass: interruptEndpoint(mode),
			CurrentState:  "building",
		}
		token := strings.TrimSpace(args.ConfirmationToken)
		if token == "" {
			prev, err := mgr.Preview(ctx, intent)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			return structuredResult(prev)
		}
		bound, err := mgr.Confirm(ctx, token, intent)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		build2, err := client.GetBuildDetailsByJob(ctx, bound.JobName, bound.BuildNumber)
		if err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolInterruptBuild, string(bound.Action), "jenkins_error", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		if build2 == nil || !build2.Building {
			mgr.EmitExecuteFail(ctx, policy.ToolInterruptBuild, string(bound.Action), "already_finished", bound.TargetHash)
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf(
				"build already finished (job=%q build=#%d); interrupt refused",
				bound.JobName, bound.BuildNumber))
		}
		resObj, err := client.InterruptBuild(ctx, bound.JobName, bound.BuildNumber, bound.Mode)
		if err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolInterruptBuild, string(bound.Action), "jenkins_error", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		mgr.EmitExecuteOK(ctx, policy.ToolInterruptBuild, string(bound.Action), bound.TargetHash, bound.RequestID)
		return structuredResult(*resObj)
	}
}

func interruptEndpoint(mode string) string {
	switch mode {
	case "term":
		return mutation.EndpointTerm
	case "kill":
		return mutation.EndpointKill
	default:
		return mutation.EndpointStop
	}
}

// rebuildBuildHandler implements MUT-011: rebuild using params from source build.
func rebuildBuildHandler(client *jenkins.Client, st regState) func(context.Context, *mcp.CallToolRequest, jenkins.RebuildBuildToolArgs) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.RebuildBuildToolArgs) (*mcp.CallToolResult, any, error) {
		bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
		if err != nil {
			return nil, nil, err
		}
		job := bref.Job.FullName
		src := int(bref.Number)
		if err := policy.CheckMutationJobAllowed(st.mutationPolicy, job); err != nil {
			return nil, nil, err
		}

		build, err := client.GetBuildDetailsByJob(ctx, job, src)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		if build == nil {
			return nil, nil, apperr.New(apperr.CodeNotFound, fmt.Sprintf("job %q build #%d not found", job, src))
		}
		// Rebuild from prior params only (no free-form secrets from the model).
		raw := make(map[string]any, len(build.Parameters))
		for k, v := range build.Parameters {
			raw[k] = v
		}
		norm, err := mutation.NormalizeParams(raw)
		if err != nil {
			// Secret-named params on the prior build cannot be replayed via model path.
			return nil, nil, mapToolErr(err)
		}
		defs, err := client.GetJobParameterDefinitions(ctx, job)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		if err := mutation.ValidateAgainstDefinitions(norm, toMutationParamDefs(defs)); err != nil {
			return nil, nil, mapToolErr(err)
		}

		mgr := ensureMutationManager(st)
		intent := mutation.Intent{
			Action:        mutation.ActionRebuildBuild,
			ToolName:      policy.ToolRebuildBuild,
			JobName:       job,
			BuildNumber:   src,
			Parameters:    norm,
			EndpointClass: mutation.EndpointRebuild,
			CurrentState:  fmt.Sprintf("rebuild_from_build_%d", src),
		}
		token := strings.TrimSpace(args.ConfirmationToken)
		if token == "" {
			prev, err := mgr.Preview(ctx, intent)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			return structuredResult(prev)
		}
		bound, err := mgr.Confirm(ctx, token, intent)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		// Re-validate defs on confirm (config drift fail-closed).
		defs2, err := client.GetJobParameterDefinitions(ctx, bound.JobName)
		if err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolRebuildBuild, string(bound.Action), "jenkins_error", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		if err := mutation.ValidateAgainstDefinitions(bound.Parameters, toMutationParamDefs(defs2)); err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolRebuildBuild, string(bound.Action), "params_invalid", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		resObj, err := client.RebuildBuild(ctx, bound.JobName, bound.BuildNumber, bound.Parameters)
		if err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolRebuildBuild, string(bound.Action), "jenkins_error", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		mgr.EmitExecuteOK(ctx, policy.ToolRebuildBuild, string(bound.Action), bound.TargetHash, bound.RequestID)
		return structuredResult(*resObj)
	}
}

// replayPipelineHandler implements MUT-012: same-definition replay only (no script edit).
func replayPipelineHandler(client *jenkins.Client, st regState) func(context.Context, *mcp.CallToolRequest, jenkins.ReplayPipelineToolArgs) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.ReplayPipelineToolArgs) (*mcp.CallToolResult, any, error) {
		bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
		if err != nil {
			return nil, nil, err
		}
		job := bref.Job.FullName
		buildNum := int(bref.Number)
		if err := policy.CheckMutationJobAllowed(st.mutationPolicy, job); err != nil {
			return nil, nil, err
		}

		// Capability: Pipeline stages probe is a cheap residual check for Pipeline jobs.
		if _, err := client.GetPipelineStages(ctx, job, buildNum); err != nil {
			// Not all failures mean non-pipeline; still allow preview if build exists.
			if b, berr := client.GetBuildDetailsByJob(ctx, job, buildNum); berr != nil || b == nil {
				return nil, nil, mapToolErr(err)
			}
		}

		mgr := ensureMutationManager(st)
		intent := mutation.Intent{
			Action:        mutation.ActionReplayPipeline,
			ToolName:      policy.ToolReplayPipeline,
			JobName:       job,
			BuildNumber:   buildNum,
			Mode:          "same",
			EndpointClass: mutation.EndpointReplay,
			CurrentState:  "replay_same_definition",
		}
		token := strings.TrimSpace(args.ConfirmationToken)
		if token == "" {
			prev, err := mgr.Preview(ctx, intent)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			return structuredResult(prev)
		}
		bound, err := mgr.Confirm(ctx, token, intent)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		resObj, err := client.ReplayPipeline(ctx, bound.JobName, bound.BuildNumber)
		if err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolReplayPipeline, string(bound.Action), "jenkins_error", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		mgr.EmitExecuteOK(ctx, policy.ToolReplayPipeline, string(bound.Action), bound.TargetHash, bound.RequestID)
		return structuredResult(*resObj)
	}
}

// setJobBuildableHandler implements MUT-013.
func setJobBuildableHandler(client *jenkins.Client, st regState) func(context.Context, *mcp.CallToolRequest, jenkins.SetJobBuildableToolArgs) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.SetJobBuildableToolArgs) (*mcp.CallToolResult, any, error) {
		name, err := jobFullName("job_name", args.JobName)
		if err != nil {
			return nil, nil, err
		}
		if err := policy.CheckMutationJobAllowed(st.mutationPolicy, name); err != nil {
			return nil, nil, err
		}
		mode := "disable"
		if args.Buildable {
			mode = "enable"
		}
		job, err := client.GetJenkinsJob(ctx, name, 0)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		if job == nil {
			return nil, nil, apperr.New(apperr.CodeNotFound, fmt.Sprintf("job %q not found", name))
		}
		mgr := ensureMutationManager(st)
		intent := mutation.Intent{
			Action:        mutation.ActionSetJobBuildable,
			ToolName:      policy.ToolSetJobBuildable,
			JobName:       name,
			Mode:          mode,
			EndpointClass: map[bool]string{true: mutation.EndpointEnable, false: mutation.EndpointDisable}[args.Buildable],
			CurrentState:  fmt.Sprintf("buildable=%v", job.Buildable),
		}
		token := strings.TrimSpace(args.ConfirmationToken)
		if token == "" {
			prev, err := mgr.Preview(ctx, intent)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			return structuredResult(prev)
		}
		bound, err := mgr.Confirm(ctx, token, intent)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		resObj, err := client.SetJobBuildable(ctx, bound.JobName, bound.Mode == "enable")
		if err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolSetJobBuildable, string(bound.Action), "jenkins_error", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		mgr.EmitExecuteOK(ctx, policy.ToolSetJobBuildable, string(bound.Action), bound.TargetHash, bound.RequestID)
		return structuredResult(*resObj)
	}
}

// setBuildKeepForeverHandler implements MUT-014 keep-forever.
func setBuildKeepForeverHandler(client *jenkins.Client, st regState) func(context.Context, *mcp.CallToolRequest, jenkins.SetBuildKeepForeverToolArgs) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.SetBuildKeepForeverToolArgs) (*mcp.CallToolResult, any, error) {
		bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
		if err != nil {
			return nil, nil, err
		}
		job := bref.Job.FullName
		buildNum := int(bref.Number)
		if err := policy.CheckMutationJobAllowed(st.mutationPolicy, job); err != nil {
			return nil, nil, err
		}
		if _, err := client.GetBuildDetailsByJob(ctx, job, buildNum); err != nil {
			return nil, nil, mapToolErr(err)
		}
		mode := "false"
		if args.KeepForever {
			mode = "true"
		}
		mgr := ensureMutationManager(st)
		intent := mutation.Intent{
			Action:        mutation.ActionSetBuildKeepForever,
			ToolName:      policy.ToolSetBuildKeepForever,
			JobName:       job,
			BuildNumber:   buildNum,
			Mode:          mode,
			EndpointClass: mutation.EndpointToggleKeepForever,
			CurrentState:  "keep_forever=" + mode,
		}
		token := strings.TrimSpace(args.ConfirmationToken)
		if token == "" {
			prev, err := mgr.Preview(ctx, intent)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			return structuredResult(prev)
		}
		bound, err := mgr.Confirm(ctx, token, intent)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		want := bound.Mode == "true"
		resObj, err := client.SetBuildKeepForever(ctx, bound.JobName, bound.BuildNumber, want)
		if err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolSetBuildKeepForever, string(bound.Action), "jenkins_error", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		mgr.EmitExecuteOK(ctx, policy.ToolSetBuildKeepForever, string(bound.Action), bound.TargetHash, bound.RequestID)
		return structuredResult(*resObj)
	}
}

// setBuildDescriptionHandler implements MUT-014 description.
func setBuildDescriptionHandler(client *jenkins.Client, st regState) func(context.Context, *mcp.CallToolRequest, jenkins.SetBuildDescriptionToolArgs) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.SetBuildDescriptionToolArgs) (*mcp.CallToolResult, any, error) {
		bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
		if err != nil {
			return nil, nil, err
		}
		job := bref.Job.FullName
		buildNum := int(bref.Number)
		if err := policy.CheckMutationJobAllowed(st.mutationPolicy, job); err != nil {
			return nil, nil, err
		}
		desc := strings.ReplaceAll(args.Description, "\x00", "")
		if len(desc) > mutation.MaxBuildDescriptionLen {
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf(
				"description exceeds max length %d", mutation.MaxBuildDescriptionLen))
		}
		if _, err := client.GetBuildDetailsByJob(ctx, job, buildNum); err != nil {
			return nil, nil, mapToolErr(err)
		}
		mgr := ensureMutationManager(st)
		intent := mutation.Intent{
			Action:        mutation.ActionSetBuildDescription,
			ToolName:      policy.ToolSetBuildDescription,
			JobName:       job,
			BuildNumber:   buildNum,
			Extra:         desc,
			EndpointClass: mutation.EndpointSubmitDescription,
			CurrentState:  fmt.Sprintf("description_len=%d", len(desc)),
		}
		token := strings.TrimSpace(args.ConfirmationToken)
		if token == "" {
			prev, err := mgr.Preview(ctx, intent)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			return structuredResult(prev)
		}
		bound, err := mgr.Confirm(ctx, token, intent)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		resObj, err := client.SetBuildDescription(ctx, bound.JobName, bound.BuildNumber, bound.Extra)
		if err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolSetBuildDescription, string(bound.Action), "jenkins_error", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		mgr.EmitExecuteOK(ctx, policy.ToolSetBuildDescription, string(bound.Action), bound.TargetHash, bound.RequestID)
		return structuredResult(*resObj)
	}
}

// cancelQueueItemsForJobHandler implements MUT-016 capped bulk cancel.
func cancelQueueItemsForJobHandler(client *jenkins.Client, st regState) func(context.Context, *mcp.CallToolRequest, jenkins.CancelQueueItemsForJobToolArgs) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.CancelQueueItemsForJobToolArgs) (*mcp.CallToolResult, any, error) {
		name, err := jobFullName("job_name", args.JobName)
		if err != nil {
			return nil, nil, err
		}
		if err := policy.CheckMutationJobAllowed(st.mutationPolicy, name); err != nil {
			return nil, nil, err
		}
		queued, err := client.GetQueuedBuilds(ctx)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		// Exact full-name match only (MUT-016). JobName on QueuedBuild is fullName
		// or FullNameFromJobURL(task.url) — never short-name HasSuffix matching,
		// which would cancel every folder's "demo" when targeting folder/demo.
		wantJob := strings.TrimSpace(name)
		ids := make([]int, 0, mutation.MaxBulkQueueCancel)
		for _, q := range queued {
			jn := strings.TrimSpace(q.JobName)
			if jn == "" {
				// Ambiguous short-name-only item: fail closed (skip).
				continue
			}
			if jn != wantJob {
				continue
			}
			if args.StuckOnly && !q.Stuck {
				continue
			}
			if q.QueueID <= 0 {
				continue
			}
			ids = append(ids, q.QueueID)
			if len(ids) >= mutation.MaxBulkQueueCancel {
				break
			}
		}
		if len(ids) == 0 {
			return nil, nil, apperr.New(apperr.CodeNotFound, fmt.Sprintf(
				"no cancellable queue items for job %q (stuck_only=%v)", name, args.StuckOnly))
		}
		mode := ""
		if args.StuckOnly {
			mode = "stuck"
		}
		mgr := ensureMutationManager(st)
		intent := mutation.Intent{
			Action:        mutation.ActionCancelQueueItemsForJob,
			ToolName:      policy.ToolCancelQueueItemsForJob,
			JobName:       name,
			QueueIDs:      ids,
			Mode:          mode,
			EndpointClass: mutation.EndpointCancelItemBulk,
			CurrentState:  fmt.Sprintf("count=%d cap=%d", len(ids), mutation.MaxBulkQueueCancel),
		}
		token := strings.TrimSpace(args.ConfirmationToken)
		if token == "" {
			prev, err := mgr.Preview(ctx, intent)
			if err != nil {
				return nil, nil, mapToolErr(err)
			}
			return structuredResult(prev)
		}
		bound, err := mgr.Confirm(ctx, token, intent)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		cancelled := make([]int, 0, len(bound.QueueIDs))
		failed := make([]int, 0)
		for _, qid := range bound.QueueIDs {
			// Wrong-state fail closed per item (not reported as success).
			if _, _, err := loadCancellableQueueItem(ctx, client, qid); err != nil {
				failed = append(failed, qid)
				continue
			}
			if _, err := client.CancelQueueItem(ctx, qid); err != nil {
				failed = append(failed, qid)
				continue
			}
			cancelled = append(cancelled, qid)
		}
		if len(cancelled) == 0 {
			mgr.EmitExecuteFail(ctx, policy.ToolCancelQueueItemsForJob, string(bound.Action), "none_cancelled", bound.TargetHash)
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, "no queue items cancelled (wrong-state or jenkins errors)")
		}
		mgr.EmitExecuteOK(ctx, policy.ToolCancelQueueItemsForJob, string(bound.Action), bound.TargetHash, bound.RequestID)
		return structuredResult(jenkins.CancelQueueItemsForJobToolResponse{
			JobName:   bound.JobName,
			Cancelled: cancelled,
			Failed:    failed,
			Status:    "partial_ok",
			Cap:       mutation.MaxBulkQueueCancel,
		})
	}
}
