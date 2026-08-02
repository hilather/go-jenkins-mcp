package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/mutation"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// startJobHandler implements MUT-002: preview without token; execute with token.
// Loads job parameter definitions, validates names/types/choices, rejects
// secret/unsupported definition types, and re-validates on confirm so job
// config drift fails closed. POST is never auto-retried (NET-003 / client).
func startJobHandler(client *jenkins.Client, st regState) func(context.Context, *mcp.CallToolRequest, jenkins.StartJobToolArgs) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.StartJobToolArgs) (*mcp.CallToolResult, any, error) {
		name, err := jobFullName("job_name", args.JobName)
		if err != nil {
			return nil, nil, err
		}
		if err := policy.CheckMutationJobAllowed(st.mutationPolicy, name); err != nil {
			return nil, nil, err
		}
		// MUT-015: refuse preview when job is not buildable.
		jobMeta, err := client.GetJenkinsJob(ctx, name, 0)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		if jobMeta != nil && !jobMeta.Buildable {
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf(
				"job %q is not buildable (disabled); start refused", name))
		}
		// Normalize then validate against fresh definitions before preview or confirm.
		// Sensitive-name heuristic runs in NormalizeParams; type/choice/unknown in ValidateAgainstDefinitions.
		norm, err := mutation.NormalizeParams(args.Parameters)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		defs, err := client.GetJobParameterDefinitions(ctx, name)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		mdefs := toMutationParamDefs(defs)
		if err := mutation.ValidateAgainstDefinitions(norm, mdefs); err != nil {
			return nil, nil, mapToolErr(err)
		}
		if err := mutation.ValidateRequiredParams(norm, mdefs); err != nil {
			return nil, nil, mapToolErr(err)
		}

		mgr := ensureMutationManager(st)
		intent := mutation.Intent{
			Action:        mutation.ActionStartJob,
			ToolName:      policy.ToolStartJob,
			JobName:       name,
			Parameters:    norm, // preview redaction + execute use the same normalized map
			EndpointClass: mutation.EndpointBuildWithParameters,
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
		// Single non-retried enqueue (client + resilience: POST not auto-retried).
		// Bound parameters match preview (token-stored normalized map).
		resObj, err := client.StartJob(ctx, bound.JobName, bound.Parameters)
		if err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolStartJob, string(bound.Action), "jenkins_error", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		mgr.EmitExecuteOK(ctx, policy.ToolStartJob, string(bound.Action), bound.TargetHash, bound.RequestID)
		return structuredResult(*resObj)
	}
}

// toMutationParamDefs maps jenkins BuildParameter definitions into mutation.ParamDefinition.
func toMutationParamDefs(defs []jenkins.BuildParameter) []mutation.ParamDefinition {
	if len(defs) == 0 {
		return nil
	}
	out := make([]mutation.ParamDefinition, 0, len(defs))
	for _, d := range defs {
		out = append(out, mutation.ParamDefinition{
			Name:     d.Name,
			Type:     d.Type,
			Choices:  d.Choices,
			Required: d.Required,
		})
	}
	return out
}

// stopBuildHandler implements MUT-003: preview without token; execute with token.
// Completed builds are rejected with a clear invalid_argument / wrong-state error.
func stopBuildHandler(client *jenkins.Client, st regState) func(context.Context, *mcp.CallToolRequest, jenkins.StopBuildToolArgs) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.StopBuildToolArgs) (*mcp.CallToolResult, any, error) {
		bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
		if err != nil {
			return nil, nil, err
		}
		job := bref.Job.FullName
		buildNum := int(bref.Number)

		// Fresh status before preview or execute (MUT-003).
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
			// Clear error: completed/wrong-state is not a successful stop.
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf(
				"build already finished (job=%q build=#%d result=%s); stop refused",
				job, buildNum, result))
		}

		mgr := ensureMutationManager(st)
		intent := mutation.Intent{
			Action:        mutation.ActionStopBuild,
			ToolName:      policy.ToolStopBuild,
			JobName:       job,
			BuildNumber:   buildNum,
			EndpointClass: mutation.EndpointStop,
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
		// Re-check state immediately before POST (race with natural completion).
		build2, err := client.GetBuildDetailsByJob(ctx, bound.JobName, bound.BuildNumber)
		if err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolStopBuild, string(bound.Action), "jenkins_error", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		if build2 == nil || !build2.Building {
			result := "finished"
			if build2 != nil && strings.TrimSpace(build2.Result) != "" {
				result = strings.TrimSpace(build2.Result)
			}
			mgr.EmitExecuteFail(ctx, policy.ToolStopBuild, string(bound.Action), "already_finished", bound.TargetHash)
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf(
				"build already finished (job=%q build=#%d result=%s); stop refused",
				bound.JobName, bound.BuildNumber, result))
		}
		resObj, err := client.StopBuild(ctx, bound.JobName, bound.BuildNumber)
		if err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolStopBuild, string(bound.Action), "jenkins_error", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		mgr.EmitExecuteOK(ctx, policy.ToolStopBuild, string(bound.Action), bound.TargetHash, bound.RequestID)
		return structuredResult(*resObj)
	}
}

// cancelQueueItemHandler implements MUT-003 queue cancel: preview without token;
// execute with token. Fresh GetQueueItem before preview/execute; missing or
// already-left/already-cancelled items are clear non-success errors (not false success).
func cancelQueueItemHandler(client *jenkins.Client, st regState) func(context.Context, *mcp.CallToolRequest, jenkins.CancelQueueItemToolArgs) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.CancelQueueItemToolArgs) (*mcp.CallToolResult, any, error) {
		qref, err := queueItemRef("queue_id", args.QueueID, "")
		if err != nil {
			return nil, nil, err
		}
		queueID := int(qref.ID)

		// Fresh status before preview or execute (MUT-003).
		item, state, err := loadCancellableQueueItem(ctx, client, queueID)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}

		mgr := ensureMutationManager(st)
		intent := mutation.Intent{
			Action:        mutation.ActionCancelQueue,
			ToolName:      policy.ToolCancelQueueItem,
			JobName:       strings.TrimSpace(item.JobName),
			QueueID:       queueID,
			EndpointClass: mutation.EndpointCancelItem,
			CurrentState:  state,
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
		// Re-check state immediately before POST (race with natural leave/cancel).
		item2, _, err := loadCancellableQueueItem(ctx, client, bound.QueueID)
		if err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolCancelQueueItem, string(bound.Action), "already_left", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		resObj, err := client.CancelQueueItem(ctx, bound.QueueID)
		if err != nil {
			mgr.EmitExecuteFail(ctx, policy.ToolCancelQueueItem, string(bound.Action), "jenkins_error", bound.TargetHash)
			return nil, nil, mapToolErr(err)
		}
		if item2 != nil && strings.TrimSpace(item2.JobName) != "" {
			resObj.JobName = strings.TrimSpace(item2.JobName)
		} else if bound.JobName != "" {
			resObj.JobName = bound.JobName
		}
		mgr.EmitExecuteOK(ctx, policy.ToolCancelQueueItem, string(bound.Action), bound.TargetHash, bound.RequestID)
		return structuredResult(*resObj)
	}
}

// loadCancellableQueueItem fetches a queue item and rejects wrong-state targets
// (missing, already cancelled, already assigned to a build).
func loadCancellableQueueItem(ctx context.Context, client *jenkins.Client, queueID int) (*jenkins.QueueItem, string, error) {
	item, err := client.GetQueueItem(ctx, queueID)
	if err != nil {
		// Missing / not found must not be treated as successful cancel.
		msg := err.Error()
		if strings.Contains(strings.ToLower(msg), "not found") {
			return nil, "", apperr.New(apperr.CodeNotFound, fmt.Sprintf(
				"queue item #%d not found (already left queue or never existed); cancel refused", queueID))
		}
		return nil, "", err
	}
	if item == nil {
		return nil, "", apperr.New(apperr.CodeNotFound, fmt.Sprintf(
			"queue item #%d not found; cancel refused", queueID))
	}
	if item.Cancelled {
		return nil, "", apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf(
			"queue item #%d already cancelled; cancel refused", queueID))
	}
	if item.Executable != nil && item.Executable.Number > 0 {
		return nil, "", apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf(
			"queue item #%d already left the queue (assigned build #%d); cancel refused — use jenkins_stop_build if the build is still running",
			queueID, item.Executable.Number))
	}
	state := "queued"
	if item.Stuck {
		state = "stuck"
	} else if item.Buildable {
		state = "buildable"
	}
	if why := strings.TrimSpace(item.Why); why != "" && len(why) < 120 {
		state = state + ": " + why
	}
	return item, state, nil
}

// ensureMutationManager returns the process mutation gate.
// Prefer the manager wired via RegisterOptions / resolveRegisterOptions so
// preview tokens are process-scoped. Fallback constructs a one-off manager
// only for force-registered RO deny-path tests (tokens will not span calls).
// Zero rate/cooldown fields take MUT-001 production defaults (process live
// after serve Resolve+Set when positive, else 30 previews/min and 5s confirm
// cooldown per target); see mutation.NewManager. Multi-user BindingFromContext
// and ExternalSubject/Tenant are included when present on regState.
func ensureMutationManager(st regState) *mutation.Manager {
	if st.mutations != nil {
		return st.mutations
	}
	return newMutationManager(st)
}
