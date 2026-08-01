package tools

import (
	"context"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// HOST-004 serve wire: subject-bound opaque page tokens for list tools.
//
// When regState.subjectKey is non-empty (gateway serve), resolve and mint
// page tokens with jenkins.*WithSubject helpers so Alice cannot continue Bob's
// list. Empty subjectKey leaves fingerprints unbound (stdio pilot residual).
//
// Strategy for client-owned list methods (GetJobs / ListBuilds): resolve under
// the subject-bound fingerprint here, call the client with offset/limit only
// (clear page_token so the client does not reject a subject-bound token against
// its unbound fingerprint), then rebind next_page_token.

// getJobsWithSubject is jenkins_get_jobs with HOST-004 subject isolation.
func getJobsWithSubject(ctx context.Context, client *jenkins.Client, st regState, args jenkins.GetJobsToolArgs) (*jenkins.GetJobsToolResponse, error) {
	sk := effectiveSubjectKey(st, ctx)
	filterFP := jenkins.FilterFingerprint("get_jobs")
	off, lim, err := jenkins.ResolveListPaginationWithSubject(
		args.PageToken, args.Offset, args.Limit,
		jenkins.DefaultGetJobsLimit, jenkins.MaxGetJobsLimit, filterFP, sk,
	)
	if err != nil {
		return nil, err
	}
	call := args
	call.PageToken = ""
	call.Offset = off
	call.Limit = lim
	res, err := client.GetJobs(ctx, call)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	res.NextPageToken = jenkins.NextPageTokenIfMoreWithSubject(
		res.Offset, res.Limit, len(res.JobList), res.Total, filterFP, sk)
	return res, nil
}

// listBuildsWithSubject is jenkins_list_builds with HOST-004 subject isolation.
func listBuildsWithSubject(ctx context.Context, client *jenkins.Client, st regState, args jenkins.ListBuildsToolArgs) (*jenkins.ListBuildsToolResponse, error) {
	sk := effectiveSubjectKey(st, ctx)
	filterFP := listBuildsFilterFingerprint(args)
	off, lim, err := jenkins.ResolveListPaginationWithSubject(
		args.PageToken, args.Offset, args.Limit,
		jenkins.DefaultListBuildsLimit, jenkins.MaxListBuildsLimit, filterFP, sk,
	)
	if err != nil {
		return nil, err
	}
	call := args
	call.PageToken = ""
	call.Offset = off
	call.Limit = lim
	res, err := client.ListBuilds(ctx, call)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	// ListBuilds pagination uses Matched (filtered count), not a Total field.
	res.NextPageToken = jenkins.NextPageTokenIfMoreWithSubject(
		res.Offset, res.Limit, len(res.Builds), res.Matched, filterFP, sk)
	return res, nil
}

// listBuildsFilterFingerprint mirrors jenkins.Client.ListBuilds fingerprint
// inputs (job + since_build + result + lookback + include_parameters).
func listBuildsFilterFingerprint(args jenkins.ListBuildsToolArgs) [8]byte {
	jobName := strings.TrimSpace(args.JobName)
	lookback := args.MaxLookback
	if lookback <= 0 {
		lookback = jenkins.DefaultListBuildsLookback
	}
	if lookback > jenkins.MaxListBuildsLookback {
		lookback = jenkins.MaxListBuildsLookback
	}
	resultFilter := strings.ToUpper(strings.TrimSpace(args.Result))
	return jenkins.FilterFingerprint(
		"list_builds",
		jobName,
		jenkins.FormatFilterInt(args.SinceBuild),
		resultFilter,
		jenkins.FormatFilterInt(lookback),
		jenkins.FormatFilterBool(args.IncludeParameters),
	)
}
