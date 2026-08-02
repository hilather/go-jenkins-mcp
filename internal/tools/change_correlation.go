package tools

import (
	"context"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/correlate"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolGetChangeCorrelation is the INT-004 correlation tool name.
// Registered when RegisterOptions.EnableChangeCorrelation is true (serve: work-items adapter).
const ToolGetChangeCorrelation = "jenkins_get_change_correlation"

const residualWorkItemTicketAPI = "ticket system API residual (INT-004 MVP: extract refs from Jenkins metadata/SCM only; no Jira/GitHub network lookup)"

// GetChangeCorrelationToolArgs is the MCP input for jenkins_get_change_correlation.
type GetChangeCorrelationToolArgs struct {
	JobName     string `json:"job_name" mcp:"Jenkins job full name (folder/job path; not a URL)"`
	BuildNumber int    `json:"build_number" mcp:"build number"`
	// MaxItems caps returned work items (0 ⇒ default 32; hard max 64).
	MaxItems int `json:"max_items,omitempty" mcp:"maximum work item refs to return"`
	// IncludeSCM when true (default) also scans changeSets for SHAs, messages, hosts.
	// Set false to only scan build parameters.
	IncludeSCM *bool `json:"include_scm,omitempty" mcp:"include SCM changeSets in extraction (default true)"`
}

// GetChangeCorrelationToolResponse is the bounded correlation payload.
type GetChangeCorrelationToolResponse struct {
	Job   string `json:"job"`
	Build int    `json:"build"`
	// WorkItems are extracted refs (JIRA-like keys, issue URLs, commit SHAs, SCM hosts).
	WorkItems []correlate.WorkItem `json:"work_items"`
	Count     int                  `json:"count"`
	Truncated bool                 `json:"truncated,omitempty"`
	MaxItems  int                  `json:"max_items"`
	// EvidenceSources lists distinct evidence origins used.
	EvidenceSources []string `json:"evidence_sources,omitempty"`
	// Freshness labels the data path (live Jenkins APIs).
	Freshness string `json:"freshness"`
	// Sources lists data paths used (build_api, scm_api).
	Sources []string `json:"sources,omitempty"`
	// Residuals document missing ticket-system capabilities.
	Residuals []string `json:"residuals,omitempty"`
	// AdapterStub notes optional work-items adapter passthrough (when wired).
	AdapterStub []string `json:"adapter_stub,omitempty"`
	// Message when nothing found.
	Message string `json:"message,omitempty"`
}

// WorkItemLookuper is optional INT-004 stub enrichment (refs only; no network).
// Implemented by cmd bridge to work-items adapter. Nil ⇒ skip.
type WorkItemLookuper interface {
	LookupWorkItemRefs(ctx context.Context, ids []string) ([]string, error)
}

// registerChangeCorrelationTool registers jenkins_get_change_correlation when enabled.
func registerChangeCorrelationTool(s *mcp.Server, client *jenkins.Client, st regState) {
	if !st.enableChangeCorrelation {
		return
	}
	addReadTool(s, st, &mcp.Tool{
		Name: ToolGetChangeCorrelation,
		Description: "Extract work-item and SCM host correlation refs from Jenkins build " +
			"parameters and changeSets (JIRA-like keys, GitHub/GitLab/Bitbucket issue URLs, " +
			"commit SHAs). Disabled by default; enable via work-items adapter. No ticket API calls.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args GetChangeCorrelationToolArgs) (*mcp.CallToolResult, GetChangeCorrelationToolResponse, error) {
		out, err := runGetChangeCorrelation(ctx, client, st.workItemLookup, args)
		if err != nil {
			return nil, GetChangeCorrelationToolResponse{}, err
		}
		return structuredResult(out)
	})
}

func runGetChangeCorrelation(
	ctx context.Context,
	client *jenkins.Client,
	lookup WorkItemLookuper,
	args GetChangeCorrelationToolArgs,
) (GetChangeCorrelationToolResponse, error) {
	bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
	if err != nil {
		return GetChangeCorrelationToolResponse{}, err
	}
	job := bref.Job.FullName
	build := int(bref.Number)

	out := GetChangeCorrelationToolResponse{
		Job:       job,
		Build:     build,
		WorkItems: []correlate.WorkItem{},
		Freshness: "live",
		Residuals: []string{residualWorkItemTicketAPI},
	}
	if client == nil {
		return GetChangeCorrelationToolResponse{}, apperr.New(apperr.CodeInternal, "jenkins client is nil")
	}

	opts := correlate.ExtractOptions{MaxItems: args.MaxItems}
	var parts []correlate.ExtractResult

	// Parameters (always).
	b, err := client.GetBuildDetailsByJob(ctx, job, build)
	if err != nil {
		return GetChangeCorrelationToolResponse{}, mapToolErr(err)
	}
	out.Sources = append(out.Sources, "build_api")
	parts = append(parts, correlate.ExtractFromParams(b.Parameters, opts))

	includeSCM := true
	if args.IncludeSCM != nil {
		includeSCM = *args.IncludeSCM
	}
	if includeSCM {
		changes, err := client.GetBuildChanges(ctx, jenkins.GetBuildChangesToolArgs{
			JobName:     job,
			BuildNumber: build,
			MaxCommits:  50,
		})
		if err != nil {
			// Correlation must not block on SCM failure — residual and continue.
			out.Residuals = append(out.Residuals, "scm change data unavailable; parameter extraction only")
		} else {
			out.Sources = append(out.Sources, "scm_api")
			sets := make([]correlate.SCMChangeSetInput, 0, len(changes.ChangeSets))
			for _, cs := range changes.ChangeSets {
				in := correlate.SCMChangeSetInput{
					Kind:     cs.Kind,
					RepoURLs: append([]string(nil), cs.RepoURLs...),
				}
				for _, c := range cs.Commits {
					in.Commits = append(in.Commits, correlate.SCMCommitInput{
						ID:      c.ID,
						Message: c.Message,
					})
				}
				sets = append(sets, in)
			}
			parts = append(parts, correlate.ExtractFromChangeSets(sets, opts))
		}
	}

	merged := correlate.MergeResults(opts, parts...)
	if merged.Items != nil {
		out.WorkItems = merged.Items
	}
	out.Count = len(out.WorkItems)
	out.Truncated = merged.Truncated
	out.MaxItems = merged.MaxItems

	// Distinct evidence sources.
	seenEv := map[string]struct{}{}
	for _, it := range out.WorkItems {
		if it.EvidenceSource == "" {
			continue
		}
		if _, ok := seenEv[it.EvidenceSource]; ok {
			continue
		}
		seenEv[it.EvidenceSource] = struct{}{}
		out.EvidenceSources = append(out.EvidenceSources, it.EvidenceSource)
	}

	// Optional work-items adapter stub: echo ids (no network, no private content).
	if lookup != nil && len(out.WorkItems) > 0 {
		ids := make([]string, 0, len(out.WorkItems))
		for _, it := range out.WorkItems {
			ids = append(ids, it.ID)
		}
		if stubIDs, err := lookup.LookupWorkItemRefs(ctx, ids); err == nil && len(stubIDs) > 0 {
			out.AdapterStub = stubIDs
		}
		// Failure of external correlation must not fail the tool.
	}

	if len(out.WorkItems) == 0 {
		out.Message = "no recognized work-item or SCM host identifiers in build parameters/changeSets"
	}
	return out, nil
}
