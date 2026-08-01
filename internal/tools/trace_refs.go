package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/otelx"
)

// ToolGetTraceRefs is the optional INT-002 correlation tool name.
// Registered only when RegisterOptions.EnableTraceRefs is true (disabled by default).
const ToolGetTraceRefs = "jenkins_get_trace_refs"

// residualOTLPBackend is returned on every successful correlation response so
// operators/models know full OTLP query/export is not implemented in MVP.
const residualOTLPBackend = "OTLP backend query/export residual (INT-002 MVP: build-metadata correlation IDs only; no remote telemetry)"

// GetTraceRefsToolArgs is the MCP input for jenkins_get_trace_refs.
type GetTraceRefsToolArgs struct {
	JobName     string `json:"job_name" mcp:"Jenkins job full name (folder/job path; not a URL)"`
	BuildNumber int    `json:"build_number" mcp:"build number"`
	// MaxRefs caps returned correlations (0 ⇒ otelx default; hard-capped).
	MaxRefs int `json:"max_refs,omitempty" mcp:"maximum correlation refs to return"`
}

// GetTraceRefsToolResponse is the bounded correlation payload (model-facing).
// Never includes log text, tokens, or unvalidated parameter values.
type GetTraceRefsToolResponse struct {
	Job   string           `json:"job"`
	Build int              `json:"build"`
	Refs  []otelx.TraceRef `json:"trace_refs"`
	// Count is len(Refs).
	Count int `json:"count"`
	// Truncated when more candidates existed than MaxRefs.
	Truncated bool `json:"truncated,omitempty"`
	// MaxRefs is the effective cap applied.
	MaxRefs int `json:"max_refs"`
	// EvidenceSource is always jenkins_build_metadata for MVP.
	EvidenceSource string `json:"evidence_source"`
	// Freshness labels the data path (live Jenkins build API).
	Freshness string `json:"freshness"`
	// Sources lists data paths used.
	Sources []string `json:"sources,omitempty"`
	// Residuals document missing backend capabilities.
	Residuals []string `json:"residuals,omitempty"`
	// Message is a short status when no refs found.
	Message string `json:"message,omitempty"`
}

// registerTraceRefsTool registers jenkins_get_trace_refs when EnableTraceRefs.
func registerTraceRefsTool(s *mcp.Server, client *jenkins.Client, st regState) {
	if !st.enableTraceRefs {
		return
	}
	addReadTool(s, st, &mcp.Tool{
		Name: ToolGetTraceRefs,
		Description: "Extract OpenTelemetry/Datadog correlation identifiers from Jenkins " +
			"build parameters (TRACEPARENT, TRACE_ID, OTEL_*, dd.trace_id, …). " +
			"Disabled by default; no OTLP export or remote telemetry query.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args GetTraceRefsToolArgs) (*mcp.CallToolResult, GetTraceRefsToolResponse, error) {
		out, err := runGetTraceRefs(ctx, client, args)
		if err != nil {
			return nil, GetTraceRefsToolResponse{}, err
		}
		return structuredResult(out)
	})
}

func runGetTraceRefs(ctx context.Context, client *jenkins.Client, args GetTraceRefsToolArgs) (GetTraceRefsToolResponse, error) {
	bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
	if err != nil {
		return GetTraceRefsToolResponse{}, err
	}
	job := bref.Job.FullName
	build := int(bref.Number)

	out := GetTraceRefsToolResponse{
		Job:            job,
		Build:          build,
		Refs:           []otelx.TraceRef{},
		EvidenceSource: otelx.EvidenceSourceBuildMetadata,
		Freshness:      "live",
		Residuals:      []string{residualOTLPBackend},
	}

	if client == nil {
		return GetTraceRefsToolResponse{}, apperr.New(apperr.CodeInternal, "jenkins client is nil")
	}
	b, err := client.GetBuildDetailsByJob(ctx, job, build)
	if err != nil {
		return GetTraceRefsToolResponse{}, mapToolErr(err)
	}
	out.Sources = append(out.Sources, "build_api")

	extracted := otelx.ExtractFromParams(b.Parameters, otelx.ExtractOptions{MaxRefs: args.MaxRefs})
	if extracted.Refs != nil {
		out.Refs = extracted.Refs
	}
	out.Count = len(out.Refs)
	out.Truncated = extracted.Truncated
	out.MaxRefs = extracted.MaxRefs
	if len(out.Refs) == 0 {
		out.Message = "no recognized trace/span/service identifiers in build parameters"
	}
	return out, nil
}

// extractTraceRefsFromBuildParams is used by diagnose enrichment (no extra HTTP).
func extractTraceRefsFromBuildParams(params map[string]string, maxRefs int) otelx.ExtractResult {
	return otelx.ExtractFromParams(params, otelx.ExtractOptions{MaxRefs: maxRefs})
}
