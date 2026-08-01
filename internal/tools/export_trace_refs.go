package tools

import (
	"context"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/otelx"
	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
)

// ToolExportTraceRefs is the optional INT-002 export tool name.
// Registered only when RegisterOptions.TraceExporter is non-nil (otel-export adapter).
const ToolExportTraceRefs = "jenkins_export_trace_refs"

// residualOTLPExportClient is returned on every successful export response so
// operators/models know real OTLP/OTLP-HTTP protobuf collectors are not shipped.
const residualOTLPExportClient = "real OTLP/OTLP-HTTP protobuf collector client residual (INT-002 MVP: metadata-only export stub; no log text)"

// TraceExportEnvelope is a tools-layer metadata envelope (mirrors adapter allowlist).
// Never includes console logs, tokens, or full parameter maps.
type TraceExportEnvelope struct {
	TraceID string `json:"trace_id,omitempty"`
	SpanID  string `json:"span_id,omitempty"`
	Service string `json:"service,omitempty"`
	Job     string `json:"job"`
	Build   int    `json:"build"`
	Format  string `json:"format,omitempty"`
}

// TraceExportRequest is the tools-layer export request.
type TraceExportRequest struct {
	Job       string
	Build     int
	Envelopes []TraceExportEnvelope
}

// TraceExportResult is the tools-layer export outcome.
type TraceExportResult struct {
	Status         string   `json:"status"`
	Backend        string   `json:"backend"`
	Accepted       int      `json:"accepted"`
	Attempted      int      `json:"attempted"`
	Truncated      bool     `json:"truncated,omitempty"`
	EvidenceSource string   `json:"evidence_source"`
	Residuals      []string `json:"residuals,omitempty"`
	Message        string   `json:"message,omitempty"`
}

// TraceExporter is implemented by the otel-export adapter bridge (cmd wires it).
// Core tools package does not import internal/adapter (FND-004).
type TraceExporter interface {
	ExportTraceRefs(ctx context.Context, req TraceExportRequest) (TraceExportResult, error)
}

// ExportTraceRefsToolArgs is the MCP input for jenkins_export_trace_refs.
type ExportTraceRefsToolArgs struct {
	JobName     string `json:"job_name" mcp:"Jenkins job full name (folder/job path; not a URL)"`
	BuildNumber int    `json:"build_number" mcp:"build number"`
	// MaxRefs caps extraction before export (0 ⇒ otelx default; hard-capped).
	MaxRefs int `json:"max_refs,omitempty" mcp:"maximum correlation refs to extract before export"`
}

// ExportTraceRefsToolResponse is the model-facing export status payload.
// Never includes log text, tokens, or full parameter maps.
type ExportTraceRefsToolResponse struct {
	Job            string                `json:"job"`
	Build          int                   `json:"build"`
	Status         string                `json:"status"`
	Backend        string                `json:"backend"`
	Accepted       int                   `json:"accepted"`
	Attempted      int                   `json:"attempted"`
	Truncated      bool                  `json:"truncated,omitempty"`
	Envelopes      []TraceExportEnvelope `json:"envelopes,omitempty"`
	EvidenceSource string                `json:"evidence_source"`
	Freshness      string                `json:"freshness"`
	Residuals      []string              `json:"residuals,omitempty"`
	Message        string                `json:"message,omitempty"`
	// Extracted is the number of otelx refs found before allowlist export filter.
	Extracted int `json:"extracted"`
}

func registerExportTraceRefsTool(s *mcp.Server, st regState, client *jenkins.Client) {
	if st.traceExporter == nil {
		return
	}
	exporter := st.traceExporter
	addReadTool(s, st, &mcp.Tool{
		Name: ToolExportTraceRefs,
		Description: "Extract OpenTelemetry/Datadog correlation identifiers from Jenkins build " +
			"parameters and export metadata-only envelopes via the otel-export adapter " +
			"(noop/mock/optional HTTPS JSON stub). Requires Jenkins Job/Read (fail closed). " +
			"Disabled by default. Never sends console logs, tokens, or full parameter maps. " +
			"Real OTLP/OTLP-HTTP protobuf collector clients remain residual.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args ExportTraceRefsToolArgs) (*mcp.CallToolResult, ExportTraceRefsToolResponse, error) {
		out, err := runExportTraceRefs(ctx, client, exporter, args)
		if err != nil {
			return nil, ExportTraceRefsToolResponse{}, err
		}
		return structuredResult(out)
	})
}

func runExportTraceRefs(ctx context.Context, client *jenkins.Client, exp TraceExporter, args ExportTraceRefsToolArgs) (ExportTraceRefsToolResponse, error) {
	if exp == nil {
		return ExportTraceRefsToolResponse{}, apperr.New(apperr.CodeInternal, "trace exporter is nil")
	}
	bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
	if err != nil {
		return ExportTraceRefsToolResponse{}, err
	}
	job := bref.Job.FullName
	build := int(bref.Number)

	out := ExportTraceRefsToolResponse{
		Job:            job,
		Build:          build,
		Envelopes:      []TraceExportEnvelope{},
		EvidenceSource: "otel_export_stub",
		Freshness:      "live",
		Residuals:      []string{residualOTLPExportClient},
	}

	// Fail-closed Jenkins ACL + param source: single GetBuildDetailsByJob.
	// 401/403/404 never reach the export backend (exporter not called on error).
	if client == nil {
		return ExportTraceRefsToolResponse{}, apperr.New(apperr.CodeInternal, "jenkins client is nil")
	}
	b, err := client.GetBuildDetailsByJob(ctx, job, build)
	if err != nil {
		return ExportTraceRefsToolResponse{}, mapToolErr(err)
	}

	extracted := otelx.ExtractFromParams(b.Parameters, otelx.ExtractOptions{MaxRefs: args.MaxRefs})
	out.Extracted = len(extracted.Refs)
	if extracted.Truncated {
		out.Truncated = true
	}

	// Build allowlisted envelopes only — never full params or log text.
	envelopes := envelopesFromTraceRefs(job, build, extracted.Refs)
	out.Envelopes = envelopes

	res, err := exp.ExportTraceRefs(ctx, TraceExportRequest{
		Job:       job,
		Build:     build,
		Envelopes: envelopes,
	})
	if err != nil {
		return ExportTraceRefsToolResponse{}, mapToolErr(err)
	}

	out.Status = res.Status
	out.Backend = res.Backend
	out.Accepted = res.Accepted
	out.Attempted = res.Attempted
	if res.Truncated {
		out.Truncated = true
	}
	if res.EvidenceSource != "" {
		out.EvidenceSource = res.EvidenceSource
	}
	if res.Message != "" {
		// Redact status message before model (defense in depth).
		out.Message = redact.SanitizeForModel(res.Message)
	}
	// Merge residuals; ensure OTLP residual always present.
	out.Residuals = mergeResiduals(out.Residuals, res.Residuals, residualOTLPExportClient)

	// Redact envelope string fields before model-facing output.
	for i := range out.Envelopes {
		e := &out.Envelopes[i]
		e.TraceID = redact.SanitizeForModel(e.TraceID)
		e.SpanID = redact.SanitizeForModel(e.SpanID)
		e.Service = redact.SanitizeForModel(e.Service)
		e.Format = redact.SanitizeForModel(e.Format)
		e.Job = redact.SanitizeForModel(e.Job)
	}
	if out.Status == "" {
		if out.Accepted == 0 {
			out.Status = "empty"
			if out.Message == "" {
				out.Message = "no exportable correlation identifiers in build parameters"
			}
		}
	}
	return out, nil
}

// envelopesFromTraceRefs maps otelx refs → allowlisted export envelopes.
// Drops empty / unusable refs. Never copies arbitrary parameter values.
func envelopesFromTraceRefs(job string, build int, refs []otelx.TraceRef) []TraceExportEnvelope {
	out := make([]TraceExportEnvelope, 0, len(refs))
	for _, r := range refs {
		env := TraceExportEnvelope{
			TraceID: strings.TrimSpace(r.TraceID),
			SpanID:  strings.TrimSpace(r.SpanID),
			Service: strings.TrimSpace(r.ServiceName),
			Job:     job,
			Build:   build,
			Format:  strings.TrimSpace(r.Format),
		}
		if env.TraceID == "" && env.Service == "" {
			continue
		}
		out = append(out, env)
	}
	if out == nil {
		out = []TraceExportEnvelope{}
	}
	return out
}

func mergeResiduals(base, extra []string, required string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range base {
		add(s)
	}
	for _, s := range extra {
		add(s)
	}
	add(required)
	return out
}
