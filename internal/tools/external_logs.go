package tools

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// ToolQueryExternalLogs is the optional INT-003 tool name.
// Registered only when RegisterOptions.ExternalLogs is non-nil (adapter enabled).
const ToolQueryExternalLogs = "jenkins_query_external_logs"

// ExternalLogQueryRequest is the tools-layer query (mirrors adapter bounds; no adapter import).
type ExternalLogQueryRequest struct {
	Job        string
	Build      int
	Start      time.Time
	End        time.Time
	Query      string
	MaxEntries int
}

// ExternalLogEntry is one model-facing external log hit (excerpt redacted).
type ExternalLogEntry struct {
	RefID          string `json:"ref_id"`
	Excerpt        string `json:"excerpt,omitempty"`
	Timestamp      string `json:"timestamp,omitempty"`
	SourceLabel    string `json:"source_label"`
	Freshness      string `json:"freshness"`
	EvidenceSource string `json:"evidence_source"`
}

// ExternalLogQueryResult is the tools-layer result.
type ExternalLogQueryResult struct {
	Entries        []ExternalLogEntry `json:"entries"`
	Count          int                `json:"count"`
	Truncated      bool               `json:"truncated,omitempty"`
	MaxEntries     int                `json:"max_entries"`
	SourceLabel    string             `json:"source_label"`
	Freshness      string             `json:"freshness"`
	EvidenceSource string             `json:"evidence_source"`
	Residuals      []string           `json:"residuals,omitempty"`
	Message        string             `json:"message,omitempty"`
}

// ExternalLogQuerier is implemented by the ext-logs adapter bridge (cmd wires it).
// Core tools package does not import internal/adapter (FND-004).
type ExternalLogQuerier interface {
	QueryExternalLogs(ctx context.Context, req ExternalLogQueryRequest) (ExternalLogQueryResult, error)
}

// BuildAccessChecker is a cheap Jenkins Job/Read preflight for typed job+build.
// External log backends must not be queried when Jenkins denies or the build is missing
// (fail closed; INT-003 ACL). Implemented by jenkinsBuildAccess from *jenkins.Client.
// Residual: offline-only MCP policy Target job binding remains separate (POL-004).
type BuildAccessChecker interface {
	// CheckBuildReadable returns nil when the serve principal can read the build.
	// Callers map failures with mapToolErr (401→authentication, 403→authorization,
	// 404→not_found).
	CheckBuildReadable(ctx context.Context, job string, build int) error
}

// jenkinsBuildAccess is the production BuildAccessChecker (GetBuildDetailsByJob).
type jenkinsBuildAccess struct {
	client *jenkins.Client
}

// CheckBuildReadable performs a cheap Jenkins GET of the typed build.
func (j *jenkinsBuildAccess) CheckBuildReadable(ctx context.Context, job string, build int) error {
	if j == nil || j.client == nil {
		return apperr.New(apperr.CodeInternal, "jenkins client is required for external log access preflight")
	}
	_, err := j.client.GetBuildDetailsByJob(ctx, job, build)
	if err != nil {
		return mapToolErr(err)
	}
	return nil
}

// QueryExternalLogsToolArgs is the MCP input for jenkins_query_external_logs.
type QueryExternalLogsToolArgs struct {
	JobName     string `json:"job_name" mcp:"Jenkins job full name (folder/job path; not a URL)"`
	BuildNumber int    `json:"build_number" mcp:"build number"`
	// Query is a short free-text filter (not unrestricted backend query language).
	Query string `json:"query,omitempty" mcp:"short free-text filter (max 256 chars; not backend DSL)"`
	// StartTime / EndTime are RFC3339; empty end ⇒ now; window bounded server-side.
	StartTime string `json:"start_time,omitempty" mcp:"RFC3339 start of search window"`
	EndTime   string `json:"end_time,omitempty" mcp:"RFC3339 end of search window (default now)"`
	// MaxEntries caps returned entry refs (default 20, hard max 50).
	MaxEntries int `json:"max_entries,omitempty" mcp:"maximum entry refs to return"`
}

// QueryExternalLogsToolResponse is the bounded MCP payload.
type QueryExternalLogsToolResponse struct {
	Job            string             `json:"job"`
	Build          int                `json:"build"`
	Entries        []ExternalLogEntry `json:"entries"`
	Count          int                `json:"count"`
	Truncated      bool               `json:"truncated,omitempty"`
	MaxEntries     int                `json:"max_entries"`
	SourceLabel    string             `json:"source_label"`
	Freshness      string             `json:"freshness"`
	EvidenceSource string             `json:"evidence_source"`
	Residuals      []string           `json:"residuals,omitempty"`
	Message        string             `json:"message,omitempty"`
	// QueryEcho is the accepted (bounded) query string — never backend secrets.
	QueryEcho string `json:"query_echo,omitempty"`
}

func registerExternalLogsTool(s *mcp.Server, st regState, client *jenkins.Client) {
	if st.externalLogs == nil {
		return
	}
	querier := st.externalLogs
	// Fail closed: always preflight Jenkins Job/Read before any external query.
	var access BuildAccessChecker
	if client != nil {
		access = &jenkinsBuildAccess{client: client}
	}
	addReadTool(s, st, &mcp.Tool{
		Name: ToolQueryExternalLogs,
		Description: "Query an approved external log system by Jenkins job/build identity " +
			"(bounded time range and short free-text filter). Requires Jenkins Job/Read on the " +
			"typed job+build (fail closed). Disabled by default; requires ext-logs adapter. " +
			"Returns entry refs + short redacted excerpts only — not a full console dump. " +
			"Real Splunk/ELK clients remain residual.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args QueryExternalLogsToolArgs) (*mcp.CallToolResult, QueryExternalLogsToolResponse, error) {
		out, err := runQueryExternalLogs(ctx, access, querier, args)
		if err != nil {
			return nil, QueryExternalLogsToolResponse{}, err
		}
		return structuredResult(out)
	})
}

func runQueryExternalLogs(ctx context.Context, access BuildAccessChecker, q ExternalLogQuerier, args QueryExternalLogsToolArgs) (QueryExternalLogsToolResponse, error) {
	if q == nil {
		return QueryExternalLogsToolResponse{}, apperr.New(apperr.CodeInternal, "external log querier is nil")
	}
	bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
	if err != nil {
		return QueryExternalLogsToolResponse{}, err
	}
	job := bref.Job.FullName
	build := int(bref.Number)

	// Bound query length early (adapter also enforces).
	query := strings.TrimSpace(args.Query)
	if utf8.RuneCountInString(query) > 256 {
		return QueryExternalLogsToolResponse{}, apperr.New(apperr.CodeInvalidArgument, "query exceeds max length 256")
	}

	var start, end time.Time
	if strings.TrimSpace(args.StartTime) != "" {
		start, err = time.Parse(time.RFC3339, strings.TrimSpace(args.StartTime))
		if err != nil {
			return QueryExternalLogsToolResponse{}, apperr.New(apperr.CodeInvalidArgument, "start_time must be RFC3339")
		}
	}
	if strings.TrimSpace(args.EndTime) != "" {
		end, err = time.Parse(time.RFC3339, strings.TrimSpace(args.EndTime))
		if err != nil {
			return QueryExternalLogsToolResponse{}, apperr.New(apperr.CodeInvalidArgument, "end_time must be RFC3339")
		}
	}

	// INT-003 fail-closed ACL: cheap Jenkins read before any external backend call.
	// Do not query operator-pinned log systems for jobs the principal cannot read.
	if access == nil {
		return QueryExternalLogsToolResponse{}, apperr.New(apperr.CodeInternal,
			"jenkins access checker is required for external log queries")
	}
	if err := access.CheckBuildReadable(ctx, job, build); err != nil {
		// mapToolErr already applied inside jenkinsBuildAccess; re-map for other injectors.
		return QueryExternalLogsToolResponse{}, mapToolErr(err)
	}

	res, err := q.QueryExternalLogs(ctx, ExternalLogQueryRequest{
		Job:        job,
		Build:      build,
		Start:      start,
		End:        end,
		Query:      query,
		MaxEntries: args.MaxEntries,
	})
	if err != nil {
		return QueryExternalLogsToolResponse{}, mapToolErr(err)
	}

	// Redact every excerpt before model-facing output (SEC-002).
	entries := make([]ExternalLogEntry, 0, len(res.Entries))
	for _, e := range res.Entries {
		ex := redact.SanitizeForModel(e.Excerpt)
		entries = append(entries, ExternalLogEntry{
			RefID:          e.RefID,
			Excerpt:        ex,
			Timestamp:      e.Timestamp,
			SourceLabel:    e.SourceLabel,
			Freshness:      e.Freshness,
			EvidenceSource: e.EvidenceSource,
		})
	}
	if entries == nil {
		entries = []ExternalLogEntry{}
	}

	out := QueryExternalLogsToolResponse{
		Job:            job,
		Build:          build,
		Entries:        entries,
		Count:          len(entries),
		Truncated:      res.Truncated,
		MaxEntries:     res.MaxEntries,
		SourceLabel:    res.SourceLabel,
		Freshness:      res.Freshness,
		EvidenceSource: res.EvidenceSource,
		Residuals:      res.Residuals,
		Message:        res.Message,
		QueryEcho:      query,
	}
	if out.EvidenceSource == "" {
		out.EvidenceSource = "external_log_system"
	}
	return out, nil
}
