package tools

import (
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
)

// ContentKindTestFailure labels untrusted JUnit failure text (TEST-001 / SEC-002).
const ContentKindTestFailure = "test_failure_excerpt"

// ContentKindStageLog labels untrusted stage/node log text (PIPE-002 / SEC-002).
const ContentKindStageLog = "stage_log_excerpt"

// ContentKindArtifactText labels untrusted artifact text (ART-001 / SEC-002).
const ContentKindArtifactText = "artifact_text_excerpt"

// ContentKindTestAnalysis labels test classification results (TEST-002).
const ContentKindTestAnalysis = "test_analysis"

// sanitizedBuildLogs is the model-facing build log payload (SEC-002/003).
// Evidence handles (job, build, offset, totalSize, hasMore) are preserved for
// forensic range retrieval; Logs is control-stripped and secret-redacted.
// Untrusted marks the text as untrusted build output (never control/instructions).
type sanitizedBuildLogs struct {
	JobName     string         `json:"jobName"`
	BuildNumber int            `json:"buildNumber"`
	Offset      int            `json:"offset"`
	Length      int            `json:"length"`
	TotalSize   int            `json:"totalSize"`
	HasMore     bool           `json:"hasMore"`
	Logs        string         `json:"logs"`
	Untrusted   bool           `json:"untrusted"`
	ContentKind string         `json:"content_kind"`
	Redaction   map[string]int `json:"redaction,omitempty"`
}

// PrepareBuildLogsForModel applies SanitizeForModel (control strip + layered
// redaction) to the log body and labels the payload as untrusted. Call before
// EnforceBudget so truncation sees the post-redaction size.
//
// Exported for unit tests; production handlers call this before structuredResult.
func PrepareBuildLogsForModel(bl *jenkins.BuildLogs) sanitizedBuildLogs {
	if bl == nil {
		return sanitizedBuildLogs{
			Untrusted:   true,
			ContentKind: redact.ContentKindBuildLog,
		}
	}
	text, rep := redact.SanitizeForModelReport(bl.Logs)
	out := sanitizedBuildLogs{
		JobName:     bl.JobName,
		BuildNumber: bl.BuildNumber,
		Offset:      bl.Offset,
		// Length is the model-visible excerpt size (after sanitize/redact).
		Length:      len(text),
		TotalSize:   bl.TotalSize,
		HasMore:     bl.HasMore,
		Logs:        text,
		Untrusted:   true,
		ContentKind: redact.ContentKindBuildLog,
	}
	if rep.Total() > 0 {
		out.Redaction = rep.Counts
	}
	return out
}

// redactParamMap redacts Jenkins build parameter maps for model output
// (sensitive keys fully replaced; all values also pass RedactText).
func redactParamMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if redact.IsSensitiveFieldName(k) {
			out[k] = redact.Replacement
			continue
		}
		out[k] = redact.RedactText(v)
	}
	return out
}

// prepareBuildForModel copies a Build and redacts Parameters (SEC-002 light wire).
func prepareBuildForModel(b jenkins.Build) jenkins.Build {
	b.Parameters = redactParamMap(b.Parameters)
	return b
}

// prepareSearchBuildsForModel redacts parameter maps on each matched build.
func prepareSearchBuildsForModel(res *jenkins.SearchBuildsToolResponse) jenkins.SearchBuildsToolResponse {
	if res == nil {
		return jenkins.SearchBuildsToolResponse{}
	}
	out := *res
	if len(out.Builds) == 0 {
		return out
	}
	builds := make([]jenkins.Build, len(out.Builds))
	for i := range out.Builds {
		builds[i] = prepareBuildForModel(out.Builds[i])
	}
	out.Builds = builds
	return out
}

// PrepareTestReportForModel redacts failure messages and labels the payload
// as untrusted build/test output (TEST-001). Call before EnforceBudget.
type sanitizedTestReport struct {
	JobName              string                `json:"jobName"`
	BuildNumber          int                   `json:"buildNumber"`
	Available            bool                  `json:"available"`
	PassCount            int                   `json:"passCount"`
	FailCount            int                   `json:"failCount"`
	SkipCount            int                   `json:"skipCount"`
	TotalCount           int                   `json:"totalCount"`
	Duration             jenkins.DurationMS    `json:"duration"`
	FailedTests          []sanitizedFailedTest `json:"failedTests,omitempty"`
	FailedTestsTruncated bool                  `json:"failedTestsTruncated,omitempty"`
	Message              string                `json:"message,omitempty"`
	Untrusted            bool                  `json:"untrusted"`
	ContentKind          string                `json:"content_kind,omitempty"`
	Redaction            map[string]int        `json:"redaction,omitempty"`
}

type sanitizedFailedTest struct {
	Name            string             `json:"name"`
	ClassName       string             `json:"className,omitempty"`
	Status          string             `json:"status,omitempty"`
	Duration        jenkins.DurationMS `json:"duration"`
	Age             int                `json:"age,omitempty"`
	ErrorDetails    string             `json:"errorDetails,omitempty"`
	ErrorStackTrace string             `json:"errorStackTrace,omitempty"`
}

func PrepareTestReportForModel(rep *jenkins.TestReport) sanitizedTestReport {
	if rep == nil {
		return sanitizedTestReport{
			Available:   false,
			Untrusted:   true,
			ContentKind: ContentKindTestFailure,
			Message:     "no test report",
		}
	}
	out := sanitizedTestReport{
		JobName:              rep.JobName,
		BuildNumber:          rep.BuildNumber,
		Available:            rep.Available,
		PassCount:            rep.PassCount,
		FailCount:            rep.FailCount,
		SkipCount:            rep.SkipCount,
		TotalCount:           rep.TotalCount,
		Duration:             rep.Duration,
		FailedTestsTruncated: rep.FailedTestsTruncated,
		Message:              rep.Message,
		Untrusted:            true,
		ContentKind:          ContentKindTestFailure,
	}
	if len(rep.FailedTests) == 0 {
		return out
	}
	counts := make(map[string]int)
	out.FailedTests = make([]sanitizedFailedTest, len(rep.FailedTests))
	for i, ft := range rep.FailedTests {
		details, dRep := redact.SanitizeForModelReport(ft.ErrorDetails)
		trace, tRep := redact.SanitizeForModelReport(ft.ErrorStackTrace)
		for k, v := range dRep.Counts {
			counts[k] += v
		}
		for k, v := range tRep.Counts {
			counts[k] += v
		}
		out.FailedTests[i] = sanitizedFailedTest{
			Name:            ft.Name,
			ClassName:       ft.ClassName,
			Status:          ft.Status,
			Duration:        ft.Duration,
			Age:             ft.Age,
			ErrorDetails:    details,
			ErrorStackTrace: trace,
		}
	}
	if len(counts) > 0 {
		out.Redaction = counts
	}
	return out
}

// sanitizedStageLog is the model-facing stage log payload (PIPE-002 / SEC-002).
type sanitizedStageLog struct {
	JobName     string         `json:"jobName"`
	BuildNumber int            `json:"buildNumber"`
	StageID     string         `json:"stageId"`
	StageName   string         `json:"stageName,omitempty"`
	SourceAPI   string         `json:"sourceApi"`
	NodeStatus  string         `json:"nodeStatus,omitempty"`
	Offset      int            `json:"offset"`
	Length      int            `json:"length"`
	TotalSize   int            `json:"totalSize"`
	HasMore     bool           `json:"hasMore"`
	Logs        string         `json:"logs"`
	LogKeyJob   string         `json:"logKeyJob,omitempty"`
	Mirrored    bool           `json:"mirrored,omitempty"`
	Untrusted   bool           `json:"untrusted"`
	ContentKind string         `json:"content_kind"`
	Redaction   map[string]int `json:"redaction,omitempty"`
}

// PrepareStageLogForModel sanitizes stage log text for the model (PIPE-002).
func PrepareStageLogForModel(sl *jenkins.StageLog) sanitizedStageLog {
	if sl == nil {
		return sanitizedStageLog{
			Untrusted:   true,
			ContentKind: ContentKindStageLog,
		}
	}
	text, rep := redact.SanitizeForModelReport(sl.Logs)
	out := sanitizedStageLog{
		JobName:     sl.JobName,
		BuildNumber: sl.BuildNumber,
		StageID:     sl.StageID,
		StageName:   sl.StageName,
		SourceAPI:   sl.SourceAPI,
		NodeStatus:  sl.NodeStatus,
		Offset:      sl.Offset,
		Length:      len(text),
		TotalSize:   sl.TotalSize,
		HasMore:     sl.HasMore,
		Logs:        text,
		LogKeyJob:   sl.LogKeyJob,
		Mirrored:    sl.Mirrored,
		Untrusted:   true,
		ContentKind: ContentKindStageLog,
	}
	if rep.Total() > 0 {
		out.Redaction = rep.Counts
	}
	return out
}

// sanitizedTestAnalysis is model-facing TEST-002 output (no secret-bearing stacks).
type sanitizedTestAnalysis struct {
	JobName          string                       `json:"jobName"`
	BuildNumber      int                          `json:"buildNumber"`
	Lookback         int                          `json:"lookback"`
	SampleSize       int                          `json:"sampleSize"`
	CurrentAvailable bool                         `json:"currentAvailable"`
	CurrentFailCount int                          `json:"currentFailCount"`
	Classifications  []jenkins.TestClassification `json:"classifications,omitempty"`
	Truncated        bool                         `json:"truncated,omitempty"`
	Message          string                       `json:"message,omitempty"`
	HistoryTruncated bool                         `json:"historyTruncated,omitempty"`
	Untrusted        bool                         `json:"untrusted"`
	ContentKind      string                       `json:"content_kind"`
}

// PrepareTestAnalysisForModel labels analysis output (classifications are metadata-only).
func PrepareTestAnalysisForModel(an *jenkins.TestAnalysis) sanitizedTestAnalysis {
	if an == nil {
		return sanitizedTestAnalysis{
			Untrusted:   true,
			ContentKind: ContentKindTestAnalysis,
			Message:     "no analysis",
		}
	}
	return sanitizedTestAnalysis{
		JobName:          an.JobName,
		BuildNumber:      an.BuildNumber,
		Lookback:         an.Lookback,
		SampleSize:       an.SampleSize,
		CurrentAvailable: an.CurrentAvailable,
		CurrentFailCount: an.CurrentFailCount,
		Classifications:  an.Classifications,
		Truncated:        an.Truncated,
		Message:          an.Message,
		HistoryTruncated: an.HistoryTruncated,
		Untrusted:        true,
		ContentKind:      ContentKindTestAnalysis,
	}
}

// sanitizedArtifactText is model-facing artifact text (ART-001 / SEC-002).
type sanitizedArtifactText struct {
	JobName     string         `json:"jobName"`
	BuildNumber int            `json:"buildNumber"`
	Path        string         `json:"path"`
	SizeBytes   int64          `json:"sizeBytes"`
	Truncated   bool           `json:"truncated,omitempty"`
	SHA256      string         `json:"sha256"`
	ContentType string         `json:"contentType,omitempty"`
	Content     string         `json:"content"`
	Ref         string         `json:"ref,omitempty"`
	Untrusted   bool           `json:"untrusted"`
	ContentKind string         `json:"content_kind"`
	Redaction   map[string]int `json:"redaction,omitempty"`
}

// PrepareArtifactTextForModel sanitizes artifact body for the model (ART-001).
func PrepareArtifactTextForModel(at *jenkins.ArtifactText) sanitizedArtifactText {
	if at == nil {
		return sanitizedArtifactText{
			Untrusted:   true,
			ContentKind: ContentKindArtifactText,
		}
	}
	text, rep := redact.SanitizeForModelReport(at.Content)
	out := sanitizedArtifactText{
		JobName:     at.JobName,
		BuildNumber: at.BuildNumber,
		Path:        at.Path,
		SizeBytes:   at.SizeBytes,
		Truncated:   at.Truncated,
		SHA256:      at.SHA256,
		ContentType: at.ContentType,
		Content:     text,
		Ref:         at.Ref,
		Untrusted:   true,
		ContentKind: ContentKindArtifactText,
	}
	if rep.Total() > 0 {
		out.Redaction = rep.Counts
	}
	return out
}

// ContentKindArtifactInspect labels untrusted artifact inspection text (ART-002).
const ContentKindArtifactInspect = "artifact_inspect"

// ContentKindSCMChanges labels SCM commit messages/paths (SCM-001 / SEC-002).
const ContentKindSCMChanges = "scm_changes"

// sanitizedArtifactInspection is model-facing ART-002 output.
type sanitizedArtifactInspection struct {
	JobName     string                    `json:"jobName"`
	BuildNumber int                       `json:"buildNumber"`
	Path        string                    `json:"path"`
	Kind        string                    `json:"kind"`
	SizeBytes   int64                     `json:"sizeBytes"`
	SHA256      string                    `json:"sha256,omitempty"`
	ContentType string                    `json:"contentType,omitempty"`
	Truncated   bool                      `json:"truncated,omitempty"`
	Text        string                    `json:"text,omitempty"`
	JSONValid   bool                      `json:"jsonValid,omitempty"`
	XMLValid    bool                      `json:"xmlValid,omitempty"`
	ParseError  string                    `json:"parseError,omitempty"`
	Archive     *jenkins.ArchiveInventory `json:"archive,omitempty"`
	Ref         string                    `json:"ref,omitempty"`
	Residuals   []string                  `json:"residuals,omitempty"`
	Message     string                    `json:"message,omitempty"`
	Untrusted   bool                      `json:"untrusted"`
	ContentKind string                    `json:"content_kind"`
	Redaction   map[string]int            `json:"redaction,omitempty"`
}

// PrepareArtifactInspectionForModel sanitizes inspect text snippets (ART-002).
func PrepareArtifactInspectionForModel(ins *jenkins.ArtifactInspection) sanitizedArtifactInspection {
	if ins == nil {
		return sanitizedArtifactInspection{
			Untrusted:   true,
			ContentKind: ContentKindArtifactInspect,
		}
	}
	text, rep := redact.SanitizeForModelReport(ins.Text)
	out := sanitizedArtifactInspection{
		JobName:     ins.JobName,
		BuildNumber: ins.BuildNumber,
		Path:        ins.Path,
		Kind:        ins.Kind,
		SizeBytes:   ins.SizeBytes,
		SHA256:      ins.SHA256,
		ContentType: ins.ContentType,
		Truncated:   ins.Truncated,
		Text:        text,
		JSONValid:   ins.JSONValid,
		XMLValid:    ins.XMLValid,
		ParseError:  ins.ParseError,
		Archive:     ins.Archive,
		Ref:         ins.Ref,
		Residuals:   ins.Residuals,
		Message:     ins.Message,
		Untrusted:   true,
		ContentKind: ContentKindArtifactInspect,
	}
	if rep.Total() > 0 {
		out.Redaction = rep.Counts
	}
	return out
}

// sanitizedBuildChanges is model-facing SCM-001 output (commit messages redacted).
type sanitizedBuildChanges struct {
	JobName         string                  `json:"jobName"`
	BuildNumber     int                     `json:"buildNumber"`
	BaselineBuild   int                     `json:"baselineBuild,omitempty"`
	ChangeSets      []sanitizedSCMChangeSet `json:"changeSets"`
	Culprits        []jenkins.SCMCulprit    `json:"culprits,omitempty"`
	CommitOffset    int                     `json:"commitOffset"`
	CommitLimit     int                     `json:"commitLimit"`
	CommitsReturned int                     `json:"commitsReturned"`
	CommitsTotal    int                     `json:"commitsTotal"`
	Truncated       bool                    `json:"truncated,omitempty"`
	BuildsScanned   int                     `json:"buildsScanned,omitempty"`
	Residuals       []string                `json:"residuals,omitempty"`
	Message         string                  `json:"message,omitempty"`
	Untrusted       bool                    `json:"untrusted"`
	ContentKind     string                  `json:"content_kind"`
	Redaction       map[string]int          `json:"redaction,omitempty"`
}

type sanitizedSCMChangeSet struct {
	Kind             string                `json:"kind,omitempty"`
	RepoURLs         []string              `json:"repoUrls,omitempty"`
	Revisions        []jenkins.SCMRevision `json:"revisions,omitempty"`
	Commits          []sanitizedSCMCommit  `json:"commits,omitempty"`
	CommitsTotal     int                   `json:"commitsTotal"`
	CommitsTruncated bool                  `json:"commitsTruncated,omitempty"`
}

type sanitizedSCMCommit struct {
	ID               string   `json:"id,omitempty"`
	Message          string   `json:"message,omitempty"`
	Author           string   `json:"author,omitempty"`
	Timestamp        int64    `json:"timestamp,omitempty"`
	AffectedPaths    []string `json:"affectedPaths,omitempty"`
	PathsTruncated   bool     `json:"pathsTruncated,omitempty"`
	MessageTruncated bool     `json:"messageTruncated,omitempty"`
	BuildNumber      int      `json:"buildNumber,omitempty"`
}

// PrepareBuildChangesForModel redacts commit messages for the model (SCM-001).
func PrepareBuildChangesForModel(bc *jenkins.BuildChanges) sanitizedBuildChanges {
	if bc == nil {
		return sanitizedBuildChanges{
			ChangeSets:  []sanitizedSCMChangeSet{},
			Untrusted:   true,
			ContentKind: ContentKindSCMChanges,
			Message:     "no changes",
		}
	}
	counts := make(map[string]int)
	out := sanitizedBuildChanges{
		JobName:         bc.JobName,
		BuildNumber:     bc.BuildNumber,
		BaselineBuild:   bc.BaselineBuild,
		Culprits:        bc.Culprits,
		CommitOffset:    bc.CommitOffset,
		CommitLimit:     bc.CommitLimit,
		CommitsReturned: bc.CommitsReturned,
		CommitsTotal:    bc.CommitsTotal,
		Truncated:       bc.Truncated,
		BuildsScanned:   bc.BuildsScanned,
		Residuals:       bc.Residuals,
		Message:         bc.Message,
		Untrusted:       true,
		ContentKind:     ContentKindSCMChanges,
		ChangeSets:      make([]sanitizedSCMChangeSet, 0, len(bc.ChangeSets)),
	}
	for _, cs := range bc.ChangeSets {
		scs := sanitizedSCMChangeSet{
			Kind:             cs.Kind,
			RepoURLs:         cs.RepoURLs,
			Revisions:        cs.Revisions,
			CommitsTotal:     cs.CommitsTotal,
			CommitsTruncated: cs.CommitsTruncated,
			Commits:          make([]sanitizedSCMCommit, 0, len(cs.Commits)),
		}
		for _, c := range cs.Commits {
			msg, rep := redact.SanitizeForModelReport(c.Message)
			for k, v := range rep.Counts {
				counts[k] += v
			}
			// Paths are repo-relative file names; still strip controls.
			paths := make([]string, len(c.AffectedPaths))
			for i, p := range c.AffectedPaths {
				paths[i] = redact.StripControlSequences(p)
			}
			scs.Commits = append(scs.Commits, sanitizedSCMCommit{
				ID:               c.ID,
				Message:          msg,
				Author:           c.Author,
				Timestamp:        c.Timestamp,
				AffectedPaths:    paths,
				PathsTruncated:   c.PathsTruncated,
				MessageTruncated: c.MessageTruncated,
				BuildNumber:      c.BuildNumber,
			})
		}
		out.ChangeSets = append(out.ChangeSets, scs)
	}
	if len(counts) > 0 {
		out.Redaction = counts
	}
	return out
}

func prepareListBuildsForModel(res *jenkins.ListBuildsToolResponse) jenkins.ListBuildsToolResponse {
	if res == nil {
		return jenkins.ListBuildsToolResponse{}
	}
	out := *res
	if len(out.Builds) == 0 {
		return out
	}
	builds := make([]jenkins.Build, len(out.Builds))
	for i := range out.Builds {
		builds[i] = prepareBuildForModel(out.Builds[i])
	}
	out.Builds = builds
	return out
}
