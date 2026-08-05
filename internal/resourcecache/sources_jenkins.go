package resourcecache

import (
	"context"
	"fmt"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// JenkinsClient is the subset of *jenkins.Client used for resource sources.
type JenkinsClient interface {
	ListArtifacts(ctx context.Context, jobName string, buildNumber, maxArtifacts int) (*jenkins.ArtifactList, error)
	GetArtifactText(ctx context.Context, jobName string, buildNumber int, artifactPath string, maxBytes int) (*jenkins.ArtifactText, error)
	InspectArtifact(ctx context.Context, jobName string, buildNumber int, artifactPath string, maxBytes, maxMembers int) (*jenkins.ArtifactInspection, error)
	GetTestReport(ctx context.Context, jobName string, buildNumber, maxFailed int) (*jenkins.TestReport, error)
	GetPipelineStages(ctx context.Context, jobName string, buildNumber int) (*jenkins.PipelineStages, error)
	GetStageLog(ctx context.Context, jobName string, buildNumber int, stageID, stageName string, maxLength int) (*jenkins.StageLog, error)
	GetBuildChanges(ctx context.Context, args jenkins.GetBuildChangesToolArgs) (*jenkins.BuildChanges, error)
	// OpenArtifactStream is optional for full blob caching.
	// When not implemented, artifact_blob fetches via GetArtifactText only for small caps.
}

// ArtifactStreamer optionally provides exact-byte artifact streams.
type ArtifactStreamer interface {
	OpenArtifact(ctx context.Context, jobName string, buildNumber int, artifactPath string) (body interface {
		Read([]byte) (int, error)
		Close() error
	}, contentLength int64, err error)
}

// JenkinsSources implements SourceFetcher for approved kinds using JenkinsClient.
type JenkinsSources struct {
	Client JenkinsClient
}

// Fetch dispatches by key.Kind.
func (s *JenkinsSources) Fetch(ctx context.Context, key ResourceKey, _ *Entry) (FetchResult, error) {
	if s == nil || s.Client == nil {
		return FetchResult{}, apperr.New(apperr.CodeInternal, "jenkins source client nil")
	}
	job := key.JobFullName
	bn := int(key.BuildNumber)
	switch key.Kind {
	case KindArtifactCatalog:
		// Variant may encode max; default large fetch for catalog cache, tools re-cap.
		max := 5000
		list, err := s.Client.ListArtifacts(ctx, job, bn, max)
		if err != nil {
			return FetchResult{}, err
		}
		return FetchResult{
			Structured: list,
			Meta:       SourceMetadata{Completeness: Complete},
		}, nil
	case KindArtifactText:
		maxBytes := 256 * 1024
		at, err := s.Client.GetArtifactText(ctx, job, bn, key.Selector, maxBytes)
		if err != nil {
			return FetchResult{}, err
		}
		comp := Complete
		if at != nil && at.Truncated {
			comp = Partial
		}
		return FetchResult{
			Structured: at,
			Meta:       SourceMetadata{Completeness: comp},
		}, nil
	case KindArtifactInspection:
		ins, err := s.Client.InspectArtifact(ctx, job, bn, key.Selector, 0, 0)
		if err != nil {
			return FetchResult{}, err
		}
		return FetchResult{
			Structured: ins,
			Meta:       SourceMetadata{Completeness: Complete},
		}, nil
	case KindTestReport:
		// Variant may be "max_failed=N"; default 50 matches common tool default.
		maxFailed := 50
		if strings.HasPrefix(key.Variant, "max_failed=") {
			var n int
			if _, err := fmt.Sscanf(key.Variant, "max_failed=%d", &n); err == nil && n > 0 {
				maxFailed = n
			}
		}
		rep, err := s.Client.GetTestReport(ctx, job, bn, maxFailed)
		if err != nil {
			return FetchResult{}, err
		}
		return FetchResult{
			Structured: rep,
			Meta:       SourceMetadata{Completeness: Complete},
		}, nil
	case KindPipelineStages:
		ps, err := s.Client.GetPipelineStages(ctx, job, bn)
		if err != nil {
			return FetchResult{}, err
		}
		return FetchResult{
			Structured: ps,
			Meta:       SourceMetadata{Completeness: Complete},
		}, nil
	case KindBuildChanges:
		res, err := s.Client.GetBuildChanges(ctx, jenkins.GetBuildChangesToolArgs{
			JobName:     job,
			BuildNumber: bn,
		})
		if err != nil {
			return FetchResult{}, err
		}
		return FetchResult{
			Structured: res,
			Meta:       SourceMetadata{Completeness: Complete},
		}, nil
	case KindStageLog:
		maxLen := 0
		if strings.HasPrefix(key.Variant, "max_length=") {
			var n int
			if _, err := fmt.Sscanf(key.Variant, "max_length=%d", &n); err == nil {
				maxLen = n
			}
		}
		sl, err := s.Client.GetStageLog(ctx, job, bn, key.Selector, "", maxLen)
		if err != nil {
			return FetchResult{}, err
		}
		comp := Complete
		if sl != nil && sl.HasMore {
			comp = Partial
		}
		return FetchResult{
			Structured: sl,
			Meta: SourceMetadata{
				Completeness: comp,
				Extra:        map[string]string{"stage_id": sl.StageID},
			},
		}, nil
	case KindArtifactBlob:
		// Prefer streaming API if available; else fall back to GetArtifactText limited path
		// (not exact for large files — tools must use dedicated prewarm for full blobs).
		if as, ok := s.Client.(interface {
			DownloadArtifact(ctx context.Context, jobName string, buildNumber int, path string) ([]byte, error)
		}); ok {
			b, err := as.DownloadArtifact(ctx, job, bn, key.Selector)
			if err != nil {
				return FetchResult{}, err
			}
			return FetchResult{
				Bytes: b,
				Meta:  SourceMetadata{Completeness: Complete, ContentLength: int64(len(b))},
			}, nil
		}
		// Fallback: bounded text download is Partial and should not be sealed as blob complete.
		at, err := s.Client.GetArtifactText(ctx, job, bn, key.Selector, 256*1024)
		if err != nil {
			return FetchResult{}, err
		}
		return FetchResult{
			Bytes: []byte(at.Content),
			Meta: SourceMetadata{
				Completeness:  Partial,
				ContentLength: int64(len(at.Content)),
			},
		}, nil
	default:
		return FetchResult{}, apperr.New(apperr.CodeInvalidArgument, "unsupported resource kind for jenkins source")
	}
}

// Ensure *jenkins.Client satisfies JenkinsClient at compile time when methods exist.
var _ JenkinsClient = (*jenkins.Client)(nil)
