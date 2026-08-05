package tools

import (
	"context"
	"fmt"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/resourcecache"
)

// ResourceCache is optional durable typed cache for approved tools.
// Implemented by *resourcecache.Cache.
type ResourceCache interface {
	GetOrFetch(ctx context.Context, req resourcecache.FetchRequest) (resourcecache.EntryReader, resourcecache.LookupResult, error)
}

// policyVerifier adapts MCP policy.Subject + PolicyEvaluator to resourcecache.AuthorizationVerifier.
type policyVerifier struct {
	st regState
}

func (v policyVerifier) AuthorizeJob(ctx context.Context, ac resourcecache.AccessContext, jobFullName string) error {
	if v.st.policy == nil {
		return nil
	}
	subj := effectiveSubject(v.st, ctx)
	d := v.st.policy.Evaluate(subj, policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead}, policy.Target{JobName: jobFullName})
	if !d.Allowed() {
		return apperr.New(apperr.CodePolicyDenial, "MCP policy denied job for cache access")
	}
	return nil
}

func (v policyVerifier) AuthorizeArtifact(ctx context.Context, ac resourcecache.AccessContext, jobFullName, artifactPath string) error {
	if v.st.policy == nil {
		return nil
	}
	subj := effectiveSubject(v.st, ctx)
	d := v.st.policy.Evaluate(subj, policy.Action{ToolName: "jenkins_get_artifact_text", Class: policy.EffectRead}, policy.Target{
		JobName:      jobFullName,
		ArtifactPath: artifactPath,
	})
	if !d.Allowed() {
		return apperr.New(apperr.CodePolicyDenial, "MCP policy denied artifact path for cache access")
	}
	return nil
}

// resourceAccess builds AccessContext from regState/request context.
func resourceAccess(ctx context.Context, st regState, profileID string) resourcecache.AccessContext {
	subj := effectiveSubject(st, ctx)
	return resourcecache.AccessContext{
		SubjectKey:  effectiveSubjectKey(st, ctx),
		PrincipalID: subj.JenkinsUserID,
		ProfileID:   firstNonEmptyStr(profileID, st.profileID),
		Groups:      subj.Groups,
	}
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// getCachedStructured fetches via ResourceCache when configured, else calls origin.
func getCachedStructured[T any](
	ctx context.Context,
	st regState,
	client *jenkins.Client,
	key resourcecache.ResourceKey,
	artifactPath string,
	origin func() (T, error),
) (T, resourcecache.LookupResult, error) {
	var zero T
	rc, ok := st.resourceCache.(*resourcecache.Cache)
	if !ok || rc == nil {
		v, err := origin()
		return v, resourcecache.LookupResult{Source: resourcecache.SourceOrigin}, err
	}
	key.ProfileID = firstNonEmptyStr(key.ProfileID, st.profileID)
	src := &resourcecache.JenkinsSources{Client: client}
	er, lr, err := rc.GetOrFetch(ctx, resourcecache.FetchRequest{
		Key:          key,
		Access:       resourceAccess(ctx, st, key.ProfileID),
		Source:       src,
		ArtifactPath: artifactPath,
		Verifier:     policyVerifier{st: st},
	})
	if err != nil {
		return zero, lr, err
	}
	var out T
	if err := er.DecodeStructured(&out); err != nil {
		// Cache corrupt → origin fallback once
		v, oerr := origin()
		if oerr != nil {
			return zero, lr, fmt.Errorf("cache decode: %w; origin: %v", err, oerr)
		}
		return v, resourcecache.LookupResult{Source: resourcecache.SourceOrigin}, nil
	}
	return out, lr, nil
}
