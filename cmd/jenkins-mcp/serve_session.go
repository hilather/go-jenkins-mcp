package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

// serveOIDCSession holds mid-serve OIDC continuity state (wave 14).
// api_token sessions leave Guard and Live nil.
type serveOIDCSession struct {
	TokenResult auth.AccessTokenResult
	Groups      auth.GroupExtractResult
	Guard       *auth.SessionGuard
	Live        *auth.LiveSessionSource
	Binding     auth.SubjectBinding
}

// validateServeOIDCAccess re-checks JWT-shaped access tokens at serve start
// (discovery JWKS + exact jenkinsAudience). Opaque tokens skip local JWT parse.
// Wrong audience / signature fails closed before whoAmI and tool registration.
func validateServeOIDCAccess(
	ctx context.Context,
	sess auth.Session,
	profDoc *profile.Profile,
	baseURL string,
	httpClient *http.Client,
) (auth.AccessTokenResult, auth.GroupExtractResult, error) {
	var zero auth.AccessTokenResult
	var groups auth.GroupExtractResult
	if sess.Method != auth.MethodOIDC || profDoc == nil || profDoc.OIDC == nil || httpClient == nil {
		return zero, groups, nil
	}
	vctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	res, err := auth.ValidateServeAccessToken(vctx, sess.Secret, auth.ServeTokenValidation{
		Issuer:     profDoc.OIDC.Issuer,
		Audience:   profDoc.OIDC.JenkinsAudience,
		ClientID:   profDoc.OIDC.ClientID,
		TenantID:   profDoc.OIDC.TenantID,
		JenkinsURL: baseURL,
		HTTP:       httpClient,
	})
	if err != nil {
		return zero, groups, err
	}
	if res.Form == auth.TokenFormJWT {
		groups, err = auth.GroupsFromValidatedToken(sess.Secret, res, auth.DefaultGroupClaimConfig())
		if err != nil {
			return zero, auth.GroupExtractResult{}, err
		}
		log.Printf("OIDC JWT access token validated audience_ok form=jwt group_count=%d truncated=%v",
			len(groups.Groups), groups.Truncated)
	} else {
		log.Printf("OIDC access token form=opaque (JWT claims skipped; whoAmI binds identity)")
	}
	return res, groups, nil
}

// bindServeOIDCSession constructs SessionGuard + LiveSessionSource after
// AUTH-004 whoAmI has verified the Jenkins principal (OIDC only).
// When epochStore is non-nil, LiveSessionSource watches session.epoch so CLI
// logout/re-login in another process fail-closes mid-serve credentials.
func bindServeOIDCSession(
	sess auth.Session,
	authPr auth.Profile,
	profDoc *profile.Profile,
	oidcProv *auth.OIDCProvider,
	principal auth.Principal,
	tokenRes auth.AccessTokenResult,
	groups auth.GroupExtractResult,
	httpClient *http.Client,
	epochStore *auth.SessionEpochStore,
) serveOIDCSession {
	var out serveOIDCSession
	out.TokenResult = tokenRes
	out.Groups = groups
	if sess.Method != auth.MethodOIDC || oidcProv == nil {
		return out
	}
	extSub := tokenRes.Claims.Subject
	tenant := ""
	if profDoc != nil && profDoc.OIDC != nil {
		tenant = profDoc.OIDC.TenantID
	}
	if tenant == "" {
		tenant = tokenRes.Claims.TenantID
	}
	out.Binding = auth.BindOIDCSubject(extSub, tenant, principal.ID, groups.Groups, groups.ResidualNote)
	out.Guard = auth.NewSessionGuard(out.Binding.Fingerprint)
	var epochWatch *auth.SessionEpochWatcher
	if epochStore != nil {
		epochWatch = &auth.SessionEpochWatcher{Store: epochStore}
		if err := epochWatch.Bind(); err != nil {
			// Non-fatal at bind: first Credentials() will fail closed if still unreadable.
			log.Printf("session epoch bind: %v", err)
		} else {
			log.Printf("session epoch bound path=%s", epochStore.Path())
		}
	}
	out.Live = &auth.LiveSessionSource{
		OIDC:    oidcProv,
		Profile: authPr,
		Guard:   out.Guard,
		HTTP:    httpClient,
		Epoch:   epochWatch,
	}
	if out.Binding.ResidualNote != "" {
		log.Printf("OIDC group residual: %s", out.Binding.ResidualNote)
	}
	log.Printf("SessionGuard bound fingerprint_set=%v group_count=%d",
		out.Binding.Fingerprint != "", len(out.Binding.Groups))
	return out
}

// attachLiveAuthProvider installs OIDC mid-serve refresh on the Jenkins client.
// No-op when live is nil (api_token).
func attachLiveAuthProvider(client *jenkins.Client, live *auth.LiveSessionSource) {
	if client == nil || live == nil {
		return
	}
	src := live
	client.WithAuthProvider(func() (user, secret string, sch jenkins.AuthScheme, err error) {
		c, err := src.Credentials(context.Background())
		if err != nil {
			return "", "", "", err
		}
		out := jenkins.AuthSchemeBasic
		if c.Scheme == auth.HTTPAuthBearer {
			out = jenkins.AuthSchemeBearer
		}
		return c.User, c.Secret, out, nil
	})
}

// applyOIDCSubjectFields attaches external subject + bounded groups to a verified
// local (non-gateway) policy subject when OIDC claims are available.
func applyOIDCSubjectFields(subject policy.Subject, sess auth.Session, oidc serveOIDCSession, profDoc *profile.Profile) policy.Subject {
	if sess.Method != auth.MethodOIDC {
		return subject
	}
	ext := oidc.TokenResult.Claims.Subject
	tenant := ""
	if profDoc != nil && profDoc.OIDC != nil {
		tenant = profDoc.OIDC.TenantID
	}
	if tenant == "" {
		tenant = oidc.TokenResult.Claims.TenantID
	}
	if ext != "" || len(oidc.Groups.Groups) > 0 || tenant != "" {
		return subject.WithExternal(ext).WithGateway(tenant, "", oidc.Groups.Groups)
	}
	return subject
}
