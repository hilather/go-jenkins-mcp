package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// RSProbeOptions configures online resource-server fallthrough probes (OAUTH-009).
// Secrets in bearer material must never appear in results.
type RSProbeOptions struct {
	// Client is a Jenkins client pointed at the controller under test.
	Client *jenkins.Client
	// HTTP optional override for CallJenkins transport (tests).
	HTTP *http.Client
	// Paths to probe; empty → auth.RequiredMCPRoutes example paths (capped).
	Paths []string
	// MaxPaths bounds online fan-out (0 → default 8).
	MaxPaths int
	// InvalidBearer is sent as Authorization Bearer (default: fixed non-secret canary).
	InvalidBearer string
	// Timeout per request (0 → 5s).
	Timeout time.Duration
}

// RSPathProbe is one path's invalid-bearer result (non-secret).
type RSPathProbe struct {
	Path                string `json:"path"`
	StatusCode          int    `json:"statusCode"`
	Denied              bool   `json:"denied"`
	FallthroughDetected bool   `json:"fallthroughDetected"`
	Reason              string `json:"reason"`
}

// RSOnlineProbeResult aggregates online fallthrough samples and optional bearer whoAmI.
type RSOnlineProbeResult struct {
	PathsProbed       int           `json:"pathsProbed"`
	Denied            int           `json:"denied"`
	Fallthrough       int           `json:"fallthrough"`
	Inconclusive      int           `json:"inconclusive"`
	AllDenied         bool          `json:"allDenied"`
	Results           []RSPathProbe `json:"results"`
	BearerWhoAmIOK    bool          `json:"bearerWhoAmIOK,omitempty"`
	BearerWhoAmIError string        `json:"bearerWhoAmIError,omitempty"`
	PrincipalID       string        `json:"principalId,omitempty"`
}

const (
	defaultRSProbePaths   = 8
	defaultRSProbeTimeout = 5 * time.Second
	defaultInvalidBearer  = "oauth-009-invalid-bearer-not-a-jwt"
)

// ProbeInvalidBearerFallthrough sends Authorization: Bearer <invalid> to sample
// MCP routes and evaluates auth.FallthroughMustDeny via EvaluateInvalidBearerResponse.
func ProbeInvalidBearerFallthrough(ctx context.Context, opts RSProbeOptions) (RSOnlineProbeResult, error) {
	if opts.Client == nil {
		return RSOnlineProbeResult{}, apperr.New(apperr.CodeInvalidArgument, "jenkins client is required")
	}
	if err := ctx.Err(); err != nil {
		return RSOnlineProbeResult{}, apperr.Wrap(apperr.CodeCancelled, "rs probe cancelled", err)
	}
	httpClient := opts.HTTP
	if httpClient == nil {
		httpClient = opts.Client.Client
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	paths := opts.Paths
	if len(paths) == 0 {
		for _, r := range auth.RequiredMCPRoutes {
			paths = append(paths, r.ExamplePath)
		}
	}
	max := opts.MaxPaths
	if max <= 0 {
		max = defaultRSProbePaths
	}
	if len(paths) > max {
		paths = paths[:max]
	}
	invalid := strings.TrimSpace(opts.InvalidBearer)
	if invalid == "" {
		invalid = defaultInvalidBearer
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultRSProbeTimeout
	}

	// Build a disposable probe client (never mutate caller; avoid copying Mutex).
	probe := &jenkins.Client{
		URL:        opts.Client.URL,
		Token:      invalid,
		AuthScheme: jenkins.AuthSchemeBearer,
		User:       "",
		Client:     httpClient,
	}

	out := RSOnlineProbeResult{}
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return out, apperr.Wrap(apperr.CodeCancelled, "rs probe cancelled", err)
		}
		pr := probeOneInvalidBearer(ctx, probe, httpClient, p, invalid, timeout)
		out.Results = append(out.Results, pr)
		out.PathsProbed++
		switch {
		case pr.Denied:
			out.Denied++
		case pr.FallthroughDetected:
			out.Fallthrough++
		default:
			out.Inconclusive++
		}
	}
	out.AllDenied = out.PathsProbed > 0 && out.Fallthrough == 0 && out.Denied == out.PathsProbed
	return out, nil
}

func probeOneInvalidBearer(ctx context.Context, c *jenkins.Client, httpClient *http.Client, path, invalid string, timeout time.Duration) RSPathProbe {
	res := RSPathProbe{Path: path}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := c.CallJenkins(pctx, httpClient, http.MethodGet, path, nil, nil)
	if err != nil {
		// CallJenkins may wrap 4xx as transport errors depending on path; treat
		// message classes carefully without echoing bearer.
		msg := err.Error()
		if strings.Contains(msg, invalid) {
			res.Reason = "transport error"
			return res
		}
		// Some client paths return error before status; mark inconclusive.
		res.Reason = "transport or policy error"
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	res.StatusCode = resp.StatusCode

	// Wave 33: use full classifier (WWW-Authenticate + body class), not whoAmI flags alone.
	bc := auth.ClassifyResponseBodyClass(body)
	www := resp.Header.Get("WWW-Authenticate")
	authenticated, anonymous := parseWhoAmIFlags(body)
	eval := auth.ClassifyFallthroughProbe(auth.FallthroughProbeInput{
		StatusCode:          resp.StatusCode,
		WWWAuthenticate:     www,
		BodyClass:           bc,
		WhoAmIAuthenticated: authenticated,
		WhoAmIAnonymous:     anonymous,
	})
	res.Denied = eval.Denied
	res.FallthroughDetected = eval.FallthroughDetected
	res.Reason = eval.Reason
	// Canary: never echo the invalid bearer probe string (or any secret-shaped token).
	if invalid != "" && strings.Contains(res.Reason, invalid) {
		res.Reason = "invalid bearer evaluation"
	}
	if strings.Contains(res.Reason, "Bearer ey") {
		res.Reason = "invalid bearer evaluation"
	}
	return res
}

func parseWhoAmIFlags(body []byte) (authenticated, anonymous bool) {
	if len(body) == 0 {
		return false, false
	}
	var who struct {
		Authenticated bool `json:"authenticated"`
		Anonymous     bool `json:"anonymous"`
	}
	if err := json.Unmarshal(body, &who); err != nil {
		return false, false
	}
	return who.Authenticated, who.Anonymous
}

// ProbeBearerWhoAmI calls whoAmI with the client's configured Bearer token.
// Never returns the token in errors.
func ProbeBearerWhoAmI(ctx context.Context, c *jenkins.Client) (jenkins.WhoAmI, error) {
	if c == nil {
		return jenkins.WhoAmI{}, apperr.New(apperr.CodeInvalidArgument, "jenkins client is required")
	}
	if strings.TrimSpace(c.Token) == "" {
		return jenkins.WhoAmI{}, apperr.New(apperr.CodeAuthentication, "bearer token not configured on client")
	}
	prev := c.AuthScheme
	c.AuthScheme = jenkins.AuthSchemeBearer
	defer func() { c.AuthScheme = prev }()
	who, err := c.WhoAmI(ctx)
	if err != nil {
		if c.Token != "" && strings.Contains(err.Error(), c.Token) {
			return jenkins.WhoAmI{}, apperr.New(apperr.CodeAuthentication, "bearer whoAmI failed")
		}
		return jenkins.WhoAmI{}, err
	}
	if who.Anonymous || !who.Authenticated || strings.TrimSpace(who.ID) == "" {
		return who, apperr.New(apperr.CodeAuthentication, "bearer whoAmI returned anonymous or empty principal")
	}
	return who, nil
}

// FormatRSOnlineProbeText is a secret-free summary for CLI.
func FormatRSOnlineProbeText(r RSOnlineProbeResult) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("online invalid-bearer probes: paths=%d denied=%d fallthrough=%d inconclusive=%d all_denied=%v\n",
		r.PathsProbed, r.Denied, r.Fallthrough, r.Inconclusive, r.AllDenied))
	for _, p := range r.Results {
		b.WriteString(fmt.Sprintf("  %s → HTTP %d denied=%v fallthrough=%v (%s)\n",
			p.Path, p.StatusCode, p.Denied, p.FallthroughDetected, p.Reason))
	}
	if r.BearerWhoAmIError != "" {
		b.WriteString("bearer whoAmI: " + r.BearerWhoAmIError + "\n")
	} else if r.BearerWhoAmIOK {
		b.WriteString(fmt.Sprintf("bearer whoAmI: ok principal=%s\n", r.PrincipalID))
	}
	return b.String()
}
