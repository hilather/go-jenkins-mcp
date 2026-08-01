package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

// runOAuth dispatches OAuth/OIDC operator commands (OAUTH-001 / OAUTH-009).
func runOAuth(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"oauth subcommand required: validate-profile|probe-rs")
	}
	switch args[0] {
	case "validate-profile":
		return runOAuthValidateProfile(args[1:])
	case "probe-rs":
		return runOAuthProbeRS(args[1:])
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unknown oauth subcommand %q (validate-profile|probe-rs)", args[0]))
	}
}

// runOAuthValidateProfile checks oidc_bearer profile structure and optionally
// live OIDC discovery (/.well-known/openid-configuration).
//
//	jenkins-mcp oauth validate-profile --profile <id> [--offline]
func runOAuthValidateProfile(args []string) error {
	fs := flag.NewFlagSet("oauth validate-profile", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	offline := fs.Bool("offline", false, "Structural checks only (skip network discovery)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"profile": true, "offline": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if strings.TrimSpace(*profileFlag) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}

	store, err := profileStore()
	if err != nil {
		return err
	}
	p, err := store.Load(*profileFlag)
	if err != nil {
		return err
	}

	if err := auth.ValidateOIDCProfileOffline(p); err != nil {
		return err
	}

	fmt.Printf("profile:          %s\n", p.ID)
	fmt.Printf("authMethod:       %s\n", p.AuthMethod)
	fmt.Printf("jenkinsURL:       %s\n", p.JenkinsURL)
	fmt.Printf("oidc.issuer:      %s\n", p.OIDC.Issuer)
	fmt.Printf("oidc.clientId:    %s\n", p.OIDC.ClientID)
	fmt.Printf("oidc.audience:    %s\n", p.OIDC.JenkinsAudience)
	fmt.Printf("oidc.scopes:      %s\n", strings.Join(p.OIDC.Scopes, " "))
	if len(p.OIDC.RedirectURIs) > 0 {
		fmt.Printf("oidc.redirects:   %s\n", strings.Join(p.OIDC.RedirectURIs, ", "))
	} else {
		fmt.Printf("oidc.redirects:   (none configured; required for OAUTH-002 browser login)\n")
	}
	fmt.Printf("structural:       ok\n")

	if *offline {
		fmt.Printf("discovery:        skipped (--offline)\n")
		return nil
	}

	client, err := discoveryHTTPClient(p)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	doc, err := auth.ValidateOIDCProfileOnline(ctx, client, p)
	if err != nil {
		return err
	}
	fmt.Printf("discovery:        ok\n")
	fmt.Printf("  authorization:  %s\n", doc.AuthorizationEndpoint)
	fmt.Printf("  token:          %s\n", doc.TokenEndpoint)
	fmt.Printf("  jwks:           %s\n", doc.JWKSURI)
	if !doc.ExpiresAt.IsZero() {
		fmt.Printf("  cache-hint:     max-age until %s (durable metadata cache residual)\n",
			doc.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

func discoveryHTTPClient(p *profile.Profile) (*http.Client, error) {
	cfg := transportConfigFromProfile(p, "", "", false)
	// Discovery is a small JSON GET; prefer API timeout.
	if cfg.APIClientTimeout == 0 {
		cfg.APIClientTimeout = 15 * time.Second
	}
	tr, err := jenkins.NewTransport(cfg)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: tr,
		Timeout:   cfg.APIClientTimeout,
	}, nil
}

// runOAuthProbeRS prints jwt-auth-filter / resource-server qualification
// matrix and optional online fallthrough samples (OAUTH-009).
//
//	jenkins-mcp oauth probe-rs --profile <id> [--offline]
func runOAuthProbeRS(args []string) error {
	fs := flag.NewFlagSet("oauth probe-rs", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	offline := fs.Bool("offline", false, "Matrix and residuals only (skip network probes)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"profile": true, "offline": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if strings.TrimSpace(*profileFlag) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}

	store, err := profileStore()
	if err != nil {
		return err
	}
	p, err := store.Load(*profileFlag)
	if err != nil {
		return err
	}

	rep := auth.BuildOfflineRSProbe(string(p.AuthMethod))
	// Explicit oic-auth-only warning for operators selecting bearer without RS.
	if p.AuthMethod == profile.AuthMethodOIDC {
		rep.Warnings = append(rep.Warnings, auth.WarnOnlyOICAuthWithoutRS)
	}

	if *offline {
		fmt.Print(auth.FormatRSProbeText(rep))
		fmt.Print(auth.FormatFallthroughClassifierMatrix())
		fmt.Println("mode: offline (no network probes)")
		fmt.Println("classifier: Done* (offline fixtures); live jwt-auth-filter lab still required for production pin")
		fmt.Println("routes (example paths that must deny invalid bearer):")
		for _, r := range auth.RequiredMCPRoutes {
			flag := ""
			if r.OutsideAPIGlob {
				flag = " [outside /**/api/**]"
			}
			fmt.Printf("  - %s %s%s\n", r.ID, r.ExamplePath, flag)
		}
		return nil
	}

	// Online best-effort: bearer whoAmI when OIDC tokens present; invalid-bearer samples.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := discoveryHTTPClient(p)
	if err != nil {
		return err
	}
	jcBase := &jenkins.Client{URL: p.JenkinsURL, Client: client}

	if p.AuthMethod == profile.AuthMethodOIDC {
		oidc := auth.NewOIDCProvider(keyringStore(), client)
		sess, aerr := oidc.Authenticate(ctx, auth.ProfileFrom(p))
		if aerr != nil || strings.TrimSpace(sess.Secret) == "" {
			rep.Warnings = append(rep.Warnings,
				"no OIDC access token in keyring; run jenkins-mcp login --profile … --oidc for bearer whoAmI")
			// Still run invalid-bearer probes (do not need valid token).
		} else {
			jc := &jenkins.Client{
				URL:        p.JenkinsURL,
				Token:      sess.Secret,
				AuthScheme: jenkins.AuthSchemeBearer,
				Client:     client,
			}
			who, werr := diagnostics.ProbeBearerWhoAmI(ctx, jc)
			ok := werr == nil
			rep.OnlineBearerWhoAmIOK = &ok
			if werr != nil {
				rep.Warnings = append(rep.Warnings, "bearer whoAmI failed: "+apperr.ModelMessage(werr))
			} else {
				rep.Notes = append(rep.Notes, fmt.Sprintf("bearer whoAmI principal=%s", who.ID))
			}
			sess.Secret = ""
		}
	}

	online, oerr := diagnostics.ProbeInvalidBearerFallthrough(ctx, diagnostics.RSProbeOptions{
		Client: jcBase,
		HTTP:   client,
		// Prefer outside-api-glob examples + whoAmI for a tight sample.
		Paths: sampleRSProbePaths(),
	})
	if oerr != nil {
		rep.Warnings = append(rep.Warnings, "invalid-bearer probe error: "+apperr.ModelMessage(oerr))
	} else {
		ok := online.AllDenied
		rep.OnlineFallthroughOK = &ok
		if !online.AllDenied {
			rep.Warnings = append(rep.Warnings,
				fmt.Sprintf("invalid bearer fallthrough or inconclusive on %d path(s)",
					online.Fallthrough+online.Inconclusive))
		}
		fmt.Print(auth.FormatRSProbeText(rep))
		fmt.Print(diagnostics.FormatRSOnlineProbeText(online))
		return nil
	}

	fmt.Print(auth.FormatRSProbeText(rep))
	return nil
}

func sampleRSProbePaths() []string {
	// whoAmI + all outside-api-glob examples (acceptance: progressive/artifact/wfapi).
	out := []string{jenkins.WhoAmIPath}
	for _, r := range auth.RequiredOutsideAPIGlobRoutes() {
		out = append(out, r.ExamplePath)
	}
	// Cap total online fan-out.
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}
