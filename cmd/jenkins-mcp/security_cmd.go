package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
)

// runSecurity dispatches `jenkins-mcp security <self-check>`.
func runSecurity(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"security subcommand required: self-check")
	}
	switch args[0] {
	case "self-check":
		return runSecuritySelfCheck(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, securityUsage())
		return nil
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			"unknown security subcommand (self-check)")
	}
}

func securityUsage() string {
	return `jenkins-mcp security — offline security self-assessment (QA-005 MVP)

Usage:
  jenkins-mcp security self-check [--json] [--profile <id>]

Runs offline canaries (no network, no secret values in output):
  - redaction canary
  - support-bundle category plan canary
  - policy signature mode status
  - OIDC profile structural validation (when --profile is oidc_bearer)
  - fleet telemetry default-off
  - global read-only default / force overlay

This is a self-assessment. It does NOT replace independent security review
or penetration testing. See docs/security/security-review-checklist.md.
`
}

func runSecuritySelfCheck(args []string) error {
	fs := flag.NewFlagSet("security self-check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "Emit report as JSON")
	profileFlag := fs.String("profile", "", "Optional profile id for OIDC structural checks")
	if err := fs.Parse(reorderFlagArgs(args, valueTakingFlags(fs))); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}

	var p *profile.Profile
	if id := *profileFlag; id != "" {
		ps, err := profileStore()
		if err != nil {
			return err
		}
		loaded, err := ps.Load(id)
		if err != nil {
			return err
		}
		p = loaded
	}

	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	var polPtr *policy.LoadResult
	if polRes, polErr := policy.LoadFromEnviron(); polErr == nil {
		polPtr = &polRes
	} else {
		// Surface load failure inside the report via PolicyResult nil + item fail
		// by re-running Load inside diagnostics; pass nil so check re-loads.
		_ = polErr
		polPtr = nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{
		Profile:      p,
		Paths:        &paths,
		PolicyResult: polPtr,
		Version:      version,
		Commit:       commit,
	})
	if err != nil {
		return err
	}

	if *asJSON {
		if err := diagnostics.FormatSelfCheckJSON(os.Stdout, rep); err != nil {
			return err
		}
	} else {
		diagnostics.FormatSelfCheckText(os.Stdout, rep)
	}

	switch rep.Overall {
	case diagnostics.SelfCheckFail:
		return apperr.New(apperr.CodeInternal, "security self-check reported one or more failures")
	default:
		// warn/ok/info: exit 0 (warn is advisory for pilot unsigned policy).
		return nil
	}
}
