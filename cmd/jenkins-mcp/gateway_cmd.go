package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway/qualify"
)

// runGateway dispatches gateway operator commands (GWY-003 lite + HOST-009 vault).
func runGateway(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway subcommand required: qualify | consent-residual | vault | vault-put | vault-delete")
	}
	switch args[0] {
	case "qualify":
		return runGatewayQualify(args[1:])
	case "consent-residual":
		return runGatewayConsentResidual(args[1:])
	case "vault":
		return runGatewayVault(args[1:])
	case "vault-put":
		// Legacy alias for `gateway vault put` (HOST-009).
		return runGatewayVaultPut(args[1:])
	case "vault-delete":
		// Legacy alias for `gateway vault delete` (HOST-009).
		return runGatewayVaultDelete(args[1:])
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unknown gateway subcommand %q (qualify|consent-residual|vault|vault-put|vault-delete)", args[0]))
	}
}

// runGatewayQualify runs the offline security/performance qualification suite.
//
//	jenkins-mcp gateway qualify --offline
//
// Prints a JSON summary with no secrets. Exit 0 when all cases pass; 1 on failure.
func runGatewayQualify(args []string) error {
	fs := flag.NewFlagSet("gateway qualify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	offline := fs.Bool("offline", false, "Run in-process mock suite (no live AgentCore/Entra network)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"offline": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if !*offline {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway qualify requires --offline (live AgentCore pin is residual; see docs/gateway/qualification.md)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sum := qualify.RunOffline(ctx)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sum); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to encode qualify summary", err)
	}
	if !sum.OK {
		// Non-zero exit via fatal in main; return typed error for consistency.
		return apperr.New(apperr.CodeInternal,
			fmt.Sprintf("gateway offline qualify failed: %d passed, %d failed", sum.Passed, sum.Failed))
	}
	return nil
}

// runGatewayConsentResidual prints Mode C progressive consent residual honesty
// (OAUTH-010 / GWY-001). Secret-free JSON: browser 3LO not automated; metadata
// path Done*; never tokens. Env-only — does not perform Obtain or open a browser.
//
//	jenkins-mcp gateway consent-residual
func runGatewayConsentResidual(args []string) error {
	fs := flag.NewFlagSet("gateway consent-residual", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	pc := gateway.NewProgressiveConsentResidual()
	// Optional Mode C enablement from env (honesty only; no secrets).
	modeC := false
	if mx, err := gateway.ModeMatrixFromEnviron(os.Getenv); err == nil {
		for _, m := range mx.Enabled {
			if m == gateway.CredentialModeAgentCore {
				modeC = true
				break
			}
		}
	} else if gateway.CredentialModeFromEnviron(os.Getenv) == gateway.CredentialModeAgentCore {
		modeC = true
	}
	out := map[string]any{
		"progressive_consent": pc.StatusMap(),
		"mode_c_enabled":      modeC,
		"doc":                 "docs/gateway/README.md § progressive consent residual",
	}
	if modeC {
		out["mode_matrix_residual"] = gateway.ModeMatrixResidualNote(
			gateway.CredentialModeAgentCore, []gateway.CredentialMode{gateway.CredentialModeAgentCore})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to encode consent residual", err)
	}
	return nil
}
