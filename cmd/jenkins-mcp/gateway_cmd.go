package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway/qualify"
)

// runGateway dispatches gateway operator commands (GWY-003 lite + HOST-009 vault).
func runGateway(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway subcommand required: qualify | residual-status | consent-residual | vault | vault-put | vault-delete")
	}
	switch args[0] {
	case "qualify":
		return runGatewayQualify(args[1:])
	case "residual-status":
		return runGatewayResidualStatus(args[1:])
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
			fmt.Sprintf("unknown gateway subcommand %q (qualify|residual-status|consent-residual|vault|vault-put|vault-delete)", args[0]))
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

// runGatewayResidualStatus prints one secret-free JSON snapshot combining mode
// matrix residual (A/B/C), multi-user / HA / multi-pod residual, progressive
// consent residual, subject-rate knobs, and principal_cache entry count.
// Env/static only — no Obtain, vault open, or browser. Never tokens or subjects.
// Shared assembly: diagnostics.BuildGatewayResidualStatus (admin BFF parity).
//
//	jenkins-mcp gateway residual-status
func runGatewayResidualStatus(args []string) error {
	fs := flag.NewFlagSet("gateway residual-status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	out := buildGatewayResidualStatus(os.Getenv)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to encode residual-status", err)
	}
	return nil
}

// buildGatewayResidualStatus is a thin CLI wrapper over the shared residual
// snapshot (diagnostics.BuildGatewayResidualStatus). Kept for gateway_cmd tests.
func buildGatewayResidualStatus(getenv func(string) string) map[string]any {
	return diagnostics.BuildGatewayResidualStatus(getenv)
}

// runGatewayConsentResidual prints Mode C progressive consent residual honesty
// (OAUTH-010 / GWY-001). Secret-free JSON: browser 3LO not automated; metadata
// path Done*; process-local consent metadata store Done* (optional file under
// XDG data for crash recovery of metadata only); never tokens. Does not perform
// Obtain or open a browser. Prefer residual-status for the unified operator snapshot.
//
// When a consent metadata file is present (default XDG path or
// JENKINS_MCP_CONSENT_STORE_PATH), lists last consent session metadata via
// secret-free StatusMap entries (session_id, authorization_host, timestamps —
// never access/refresh tokens).
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

	// List last consent metadata from process-local / file-backed store when
	// present (metadata only; secret-free StatusMap rows). Residual honesty:
	// not multi-replica shared store; browser 3LO not automated.
	store, storeErr := gateway.OpenConsentSessionStoreForCLI(os.Getenv)
	if storeErr != nil {
		out["consent_store_error"] = "consent metadata store unavailable (see logs; never embeds secrets)"
	} else if store != nil {
		out["consent_store"] = store.StatusMap()
		recs := store.List()
		rows := make([]map[string]any, 0, len(recs))
		for _, rec := range recs {
			rows = append(rows, rec.StatusMap())
		}
		out["consent_sessions"] = rows
		out["consent_sessions_count"] = len(rows)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to encode consent residual", err)
	}
	return nil
}
