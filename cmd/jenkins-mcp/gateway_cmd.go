package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway/qualify"
)

// runGateway dispatches gateway operator commands (GWY-003 lite).
func runGateway(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway subcommand required: qualify")
	}
	switch args[0] {
	case "qualify":
		return runGatewayQualify(args[1:])
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unknown gateway subcommand %q (qualify)", args[0]))
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
