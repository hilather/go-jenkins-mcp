package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// runRedact dispatches `jenkins-mcp redact <validate-patterns>`.
func runRedact(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"redact subcommand required: validate-patterns")
	}
	switch args[0] {
	case "validate-patterns":
		return runRedactValidatePatterns(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, redactUsage())
		return nil
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			"unknown redact subcommand (validate-patterns)")
	}
}

func redactUsage() string {
	return `jenkins-mcp redact — enterprise redaction pattern tools (SEC-002)

Usage:
  jenkins-mcp redact validate-patterns --file PATH [--json]

validate-patterns:
  Loads and compiles a JSON enterprise pattern file without starting serve.
  Format: [{"name":"corp_id","expr":"..."}]
  Fail closed on invalid JSON, oversized file, or invalid regexp.
  Prints category names and count only — never match samples or secrets.

Serve loads the same format from env JENKINS_MCP_REDACT_PATTERNS_FILE
(unset = no enterprise patterns). Invalid file fails serve start.
`
}

func runRedactValidatePatterns(args []string) error {
	fs := flag.NewFlagSet("redact validate-patterns", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	file := fs.String("file", "", "Enterprise redact patterns JSON path (required)")
	asJSON := fs.Bool("json", false, "Emit machine-readable JSON")
	if err := fs.Parse(reorderFlagArgs(args, valueTakingFlags(fs))); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	path := strings.TrimSpace(*file)
	if path == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--file is required")
	}

	n, names, err := redact.ValidateEnterprisePatternsFile(path)
	if err != nil {
		if *asJSON {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
				"schema": "jenkins-mcp.redact.validate_patterns.v1",
				"ok":     false,
				"error":  redact.Secrets(err.Error()),
			})
		}
		return apperr.Wrap(apperr.CodeInvalidArgument, "enterprise redact patterns invalid", err)
	}

	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"schema": "jenkins-mcp.redact.validate_patterns.v1",
			"ok":     true,
			"count":  n,
			"names":  names,
		})
	}
	fmt.Fprintf(os.Stdout, "ok: %d enterprise redact pattern(s) compiled\n", n)
	for _, name := range names {
		fmt.Fprintf(os.Stdout, "  - %s\n", name)
	}
	return nil
}

// applyServeEnterpriseRedactPatterns loads optional enterprise patterns for
// serve (SEC-002 Wave 27). Env JENKINS_MCP_REDACT_PATTERNS_FILE:
//
//	unset/empty → no enterprise patterns (default)
//	valid file  → compile + SetEnterprisePatterns
//	invalid     → error (fail closed; do not start serve)
//
// Returns installed pattern count. Does not log expressions, matches, or secrets.
func applyServeEnterpriseRedactPatterns() (int, error) {
	n, err := redact.ApplyEnterprisePatternsFromEnviron()
	if err != nil {
		return 0, apperr.Wrap(apperr.CodeInvalidArgument,
			"enterprise redact patterns (JENKINS_MCP_REDACT_PATTERNS_FILE)", err)
	}
	return n, nil
}
