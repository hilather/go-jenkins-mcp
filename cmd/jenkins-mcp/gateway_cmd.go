package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway/qualify"
)

// runGateway dispatches gateway operator commands (GWY-003 lite + HOST-009 vault).
func runGateway(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway subcommand required: qualify | vault-put | vault-delete")
	}
	switch args[0] {
	case "qualify":
		return runGatewayQualify(args[1:])
	case "vault-put":
		return runGatewayVaultPut(args[1:])
	case "vault-delete":
		return runGatewayVaultDelete(args[1:])
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unknown gateway subcommand %q (qualify|vault-put|vault-delete)", args[0]))
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

// runGatewayVaultPut provisions a Mode A personal API token (HOST-009).
//
//	jenkins-mcp gateway vault-put --subject KEY --user U --token-env VAR
//
// Token is read from the named environment variable only — never from argv
// (secrets must not appear in process lists / shell history).
//
// Optional: --vault-path PATH (default: XDG data gateway vault file).
// subject KEY is the stable vault key (tenant|subject|profile or operator key).
func runGatewayVaultPut(args []string) error {
	fs := flag.NewFlagSet("gateway vault-put", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	subject := fs.String("subject", "", "Stable subject key (tenant|subject|profile); never a tool arg identity override")
	user := fs.String("user", "", "Jenkins username for Basic auth")
	tokenEnv := fs.String("token-env", "", "Name of environment variable holding the personal API token (not the token value)")
	vaultPath := fs.String("vault-path", "", "Vault file path (default: $JENKINS_MCP_GATEWAY_VAULT_PATH or XDG data)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"subject":    true,
		"user":       true,
		"token-env":  true,
		"vault-path": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	sub := strings.TrimSpace(*subject)
	if sub == "" {
		return apperr.New(apperr.CodeInvalidArgument, "gateway vault-put requires --subject")
	}
	u := strings.TrimSpace(*user)
	if u == "" {
		return apperr.New(apperr.CodeInvalidArgument, "gateway vault-put requires --user")
	}
	envName := strings.TrimSpace(*tokenEnv)
	if envName == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway vault-put requires --token-env (token value must not appear on argv)")
	}
	// Reject accidental token-in-argv: env name must look like a variable name.
	if strings.Contains(envName, "=") || strings.ContainsAny(envName, " \t\n") {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway vault-put --token-env must be an environment variable name only")
	}
	tok := strings.TrimSpace(os.Getenv(envName))
	if tok == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("environment variable %s is empty or unset", envName))
	}

	path := strings.TrimSpace(*vaultPath)
	if path == "" {
		path = gateway.VaultPathFromEnviron(nil)
	}
	vault, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		return err
	}
	if err := vault.Put(context.Background(), sub, u, tok); err != nil {
		// Never include token in error surfaces (apperr redacts; still avoid embedding).
		return err
	}
	// Secret-free confirmation.
	fmt.Printf("vault-put ok subject=%s user=%s path=%s\n", sub, u, path)
	return nil
}

// runGatewayVaultDelete revokes a Mode A vault entry (HOST-009).
//
//	jenkins-mcp gateway vault-delete --subject KEY [--vault-path PATH]
func runGatewayVaultDelete(args []string) error {
	fs := flag.NewFlagSet("gateway vault-delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	subject := fs.String("subject", "", "Stable subject key to delete")
	vaultPath := fs.String("vault-path", "", "Vault file path (default: $JENKINS_MCP_GATEWAY_VAULT_PATH or XDG data)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"subject":    true,
		"vault-path": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	sub := strings.TrimSpace(*subject)
	if sub == "" {
		return apperr.New(apperr.CodeInvalidArgument, "gateway vault-delete requires --subject")
	}
	path := strings.TrimSpace(*vaultPath)
	if path == "" {
		path = gateway.VaultPathFromEnviron(nil)
	}
	vault, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		return err
	}
	if err := vault.Delete(context.Background(), sub); err != nil {
		return err
	}
	fmt.Printf("vault-delete ok subject=%s path=%s\n", sub, path)
	return nil
}
