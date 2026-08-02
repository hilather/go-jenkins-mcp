package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

// Default env name for Mode A personal API token when provisioning via CLI.
// Token value must never appear on argv, in logs, or in command stdout.
const envGatewayVaultToken = "JENKINS_MCP_GATEWAY_VAULT_TOKEN"

// runGatewayVault dispatches `jenkins-mcp gateway vault <subcommand>` (HOST-009).
//
//	put|set     provision or rotate a personal API token for a subject key
//	delete|revoke  remove a subject key
//	list        subject keys only (no usernames/tokens)
//	status|exists  non-secret presence check for a subject key
func runGatewayVault(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway vault subcommand required: put|set|delete|revoke|list|status|exists")
	}
	switch args[0] {
	case "put", "set":
		return runGatewayVaultPut(args[1:])
	case "delete", "revoke":
		return runGatewayVaultDelete(args[1:])
	case "list":
		return runGatewayVaultList(args[1:])
	case "status", "exists":
		return runGatewayVaultStatus(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, gatewayVaultUsage())
		return nil
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unknown gateway vault subcommand %q (put|set|delete|revoke|list|status|exists)", args[0]))
	}
}

func gatewayVaultUsage() string {
	return `jenkins-mcp gateway vault — Mode A personal API token vault (HOST-009)

Usage:
  jenkins-mcp gateway vault put|set \
    (--subject KEY | --tenant T --subject-id S [--profile P]) \
    --user JENKINS_USER \
    [--token-env VAR] [--vault-path PATH]
  jenkins-mcp gateway vault delete|revoke \
    (--subject KEY | --tenant T --subject-id S [--profile P]) \
    [--vault-path PATH]
  jenkins-mcp gateway vault list [--vault-path PATH]
  jenkins-mcp gateway vault status|exists \
    (--subject KEY | --tenant T --subject-id S [--profile P]) \
    [--vault-path PATH]

Token input (put/set only):
  Prefer environment — never put the token value on argv (process list / history).
  1) --token-env VAR   read token from named env var (e.g. MY_TOKEN)
  2) else              read from ` + envGatewayVaultToken + `
  Token is never echoed in stdout, stderr messages, or logs.

Subject key:
  Stable vault key is tenant|subject|profile (gateway.SubjectKey).
  Pass --subject KEY directly, or compose with --tenant / --subject-id / --profile.
  Never derive subject keys from MCP tool arguments.

Path:
  --vault-path PATH, or $JENKINS_MCP_GATEWAY_VAULT_PATH, or
  $XDG_DATA_HOME/jenkins-mcp/gateway/apitoken_vault.json

list prints subject keys only (one per line). status/exists prints exists=true|false.
Admin console vault write remains residual (secret-free status only).
`
}

// runGatewayVaultPut provisions or rotates a Mode A personal API token (HOST-009).
//
//	jenkins-mcp gateway vault put --subject KEY --user U
//	jenkins-mcp gateway vault-put …   (legacy alias)
//
// Token is read from --token-env VAR or JENKINS_MCP_GATEWAY_VAULT_TOKEN only —
// never from argv as a raw secret value.
func runGatewayVaultPut(args []string) error {
	fs := flag.NewFlagSet("gateway vault put", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	subject := fs.String("subject", "", "Stable subject key (tenant|subject|profile)")
	tenant := fs.String("tenant", "", "Tenant part when composing subject key")
	subjectID := fs.String("subject-id", "", "Subject (user) id when composing subject key")
	profile := fs.String("profile", "", "Profile id when composing subject key")
	user := fs.String("user", "", "Jenkins username for Basic auth")
	tokenEnv := fs.String("token-env", "", "Env var name holding the personal API token (not the token value)")
	vaultPath := fs.String("vault-path", "", "Vault file path (default: $JENKINS_MCP_GATEWAY_VAULT_PATH or XDG data)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"subject":    true,
		"tenant":     true,
		"subject-id": true,
		"profile":    true,
		"user":       true,
		"token-env":  true,
		"vault-path": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}

	sub, err := resolveVaultSubjectKey(*subject, *tenant, *subjectID, *profile)
	if err != nil {
		return err
	}
	u := strings.TrimSpace(*user)
	if u == "" {
		return apperr.New(apperr.CodeInvalidArgument, "gateway vault put requires --user")
	}
	tok, err := resolveVaultToken(*tokenEnv)
	if err != nil {
		return err
	}

	path := resolveVaultFilePath(*vaultPath)
	vault, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		return err
	}
	if err := vault.Put(context.Background(), sub, u, tok); err != nil {
		// Never include token in error surfaces (apperr redacts; still avoid embedding).
		return err
	}
	// Secret-free confirmation (subject key + username are not the API token).
	fmt.Printf("vault put ok subject=%s user=%s path=%s\n", sub, u, path)
	return nil
}

// runGatewayVaultDelete revokes a Mode A vault entry (HOST-009).
//
//	jenkins-mcp gateway vault delete --subject KEY
//	jenkins-mcp gateway vault-delete …   (legacy alias)
func runGatewayVaultDelete(args []string) error {
	fs := flag.NewFlagSet("gateway vault delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	subject := fs.String("subject", "", "Stable subject key to delete")
	tenant := fs.String("tenant", "", "Tenant part when composing subject key")
	subjectID := fs.String("subject-id", "", "Subject (user) id when composing subject key")
	profile := fs.String("profile", "", "Profile id when composing subject key")
	vaultPath := fs.String("vault-path", "", "Vault file path (default: $JENKINS_MCP_GATEWAY_VAULT_PATH or XDG data)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"subject":    true,
		"tenant":     true,
		"subject-id": true,
		"profile":    true,
		"vault-path": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	sub, err := resolveVaultSubjectKey(*subject, *tenant, *subjectID, *profile)
	if err != nil {
		return err
	}
	path := resolveVaultFilePath(*vaultPath)
	vault, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		return err
	}
	if err := vault.Delete(context.Background(), sub); err != nil {
		return err
	}
	fmt.Printf("vault delete ok subject=%s path=%s\n", sub, path)
	return nil
}

// runGatewayVaultList prints subject keys only (no usernames/tokens).
func runGatewayVaultList(args []string) error {
	fs := flag.NewFlagSet("gateway vault list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	vaultPath := fs.String("vault-path", "", "Vault file path (default: $JENKINS_MCP_GATEWAY_VAULT_PATH or XDG data)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"vault-path": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	path := resolveVaultFilePath(*vaultPath)
	vault, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		return err
	}
	keys, err := vault.ListSubjectKeys(context.Background())
	if err != nil {
		return err
	}
	for _, k := range keys {
		// Keys only — never usernames or tokens.
		fmt.Println(k)
	}
	return nil
}

// runGatewayVaultStatus reports non-secret presence of a subject key.
//
//	jenkins-mcp gateway vault status --subject KEY
//	jenkins-mcp gateway vault exists --subject KEY
func runGatewayVaultStatus(args []string) error {
	fs := flag.NewFlagSet("gateway vault status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	subject := fs.String("subject", "", "Stable subject key to check")
	tenant := fs.String("tenant", "", "Tenant part when composing subject key")
	subjectID := fs.String("subject-id", "", "Subject (user) id when composing subject key")
	profile := fs.String("profile", "", "Profile id when composing subject key")
	vaultPath := fs.String("vault-path", "", "Vault file path (default: $JENKINS_MCP_GATEWAY_VAULT_PATH or XDG data)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"subject":    true,
		"tenant":     true,
		"subject-id": true,
		"profile":    true,
		"vault-path": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	sub, err := resolveVaultSubjectKey(*subject, *tenant, *subjectID, *profile)
	if err != nil {
		return err
	}
	path := resolveVaultFilePath(*vaultPath)
	vault, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		return err
	}
	// Get returns username+token when present — discard secrets; only use ok.
	_, _, ok, err := vault.Get(context.Background(), sub)
	if err != nil {
		return err
	}
	// Secret-free: subject key + exists + path + file presence. No user/token.
	fmt.Printf("subject=%s exists=%t vault_file=%t path=%s\n",
		sub, ok, vault.FileExists(), path)
	return nil
}

// resolveVaultFilePath picks --vault-path or env/XDG default.
func resolveVaultFilePath(flagPath string) string {
	path := strings.TrimSpace(flagPath)
	if path == "" {
		path = gateway.VaultPathFromEnviron(nil)
	}
	return path
}

// resolveVaultSubjectKey accepts an explicit key or composes tenant|subject|profile.
func resolveVaultSubjectKey(subject, tenant, subjectID, profile string) (string, error) {
	sub := strings.TrimSpace(subject)
	if sub != "" {
		if err := gateway.ValidateSubjectKey(sub); err != nil {
			return "", err
		}
		return sub, nil
	}
	// Compose from parts when --subject omitted.
	composed := gateway.SubjectKeyParts(tenant, subjectID, profile)
	if composed == "" {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"gateway vault requires --subject KEY or --subject-id (optionally --tenant/--profile)")
	}
	if err := gateway.ValidateSubjectKey(composed); err != nil {
		return "", err
	}
	return composed, nil
}

// resolveVaultToken reads the personal API token from an environment variable.
// Prefer --token-env NAME; otherwise JENKINS_MCP_GATEWAY_VAULT_TOKEN.
// Rejects values that look like "NAME=secret" on the flag (token-on-argv footgun).
func resolveVaultToken(tokenEnvFlag string) (string, error) {
	envName := strings.TrimSpace(tokenEnvFlag)
	if envName == "" {
		envName = envGatewayVaultToken
	}
	// Reject accidental token-in-argv: env name must look like a variable name.
	if strings.Contains(envName, "=") || strings.ContainsAny(envName, " \t\n") {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"gateway vault --token-env must be an environment variable name only (not NAME=value)")
	}
	tok := strings.TrimSpace(os.Getenv(envName))
	if tok == "" {
		if envName == envGatewayVaultToken {
			return "", apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("gateway vault put requires token via $%s or --token-env VAR (token must not appear on argv)",
					envGatewayVaultToken))
		}
		return "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("environment variable %s is empty or unset", envName))
	}
	return tok, nil
}
