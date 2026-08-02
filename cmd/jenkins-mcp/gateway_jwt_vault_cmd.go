package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// Default env name for Mode B Jenkins-audience JWT when provisioning via CLI.
// Token value must never appear on argv, in logs, or in command stdout.
const envGatewayJWTVaultToken = "JENKINS_MCP_GATEWAY_JWT_VAULT_TOKEN"

// runGatewayJWTVault dispatches `jenkins-mcp gateway jwt-vault <subcommand>` (HOST-010).
//
// put|set     store/replace a Jenkins-audience access token for a subject key
// delete|revoke  remove a subject key
// list        subject keys only (no tokens)
// status|exists  non-secret presence check for a subject key
//
// Never stores ID tokens (JWTVault Put rejects id_token shape). Live
// jwt-auth-filter production pin remains OAUTH-009 residual.
func runGatewayJWTVault(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway jwt-vault subcommand required: put|set|delete|revoke|list|status|exists")
	}
	switch args[0] {
	case "put", "set":
		return runGatewayJWTVaultPut(args[1:])
	case "delete", "revoke":
		return runGatewayJWTVaultDelete(args[1:])
	case "list":
		return runGatewayJWTVaultList(args[1:])
	case "status", "exists":
		return runGatewayJWTVaultStatus(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, gatewayJWTVaultUsage())
		return nil
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unknown gateway jwt-vault subcommand %q (put|set|delete|revoke|list|status|exists)", args[0]))
	}
}

func gatewayJWTVaultUsage() string {
	return `jenkins-mcp gateway jwt-vault — Mode B Jenkins-audience JWT vault (HOST-010)

Usage:
  jenkins-mcp gateway jwt-vault put|set \
    (--subject KEY | --tenant T --subject-id S [--profile P]) \
    [--token-env VAR] [--vault-path PATH]
  jenkins-mcp gateway jwt-vault delete|revoke \
    (--subject KEY | --tenant T --subject-id S [--profile P]) \
    [--vault-path PATH]
  jenkins-mcp gateway jwt-vault list [--vault-path PATH]
  jenkins-mcp gateway jwt-vault status|exists \
    (--subject KEY | --tenant T --subject-id S [--profile P]) \
    [--vault-path PATH]

Token input (put/set only):
  Prefer environment — never put the JWT value on argv (process list / history).
  1) --token-env VAR   read access token from named env var
  2) else              read from ` + envGatewayJWTVaultToken + `
  Access tokens only — ID tokens are rejected. Token is never echoed.

Subject key:
  Stable vault key is tenant|subject|profile (gateway.SubjectKey).
  Pass --subject KEY directly, or compose with --tenant / --subject-id / --profile.

Path:
  --vault-path PATH, or $JENKINS_MCP_GATEWAY_JWT_VAULT_PATH, or
  $XDG_DATA_HOME/jenkins-mcp/gateway/jwt_vault.json

list prints subject keys only (one per line). status/exists prints exists=true|false.
Mode B Obtain uses this vault when JENKINS_MCP_GATEWAY_CREDENTIAL_MODE=jwt_rs_bearer.
Live jwt-auth-filter / Entra production pin remains OAUTH-009 residual (mock lab OK).
`
}

// runGatewayJWTVaultPut stores a Mode B Jenkins-audience access token (HOST-010).
func runGatewayJWTVaultPut(args []string) error {
	fs := flag.NewFlagSet("gateway jwt-vault put", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	subject := fs.String("subject", "", "Stable subject key (tenant|subject|profile)")
	tenant := fs.String("tenant", "", "Tenant part when composing subject key")
	subjectID := fs.String("subject-id", "", "Subject (user) id when composing subject key")
	profile := fs.String("profile", "", "Profile id when composing subject key")
	tokenEnv := fs.String("token-env", "", "Env var name holding the access token (not the token value)")
	vaultPath := fs.String("vault-path", "", "JWT vault file path (default: $JENKINS_MCP_GATEWAY_JWT_VAULT_PATH or XDG data)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"subject":    true,
		"tenant":     true,
		"subject-id": true,
		"profile":    true,
		"token-env":  true,
		"vault-path": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}

	sub, err := resolveVaultSubjectKey(*subject, *tenant, *subjectID, *profile)
	if err != nil {
		return err
	}
	tok, err := resolveJWTVaultToken(*tokenEnv)
	if err != nil {
		return err
	}

	path := resolveJWTVaultFilePath(*vaultPath)
	vault, err := gateway.NewFileJWTVault(path)
	if err != nil {
		return err
	}
	if err := vault.Put(context.Background(), sub, tok); err != nil {
		return err
	}
	// Secret-free confirmation — never print the token.
	fmt.Printf("jwt-vault put ok subject=%s path=%s\n", sub, path)
	return nil
}

// runGatewayJWTVaultDelete revokes a Mode B vault entry (HOST-010).
func runGatewayJWTVaultDelete(args []string) error {
	fs := flag.NewFlagSet("gateway jwt-vault delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	subject := fs.String("subject", "", "Stable subject key to delete")
	tenant := fs.String("tenant", "", "Tenant part when composing subject key")
	subjectID := fs.String("subject-id", "", "Subject (user) id when composing subject key")
	profile := fs.String("profile", "", "Profile id when composing subject key")
	vaultPath := fs.String("vault-path", "", "JWT vault file path")
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
	path := resolveJWTVaultFilePath(*vaultPath)
	vault, err := gateway.NewFileJWTVault(path)
	if err != nil {
		return err
	}
	if err := vault.Delete(context.Background(), sub); err != nil {
		return err
	}
	fmt.Printf("jwt-vault delete ok subject=%s path=%s\n", sub, path)
	return nil
}

// runGatewayJWTVaultList prints subject keys only (no tokens).
func runGatewayJWTVaultList(args []string) error {
	fs := flag.NewFlagSet("gateway jwt-vault list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	vaultPath := fs.String("vault-path", "", "JWT vault file path")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"vault-path": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	path := resolveJWTVaultFilePath(*vaultPath)
	vault, err := gateway.NewFileJWTVault(path)
	if err != nil {
		return err
	}
	keys, err := vault.ListSubjectKeys(context.Background())
	if err != nil {
		return err
	}
	for _, k := range keys {
		fmt.Println(k)
	}
	return nil
}

// runGatewayJWTVaultStatus reports non-secret presence of a subject key.
func runGatewayJWTVaultStatus(args []string) error {
	fs := flag.NewFlagSet("gateway jwt-vault status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	subject := fs.String("subject", "", "Stable subject key to check")
	tenant := fs.String("tenant", "", "Tenant part when composing subject key")
	subjectID := fs.String("subject-id", "", "Subject (user) id when composing subject key")
	profile := fs.String("profile", "", "Profile id when composing subject key")
	vaultPath := fs.String("vault-path", "", "JWT vault file path")
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
	path := resolveJWTVaultFilePath(*vaultPath)
	vault, err := gateway.NewFileJWTVault(path)
	if err != nil {
		return err
	}
	// Discard token material — only use ok.
	_, ok, err := vault.Get(context.Background(), sub)
	if err != nil {
		return err
	}
	fmt.Printf("subject=%s exists=%t vault_file=%t path=%s\n",
		sub, ok, vault.FileExists(), path)
	return nil
}

func resolveJWTVaultFilePath(flagPath string) string {
	path := strings.TrimSpace(flagPath)
	if path == "" {
		path = gateway.JWTVaultPathFromEnviron(nil)
	}
	return path
}

// resolveJWTVaultToken reads the access token from an environment variable.
// Prefer --token-env NAME; otherwise JENKINS_MCP_GATEWAY_JWT_VAULT_TOKEN.
func resolveJWTVaultToken(tokenEnvFlag string) (string, error) {
	envName := strings.TrimSpace(tokenEnvFlag)
	if envName == "" {
		envName = envGatewayJWTVaultToken
	}
	if strings.Contains(envName, "=") || strings.ContainsAny(envName, " \t\n") {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"gateway jwt-vault --token-env must be an environment variable name only (not NAME=value)")
	}
	tok := strings.TrimSpace(os.Getenv(envName))
	if tok == "" {
		if envName == envGatewayJWTVaultToken {
			return "", apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("gateway jwt-vault put requires token via $%s or --token-env VAR (token must not appear on argv)",
					envGatewayJWTVaultToken))
		}
		return "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("environment variable %s is empty or unset", envName))
	}
	return tok, nil
}
