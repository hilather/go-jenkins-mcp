// Command authlab runs disposable OAuth lab peers for HOST-012…HOST-015.
//
// Subcommands:
//
//	oidc   — mock OIDC IdP (discovery, JWKS, token mint)  — HOST-014
//	rs     — mock JWT resource server (Bearer validate)   — HOST-013
//	token  — mock AgentCore/token-exchange peer           — HOST-015
//
// Lab-only. Not for production. Never logs access tokens.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/authlab"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("authlab: ")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "keygen":
		runKeygen(args)
	case "oidc":
		runOIDC(args)
	case "rs":
		runRS(args)
	case "token":
		runToken(args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `authlab — disposable OAuth lab services (HOST-012…015)

Usage:
  authlab keygen [flags]   # one-shot: write shared lab RSA to keys-dir
  authlab oidc   [flags]
  authlab rs     [flags]
  authlab token  [flags]

Common env:
  LAB_KEYS_DIR     directory for shared private.pem / public.jwks.json (default /lab-keys)
  LAB_ISSUER       issuer URL embedded/validated (default http://127.0.0.1:18081)
  LAB_AUDIENCE     Jenkins audience (default jenkins-api)

Subcommand ports (defaults; loopback publish via compose):
  oidc  :18081
  rs    :18082
  token :18083

Lab-only keys. Not production Entra / jwt-auth-filter / AgentCore.
`)
}

func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	keysDir := fs.String("keys-dir", envOr("LAB_KEYS_DIR", "/lab-keys"), "shared lab keys directory")
	_ = fs.Parse(args)
	key, err := authlab.LoadOrGenerateKey(*keysDir)
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}
	// Do not print private key material — only confirm paths.
	log.Printf("lab keys ready under %s (kid=%s, lab-only)", *keysDir, key.Kid)
}

func runOIDC(args []string) {
	fs := flag.NewFlagSet("oidc", flag.ExitOnError)
	addr := fs.String("addr", envOr("LAB_OIDC_ADDR", ":18081"), "listen address")
	issuer := fs.String("issuer", envOr("LAB_ISSUER", "http://127.0.0.1:18081"), "issuer URL")
	keysDir := fs.String("keys-dir", envOr("LAB_KEYS_DIR", "/lab-keys"), "shared lab keys directory")
	aud := fs.String("audience", envOr("LAB_AUDIENCE", authlab.DefaultAudience), "default token audience")
	_ = fs.Parse(args)

	key, err := authlab.LoadOrGenerateKey(*keysDir)
	if err != nil {
		log.Fatalf("keys: %v", err)
	}
	iss, err := authlab.AbsoluteIssuerURL(*issuer)
	if err != nil {
		log.Fatalf("issuer: %v", err)
	}
	srv, err := authlab.NewOIDCServer(authlab.OIDCConfig{
		Issuer:          iss,
		Key:             key,
		DefaultAudience: *aud,
	})
	if err != nil {
		log.Fatalf("oidc: %v", err)
	}
	log.Printf("mock-oidc listening on %s issuer=%s (lab-only)", *addr, iss)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}

func runRS(args []string) {
	fs := flag.NewFlagSet("rs", flag.ExitOnError)
	addr := fs.String("addr", envOr("LAB_RS_ADDR", ":18082"), "listen address")
	issuer := fs.String("issuer", envOr("LAB_ISSUER", "http://127.0.0.1:18081"), "expected issuer")
	keysDir := fs.String("keys-dir", envOr("LAB_KEYS_DIR", "/lab-keys"), "shared lab keys directory")
	jwksURL := fs.String("jwks-url", envOr("LAB_JWKS_URL", ""), "optional JWKS URL (else load from keys-dir)")
	aud := fs.String("audience", envOr("LAB_AUDIENCE", authlab.DefaultAudience), "expected audience")
	_ = fs.Parse(args)

	iss, err := authlab.AbsoluteIssuerURL(*issuer)
	if err != nil {
		log.Fatalf("issuer: %v", err)
	}

	cfg := authlab.RSConfig{
		Issuer:   iss,
		Audience: *aud,
		JWKSURL:  strings.TrimSpace(*jwksURL),
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	if cfg.JWKSURL == "" {
		key, err := authlab.LoadOrGenerateKey(*keysDir)
		if err != nil {
			log.Fatalf("keys: %v", err)
		}
		doc, err := key.JWKS()
		if err != nil {
			log.Fatalf("jwks: %v", err)
		}
		cfg.JWKS = doc
	}

	srv, err := authlab.NewRSServer(cfg)
	if err != nil {
		log.Fatalf("rs: %v", err)
	}
	log.Printf("mock-rs listening on %s issuer=%s aud=%s (lab-only)", *addr, iss, *aud)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}

func runToken(args []string) {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	addr := fs.String("addr", envOr("LAB_TOKEN_ADDR", ":18083"), "listen address")
	issuer := fs.String("issuer", envOr("LAB_ISSUER", "http://127.0.0.1:18081"), "issuer for minted JWTs")
	keysDir := fs.String("keys-dir", envOr("LAB_KEYS_DIR", "/lab-keys"), "shared lab keys directory")
	aud := fs.String("audience", envOr("LAB_AUDIENCE", authlab.DefaultAudience), "default audience")
	_ = fs.Parse(args)

	key, err := authlab.LoadOrGenerateKey(*keysDir)
	if err != nil {
		log.Fatalf("keys: %v", err)
	}
	iss, err := authlab.AbsoluteIssuerURL(*issuer)
	if err != nil {
		log.Fatalf("issuer: %v", err)
	}
	srv, err := authlab.NewTokenServer(authlab.TokenConfig{
		Issuer:          iss,
		Key:             key,
		DefaultAudience: *aud,
	})
	if err != nil {
		log.Fatalf("token: %v", err)
	}
	log.Printf("mock-token listening on %s issuer=%s (lab-only)", *addr, iss)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
