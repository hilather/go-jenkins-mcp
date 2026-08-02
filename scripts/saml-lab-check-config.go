//go:build ignore

// Lab helper: load SAML config + IdP trust PEM with product parsers.
// Usage (repo root): go run scripts/saml-lab-check-config.go path/to/saml-config.json
package main

import (
	"fmt"
	"os"

	"github.com/hilather/go-jenkins-mcp/internal/saml"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/saml-lab-check-config.go <saml-config.json>")
		os.Exit(2)
	}
	cfg, err := saml.LoadConfigFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL LoadConfigFile: %v\n", err)
		os.Exit(1)
	}
	if !cfg.Enabled {
		fmt.Fprintln(os.Stderr, "FAIL: expected enabled=true")
		os.Exit(1)
	}
	if _, err := saml.LoadTrustFromPEMFile(cfg.IdPCertificatePEMPath); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL LoadTrustFromPEMFile: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: product LoadConfigFile + LoadTrustFromPEMFile")
}
