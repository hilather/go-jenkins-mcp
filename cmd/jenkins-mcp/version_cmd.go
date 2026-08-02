package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// versionInfo is secret-free build metadata for `jenkins-mcp version --json` (UPD-001).
type versionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"buildTime"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// buildVersionInfo returns embedded + runtime version fields (no secrets).
func buildVersionInfo() versionInfo {
	return versionInfo{
		Version:   version,
		Commit:    commit,
		BuildTime: buildTime,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// runVersion handles `jenkins-mcp version` and `version --json`.
func runVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "Emit version metadata as JSON")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	info := buildVersionInfo()
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(info); err != nil {
			return apperr.Wrap(apperr.CodeInternal, "encode version JSON", err)
		}
		return nil
	}
	fmt.Printf("jenkins-mcp %s commit=%s built=%s go=%s %s/%s\n",
		info.Version, info.Commit, info.BuildTime, info.GoVersion, info.OS, info.Arch)
	return nil
}
