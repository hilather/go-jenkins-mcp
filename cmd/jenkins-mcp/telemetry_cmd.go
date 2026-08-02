package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry/fleet"
)

// runTelemetry dispatches `jenkins-mcp telemetry <status|show>`.
func runTelemetry(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"telemetry subcommand required: status|show")
	}
	switch args[0] {
	case "status":
		return runTelemetryStatus(args[1:])
	case "show":
		return runTelemetryShow(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, telemetryUsage())
		return nil
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			"unknown telemetry subcommand (status|show)")
	}
}

func telemetryUsage() string {
	return `jenkins-mcp telemetry — privacy-preserving fleet health telemetry (MGR-002)

Usage:
  jenkins-mcp telemetry status [--json]
  jenkins-mcp telemetry show [--json]

status:
  Reports whether fleet telemetry is enabled, export URL configured (host only),
  queue depth, and the approved categories that would be exported. Secret-free.

show:
  Prints the last aggregate health snapshot (counters, auth method enum, error
  codes). Never includes logs, tokens, prompts, or job parameters.

Enable (disabled by default):
  JENKINS_MCP_TELEMETRY=1
  JENKINS_MCP_TELEMETRY_URL=https://telemetry.example.corp/v1/events   # optional export

See docs/security/fleet-telemetry.md for the privacy review notes.
`
}

func runTelemetryStatus(args []string) error {
	fs := flag.NewFlagSet("telemetry status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "Emit status as JSON")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	enabled := fleet.EnabledFromEnv()
	url := fleet.ExportURLFromEnv()
	urlSet := url != ""
	host := fleet.SafeURLHost(url)

	var q *fleet.Queue
	// Open queue only if the telemetry dir already exists (status must not create state).
	if dir := fleet.TelemetryDir(paths); dir != "" {
		if st, serr := os.Stat(dir); serr == nil && st.IsDir() {
			if qi, qerr := fleet.NewQueue(fleet.QueueConfig{Dir: dir}); qerr == nil {
				q = qi
			}
		}
	}
	// Never create installation_id from status when disabled; only report if present.
	installID := ""
	if b, rerr := os.ReadFile(fleet.InstallIDPath(paths)); rerr == nil {
		installID = strings.TrimSpace(string(b))
	}

	st := fleet.BuildStatus(q, installID, enabled, urlSet, host)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	printTelemetryStatus(st)
	return nil
}

func printTelemetryStatus(st fleet.Status) {
	fmt.Printf("enabled:               %v\n", st.Enabled)
	fmt.Printf("export_url_configured: %v\n", st.ExportURLConfigured)
	if st.ExportURLHost != "" {
		fmt.Printf("export_url_host:       %s\n", st.ExportURLHost)
	}
	fmt.Printf("queue_depth:           %d\n", st.QueueDepth)
	fmt.Printf("queue_bytes:           %d\n", st.QueueBytes)
	fmt.Printf("dropped:               %d\n", st.Dropped)
	if st.InstallationID != "" {
		fmt.Printf("installation_id:       %s\n", st.InstallationID)
	}
	if st.LastSnapshotAt != "" {
		fmt.Printf("last_snapshot_at:      %s\n", st.LastSnapshotAt)
	}
	fmt.Printf("schema_version:        %d\n", st.SchemaVersion)
	fmt.Printf("categories_exported:\n")
	for _, c := range st.CategoriesExported {
		fmt.Printf("  - %s\n", c)
	}
	fmt.Printf("categories_forbidden:\n")
	for _, c := range st.CategoriesForbidden {
		fmt.Printf("  - %s\n", c)
	}
	if st.Residual != "" {
		fmt.Printf("residual:              %s\n", st.Residual)
	}
}

func runTelemetryShow(args []string) error {
	fs := flag.NewFlagSet("telemetry show", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "Emit last snapshot as JSON")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	ev, err := fleet.LastSnapshotFromPaths(paths)
	if err != nil {
		if os.IsNotExist(err) {
			return apperr.New(apperr.CodeNotFound,
				"no telemetry snapshot yet (enable JENKINS_MCP_TELEMETRY=1 and run serve, or wait for first snapshot)")
		}
		return apperr.Wrap(apperr.CodeInternal, "read last telemetry snapshot", err)
	}
	// Re-validate before display (defense in depth).
	raw, err := fleet.MarshalEvent(*ev)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "marshal snapshot", err)
	}
	if err := fleet.ValidateExportJSON(raw); err != nil {
		return apperr.Wrap(apperr.CodeCorruptCache, "snapshot failed privacy validation", err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(ev)
	}
	printTelemetryShow(ev)
	return nil
}

func printTelemetryShow(ev *fleet.Event) {
	if ev == nil {
		fmt.Println("no snapshot")
		return
	}
	fmt.Printf("schema_version:   %d\n", ev.SchemaVersion)
	fmt.Printf("event_type:       %s\n", ev.EventType)
	fmt.Printf("installation_id:  %s\n", ev.InstallationID)
	if ev.ProfileIDHash != "" {
		fmt.Printf("profile_id_hash:  %s\n", ev.ProfileIDHash)
	}
	fmt.Printf("version:          %s\n", ev.Version)
	fmt.Printf("os/arch:          %s/%s\n", ev.OS, ev.Arch)
	fmt.Printf("auth_method:      %s\n", ev.AuthMethod)
	fmt.Printf("ts:               %s\n", ev.Timestamp)
	fmt.Printf("counters:\n")
	if len(ev.Counters) == 0 {
		fmt.Printf("  (none)\n")
	} else {
		for k, v := range ev.Counters {
			fmt.Printf("  %s: %d\n", k, v)
		}
	}
	if len(ev.ErrorCodes) > 0 {
		fmt.Printf("error_codes:\n")
		for k, v := range ev.ErrorCodes {
			fmt.Printf("  %s: %d\n", k, v)
		}
	}
}
