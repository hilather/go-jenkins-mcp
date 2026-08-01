package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/update"
)

// EnvUpdateManifestURL is the optional HTTPS URL for a release manifest (UPD-001).
// Empty (default) ⇒ update-check does not open a network connection.
const EnvUpdateManifestURL = "JENKINS_MCP_UPDATE_MANIFEST_URL"

// runUpdate dispatches `jenkins-mcp update <verify-manifest|download|show-lkg|verify-lkg>`.
func runUpdate(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"update subcommand required: verify-manifest|download|show-lkg|verify-lkg")
	}
	switch args[0] {
	case "verify-manifest":
		return runUpdateVerifyManifest(args[1:])
	case "download":
		return runUpdateDownload(args[1:])
	case "show-lkg":
		return runUpdateShowLKG(args[1:])
	case "verify-lkg":
		return runUpdateVerifyLKG(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, updateUsage())
		return nil
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			"unknown update subcommand (verify-manifest|download|show-lkg|verify-lkg); see also update-check")
	}
}

func updateUsage() string {
	return `jenkins-mcp update — signed release metadata and optional download (UPD-001)

Usage:
  jenkins-mcp update-check [--channel stable] [--json]
  jenkins-mcp update verify-manifest --file PATH [--keys PATH] [--json]
  jenkins-mcp update download --channel stable [--outdir DIR] [--json]
  jenkins-mcp update show-lkg [--json]
  jenkins-mcp update verify-lkg [--json] [--file PATH]

Environment:
  JENKINS_MCP_UPDATE_MANIFEST_URL       HTTPS JSON manifest URL (update-check / download)
  JENKINS_MCP_UPDATE_TRUSTED_KEYS      File or dir of Ed25519 public keys
                                        (default: $XDG_CONFIG_HOME/jenkins-mcp/update/trusted_keys/)
  JENKINS_MCP_UPDATE_ALLOW_UNSIGNED    =1 allows unsigned manifests only when no keys configured
                                        (signature_state=unverified_pilot)
  JENKINS_MCP_UPDATE_ALLOW_DOWNGRADE   =1 allows download of older versions (default: equal/newer only)
  JENKINS_MCP_UPDATE_LKG_PATH          Override last-known-good JSON path
                                        (default: $XDG_DATA_HOME/jenkins-mcp/update/last_known_good.json)

Prefer enterprise package managers for install/rollback. download never executes
or installs the binary — it only verifies sha256, writes LKG, and prints next steps.
verify-lkg re-hashes the staged artifact against LKG sha256 (fail closed on missing
file or mismatch). Default search: $XDG_DATA_HOME/jenkins-mcp/update/<path_basename>;
use --file when the artifact was downloaded to another outdir.
`
}

// updateCheckReport is the secret-free CLI report for update-check.
type updateCheckReport struct {
	Schema         string `json:"schema"`
	Channel        string `json:"channel"`
	CurrentVersion string `json:"current_version"`
	CurrentCommit  string `json:"current_commit"`
	ManifestURLSet bool   `json:"manifest_url_set"`
	NetworkSkipped bool   `json:"network_skipped,omitempty"`
	NewerAvailable bool   `json:"newer_available"`
	LatestVersion  string `json:"latest_version,omitempty"`
	LatestCommit   string `json:"latest_commit,omitempty"`
	ChangelogURL   string `json:"changelog_url,omitempty"`
	PublishedAt    string `json:"published_at,omitempty"`
	CompareResult  string `json:"compare_result,omitempty"` // newer | same | older | unknown
	// LKG fields (secret-free; from last successful verified download).
	LKGPresent      bool     `json:"lkg_present"`
	LKGVersion      string   `json:"lkg_version,omitempty"`
	LKGChannel      string   `json:"lkg_channel,omitempty"`
	LKGSHA256       string   `json:"lkg_artifact_sha256,omitempty"`
	LKGPathBasename string   `json:"lkg_path_basename,omitempty"`
	LKGTimestamp    string   `json:"lkg_timestamp,omitempty"`
	LKGKeyIDs       []string `json:"lkg_signature_key_ids,omitempty"`
	LKGPlatform     string   `json:"lkg_platform,omitempty"`
	CompareLKG      string   `json:"compare_lkg,omitempty"` // current vs LKG: newer|same|older|unknown
	SchemaVersion   int      `json:"manifest_schema_version,omitempty"`
	SignatureState  string   `json:"signature_state,omitempty"`
	SignatureKeyID  string   `json:"signature_key_id,omitempty"`
	TrustedKeysSet  bool     `json:"trusted_keys_configured"`
	AllowUnsigned   bool     `json:"allow_unsigned"`
	AllowDowngrade  bool     `json:"allow_downgrade"`
	Residual        string   `json:"residual,omitempty"`
	Notes           string   `json:"notes,omitempty"`
	AutoDownload    bool     `json:"auto_download"` // always false
	Message         string   `json:"message"`
}

// runUpdateCheck implements UPD-001: optional signed manifest fetch, never auto-download.
func runUpdateCheck(args []string) error {
	fs := flag.NewFlagSet("update-check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	channel := fs.String("channel", update.ChannelStable, "Release channel to match (stable|beta)")
	asJSON := fs.Bool("json", false, "Emit report as JSON")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	ch := strings.TrimSpace(*channel)
	if ch == "" {
		ch = update.ChannelStable
	}
	keys, err := loadUpdateKeys("")
	if err != nil {
		return err
	}
	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	rep, err := performUpdateCheck(updateCheckParams{
		Channel:        ch,
		ManifestURL:    strings.TrimSpace(os.Getenv(EnvUpdateManifestURL)),
		Keys:           keys,
		AllowUnsigned:  update.AllowUnsignedFromEnviron(),
		AllowDowngrade: update.AllowDowngradeFromEnviron(),
		AppVersion:     version,
		HTTPClient:     nil,
		Paths:          &paths,
	})
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	printUpdateCheckText(os.Stdout, rep)
	return nil
}

type updateCheckParams struct {
	Channel        string
	ManifestURL    string
	Keys           update.TrustedKeySet
	AllowUnsigned  bool
	AllowDowngrade bool
	AppVersion     string
	HTTPClient     *http.Client
	// Paths optional; used to resolve LKG. Nil ⇒ config.Resolve() / env.
	Paths *config.Paths
	// LKGPath overrides default LKG location (tests).
	LKGPath string
}

// performUpdateCheck is the testable core. When ManifestURL is empty, no network is used.
func performUpdateCheck(p updateCheckParams) (updateCheckReport, error) {
	cur := buildVersionInfo()
	appVer := p.AppVersion
	if appVer == "" {
		appVer = cur.Version
	}
	rep := updateCheckReport{
		Schema:         "jenkins-mcp.update-check.v3",
		Channel:        p.Channel,
		CurrentVersion: cur.Version,
		CurrentCommit:  cur.Commit,
		AutoDownload:   false,
		TrustedKeysSet: p.Keys.Len() > 0,
		AllowUnsigned:  p.AllowUnsigned,
		AllowDowngrade: p.AllowDowngrade,
	}
	attachLKG(&rep, p)
	if p.ManifestURL == "" {
		rep.ManifestURLSet = false
		rep.NetworkSkipped = true
		rep.Residual = "JENKINS_MCP_UPDATE_MANIFEST_URL is unset; no network check performed. " +
			"Configure a signed schema-v2 manifest URL + trusted keys for production; " +
			"install/rollback remains operator/package-manager owned. " +
			"LKG is recorded only after a successful verified download."
		rep.Message = "update check skipped (no manifest URL); current " + cur.Version
		if rep.LKGPresent {
			rep.Message += "; lkg " + rep.LKGVersion
		}
		return rep, nil
	}
	rep.ManifestURLSet = true
	if !strings.HasPrefix(p.ManifestURL, "https://") && !strings.HasPrefix(p.ManifestURL, "http://") {
		return rep, apperr.New(apperr.CodeInvalidArgument,
			"JENKINS_MCP_UPDATE_MANIFEST_URL must be an http(s) URL")
	}
	httpClient := p.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, p.ManifestURL, nil)
	if err != nil {
		return rep, apperr.Wrap(apperr.CodeInvalidArgument, "invalid manifest URL", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "jenkins-mcp-update-check/"+cur.Version)
	resp, err := httpClient.Do(req)
	if err != nil {
		return rep, apperr.Wrap(apperr.CodeUpstreamProtocol, "manifest fetch failed", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rep, apperr.New(apperr.CodeUpstreamProtocol,
			fmt.Sprintf("manifest fetch HTTP %d", resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return rep, apperr.Wrap(apperr.CodeUpstreamProtocol, "manifest body read failed", err)
	}

	vres, err := update.VerifyManifest(body, update.VerifyOptions{
		Keys:          p.Keys,
		AllowUnsigned: p.AllowUnsigned,
		Channel:       p.Channel,
		AppVersion:    appVer,
	})
	if err != nil {
		if vres != nil {
			rep.SignatureState = vres.SignatureState
			rep.SchemaVersion = vres.SchemaVersion
		}
		return rep, err
	}
	m := vres.Manifest
	rep.SignatureState = vres.SignatureState
	rep.SignatureKeyID = vres.KeyID
	rep.SchemaVersion = m.SchemaVersion
	rep.LatestVersion = m.Version
	rep.LatestCommit = m.Commit
	rep.ChangelogURL = m.ChangelogURL
	rep.PublishedAt = m.IssuedAt
	rep.Notes = m.Notes

	cmp := update.CompareVersions(cur.Version, m.Version)
	rep.CompareResult = cmp
	switch cmp {
	case "newer":
		rep.NewerAvailable = true
		rep.Message = fmt.Sprintf("newer version available: %s (current %s); signature_state=%s — use org package manager or `jenkins-mcp update download` (no auto-install)",
			m.Version, cur.Version, vres.SignatureState)
	case "same":
		rep.Message = fmt.Sprintf("already on latest reported version %s (signature_state=%s)", cur.Version, vres.SignatureState)
	case "older":
		rep.Message = fmt.Sprintf("current %s is ahead of manifest %s (signature_state=%s)", cur.Version, m.Version, vres.SignatureState)
	default:
		rep.Message = fmt.Sprintf("manifest latest=%s current=%s (version compare inconclusive; signature_state=%s)", m.Version, cur.Version, vres.SignatureState)
		if normalizeVersionLocal(cur.Version) != normalizeVersionLocal(m.Version) {
			rep.NewerAvailable = true
			rep.CompareResult = "unknown"
		}
	}
	rep.Residual = "UPD-001: never auto-installs; download is optional and checksum-only. " +
		"LKG records last verified download (not installed binary). " +
		"Binary rollback/swap remains residual — prefer enterprise package manager."
	if rep.LKGPresent && rep.LatestVersion != "" {
		// Enrich message with current / latest / LKG triad for operators.
		rep.Message = fmt.Sprintf("%s; current=%s latest=%s lkg=%s",
			rep.Message, rep.CurrentVersion, rep.LatestVersion, rep.LKGVersion)
	}
	return rep, nil
}

// attachLKG loads last-known-good into the update-check report (secret-free).
func attachLKG(rep *updateCheckReport, p updateCheckParams) {
	if rep == nil {
		return
	}
	var rec *update.LKGRecord
	var err error
	if path := strings.TrimSpace(p.LKGPath); path != "" {
		rec, err = update.LoadLKG(path)
	} else {
		rec, _, err = update.LoadLKGFromEnviron(p.Paths)
	}
	if err != nil {
		// Soft residual in notes — do not fail update-check on corrupt LKG alone;
		// operators can run show-lkg for hard fail. Keep messaging secret-free.
		if rep.Notes != "" {
			rep.Notes += "; "
		}
		rep.Notes += "LKG load failed: " + apperr.ModelMessage(err)
		return
	}
	if rec == nil {
		rep.LKGPresent = false
		return
	}
	rep.LKGPresent = true
	rep.LKGVersion = rec.Version
	rep.LKGChannel = rec.Channel
	rep.LKGSHA256 = rec.ArtifactSHA256
	rep.LKGPathBasename = rec.PathBasename
	rep.LKGTimestamp = rec.Timestamp
	rep.LKGKeyIDs = rec.SignatureKeyIDs
	rep.LKGPlatform = rec.Platform
	rep.CompareLKG = update.CompareVersions(rep.CurrentVersion, rec.Version)
}

func printUpdateCheckText(w io.Writer, rep updateCheckReport) {
	fmt.Fprintf(w, "channel:          %s\n", rep.Channel)
	fmt.Fprintf(w, "current_version:  %s\n", rep.CurrentVersion)
	fmt.Fprintf(w, "current_commit:   %s\n", rep.CurrentCommit)
	fmt.Fprintf(w, "manifest_url_set: %v\n", rep.ManifestURLSet)
	if rep.NetworkSkipped {
		fmt.Fprintf(w, "network:          skipped\n")
	}
	fmt.Fprintf(w, "trusted_keys:     %v\n", rep.TrustedKeysSet)
	fmt.Fprintf(w, "allow_unsigned:   %v\n", rep.AllowUnsigned)
	fmt.Fprintf(w, "allow_downgrade:  %v\n", rep.AllowDowngrade)
	if rep.SignatureState != "" {
		fmt.Fprintf(w, "signature_state:  %s\n", rep.SignatureState)
	}
	if rep.SignatureKeyID != "" {
		fmt.Fprintf(w, "signature_key_id: %s\n", rep.SignatureKeyID)
	}
	if rep.SchemaVersion != 0 {
		fmt.Fprintf(w, "manifest_schema:  %d\n", rep.SchemaVersion)
	}
	fmt.Fprintf(w, "newer_available:  %v\n", rep.NewerAvailable)
	if rep.LatestVersion != "" {
		fmt.Fprintf(w, "latest_version:   %s\n", rep.LatestVersion)
	}
	if rep.LatestCommit != "" {
		fmt.Fprintf(w, "latest_commit:    %s\n", rep.LatestCommit)
	}
	if rep.ChangelogURL != "" {
		fmt.Fprintf(w, "changelog_url:    %s\n", rep.ChangelogURL)
	}
	if rep.CompareResult != "" {
		fmt.Fprintf(w, "compare_result:   %s\n", rep.CompareResult)
	}
	fmt.Fprintf(w, "lkg_present:      %v\n", rep.LKGPresent)
	if rep.LKGPresent {
		fmt.Fprintf(w, "lkg_version:      %s\n", rep.LKGVersion)
		if rep.LKGChannel != "" {
			fmt.Fprintf(w, "lkg_channel:      %s\n", rep.LKGChannel)
		}
		if rep.LKGSHA256 != "" {
			fmt.Fprintf(w, "lkg_sha256:       %s\n", rep.LKGSHA256)
		}
		if rep.LKGPathBasename != "" {
			fmt.Fprintf(w, "lkg_basename:     %s\n", rep.LKGPathBasename)
		}
		if rep.LKGTimestamp != "" {
			fmt.Fprintf(w, "lkg_timestamp:    %s\n", rep.LKGTimestamp)
		}
		if rep.CompareLKG != "" {
			fmt.Fprintf(w, "compare_lkg:      %s\n", rep.CompareLKG)
		}
	}
	fmt.Fprintf(w, "auto_download:    %v\n", rep.AutoDownload)
	fmt.Fprintf(w, "message:          %s\n", rep.Message)
	if rep.Residual != "" {
		fmt.Fprintf(w, "residual:         %s\n", rep.Residual)
	}
}

func runUpdateVerifyManifest(args []string) error {
	fs := flag.NewFlagSet("update verify-manifest", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	file := fs.String("file", "", "Update manifest JSON path (required)")
	keysPath := fs.String("keys", "", "Trusted public keys file or directory")
	channel := fs.String("channel", "", "Optional channel pin (stable|beta)")
	asJSON := fs.Bool("json", false, "Emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if strings.TrimSpace(*file) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--file is required")
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return apperr.Wrap(apperr.CodeInvalidArgument, "read manifest file failed", err)
	}
	keys, err := loadUpdateKeys(strings.TrimSpace(*keysPath))
	if err != nil {
		return err
	}
	vres, err := update.VerifyManifest(raw, update.VerifyOptions{
		Keys:          keys,
		AllowUnsigned: update.AllowUnsignedFromEnviron(),
		Channel:       strings.TrimSpace(*channel),
		AppVersion:    version,
	})
	report := map[string]any{
		"schema":           "jenkins-mcp.update.verify-manifest.v1",
		"ok":               err == nil,
		"manifest_base":    filepath.Base(*file),
		"trusted_keys_set": keys.Len() > 0,
	}
	if vres != nil {
		report["signature_state"] = vres.SignatureState
		report["key_id"] = vres.KeyID
		report["channel"] = vres.Channel
		report["version"] = vres.Version
		report["schema_version"] = vres.SchemaVersion
		if vres.Message != "" {
			report["message"] = vres.Message
		}
	}
	if err != nil {
		report["error"] = apperr.ModelMessage(err)
		if *asJSON {
			_ = writeJSON(report)
			return err
		}
		fmt.Fprintf(os.Stderr, "update verify-manifest: FAIL: %s\n", apperr.ModelMessage(err))
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Printf("update verify-manifest: OK signature_state=%s", vres.SignatureState)
	if vres.KeyID != "" {
		fmt.Printf(" key_id=%s", vres.KeyID)
	}
	fmt.Printf(" version=%s channel=%s\n", vres.Version, vres.Channel)
	return nil
}

func runUpdateDownload(args []string) error {
	fs := flag.NewFlagSet("update download", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	channel := fs.String("channel", update.ChannelStable, "Release channel pin (stable|beta)")
	outdir := fs.String("outdir", "", "Destination directory (default: OS temp)")
	manifestURL := fs.String("manifest-url", "", "Override JENKINS_MCP_UPDATE_MANIFEST_URL")
	asJSON := fs.Bool("json", false, "Emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	ch := strings.TrimSpace(*channel)
	if ch == "" {
		ch = update.ChannelStable
	}
	url := strings.TrimSpace(*manifestURL)
	if url == "" {
		url = strings.TrimSpace(os.Getenv(EnvUpdateManifestURL))
	}
	if url == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"manifest URL required (set JENKINS_MCP_UPDATE_MANIFEST_URL or --manifest-url)")
	}
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return apperr.New(apperr.CodeInvalidArgument, "manifest URL must be http(s)")
	}

	keys, err := loadUpdateKeys("")
	if err != nil {
		return err
	}
	// Download requires verified signatures (keys configured + valid sig).
	if keys.Len() == 0 {
		return apperr.New(apperr.CodePolicyDenial,
			"update download requires trusted keys (JENKINS_MCP_UPDATE_TRUSTED_KEYS or XDG update/trusted_keys/); unsigned pilot cannot download")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return apperr.Wrap(apperr.CodeInvalidArgument, "invalid manifest URL", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "jenkins-mcp-update-download/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return apperr.Wrap(apperr.CodeUpstreamProtocol, "manifest fetch failed", err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if err != nil {
		return apperr.Wrap(apperr.CodeUpstreamProtocol, "manifest body read failed", err)
	}
	if resp.StatusCode != http.StatusOK {
		return apperr.New(apperr.CodeUpstreamProtocol,
			fmt.Sprintf("manifest fetch HTTP %d", resp.StatusCode))
	}

	vres, err := update.VerifyManifest(body, update.VerifyOptions{
		Keys:       keys,
		Channel:    ch,
		AppVersion: version,
	})
	if err != nil {
		return err
	}

	outDir := strings.TrimSpace(*outdir)
	allowDowngrade := update.AllowDowngradeFromEnviron()
	dres, err := update.DownloadArtifact(update.DownloadOptions{
		Manifest:        vres.Manifest,
		RequireVerified: true,
		SignatureState:  vres.SignatureState,
		GOOS:            runtime.GOOS,
		GOARCH:          runtime.GOARCH,
		OutDir:          outDir,
		UserAgent:       "jenkins-mcp-update-download/" + version,
		CurrentVersion:  version,
		ChannelPin:      ch,
		AllowDowngrade:  allowDowngrade,
	})
	if err != nil {
		return err
	}

	// Record last-known-good after successful verified download (secret-free).
	keyIDs := update.SignatureKeyIDsFromManifest(vres.Manifest)
	if vres.KeyID != "" {
		keyIDs = append(keyIDs, vres.KeyID)
	}
	lkgPath, lkgErr := update.DefaultLKGPath(nil)
	var lkgRec *update.LKGRecord
	if lkgErr == nil && lkgPath != "" {
		lkgRec, lkgErr = update.StoreLKG(update.LKGWriteOptions{
			Path:            lkgPath,
			Version:         dres.Version,
			Channel:         dres.Channel,
			ArtifactSHA256:  dres.SHA256,
			ArtifactPath:    dres.Path,
			SignatureKeyIDs: keyIDs,
			Platform:        dres.Platform,
		})
	}

	report := map[string]any{
		"schema":           "jenkins-mcp.update.download.v2",
		"ok":               true,
		"path":             dres.Path,
		"sha256":           dres.SHA256,
		"bytes_written":    dres.BytesWritten,
		"platform":         dres.Platform,
		"version":          dres.Version,
		"channel":          dres.Channel,
		"signature_state":  dres.SignatureState,
		"auto_install":     false,
		"next_steps":       dres.NextSteps,
		"signature_key_id": vres.KeyID,
		"lkg_written":      lkgRec != nil,
	}
	if lkgRec != nil {
		report["lkg_version"] = lkgRec.Version
		report["lkg_path_basename"] = lkgRec.PathBasename
		report["lkg_timestamp"] = lkgRec.Timestamp
	} else if lkgErr != nil {
		report["lkg_error"] = apperr.ModelMessage(lkgErr)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Printf("update download: OK (checksum verified; NOT installed)\n")
	fmt.Printf("  path:     %s\n", dres.Path)
	fmt.Printf("  sha256:   %s\n", dres.SHA256)
	fmt.Printf("  version:  %s\n", dres.Version)
	fmt.Printf("  platform: %s\n", dres.Platform)
	if lkgRec != nil {
		fmt.Printf("  lkg:      recorded version=%s basename=%s\n", lkgRec.Version, lkgRec.PathBasename)
	} else if lkgErr != nil {
		fmt.Printf("  lkg:      not recorded (%s)\n", apperr.ModelMessage(lkgErr))
	}
	fmt.Printf("  next:     %s\n", dres.NextSteps)
	return nil
}

func runUpdateShowLKG(args []string) error {
	fs := flag.NewFlagSet("update show-lkg", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "Emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	path, err := update.DefaultLKGPath(&paths)
	if err != nil {
		return err
	}
	rec, err := update.LoadLKG(path)
	if err != nil {
		return err
	}
	report := map[string]any{
		"schema":   "jenkins-mcp.update.show-lkg.v1",
		"lkg_path": filepath.Base(path), // basename only in output (avoid home tree leakage)
		"present":  rec != nil,
		"residual": "LKG is last verified download metadata only — not an installed binary. Install/rollback is operator-owned.",
	}
	if rec != nil {
		report["version"] = rec.Version
		report["channel"] = rec.Channel
		report["artifact_sha256"] = rec.ArtifactSHA256
		report["path_basename"] = rec.PathBasename
		report["timestamp"] = rec.Timestamp
		report["signature_key_ids"] = rec.SignatureKeyIDs
		report["platform"] = rec.Platform
		report["schema_version"] = rec.SchemaVersion
		report["compare_current"] = update.CompareVersions(version, rec.Version)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	if rec == nil {
		fmt.Printf("update show-lkg: no last-known-good record\n")
		fmt.Printf("  residual: LKG is written after a successful verified download only.\n")
		return nil
	}
	fmt.Printf("update show-lkg: present\n")
	fmt.Printf("  version:    %s\n", rec.Version)
	fmt.Printf("  channel:    %s\n", rec.Channel)
	fmt.Printf("  sha256:     %s\n", rec.ArtifactSHA256)
	fmt.Printf("  basename:   %s\n", rec.PathBasename)
	fmt.Printf("  timestamp:  %s\n", rec.Timestamp)
	if rec.Platform != "" {
		fmt.Printf("  platform:   %s\n", rec.Platform)
	}
	if len(rec.SignatureKeyIDs) > 0 {
		fmt.Printf("  key_ids:    %s\n", strings.Join(rec.SignatureKeyIDs, ","))
	}
	fmt.Printf("  compare:    current %s vs lkg → %s\n", version, update.CompareVersions(version, rec.Version))
	fmt.Printf("  residual:   LKG is download metadata only; install/rollback is operator-owned.\n")
	return nil
}

// runUpdateVerifyLKG re-hashes the staged LKG artifact against the recorded sha256.
// Fail closed: missing LKG, missing file, empty/invalid sha, or hash mismatch → error.
func runUpdateVerifyLKG(args []string) error {
	fs := flag.NewFlagSet("update verify-lkg", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "Emit machine-readable JSON")
	filePath := fs.String("file", "", "Path to staged artifact (overrides default download-dir basename lookup)")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	res, err := update.VerifyLKG(update.VerifyLKGOptions{
		ArtifactPath: strings.TrimSpace(*filePath),
		Paths:        &paths,
	})
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(res); encErr != nil {
			return encErr
		}
	} else {
		status := "FAIL"
		if res.OK {
			status = "OK"
		}
		fmt.Printf("update verify-lkg: %s\n", status)
		fmt.Printf("  lkg_present:    %v\n", res.LKGPresent)
		if res.Version != "" {
			fmt.Printf("  version:        %s\n", res.Version)
		}
		if res.Channel != "" {
			fmt.Printf("  channel:        %s\n", res.Channel)
		}
		if res.PathBasename != "" {
			fmt.Printf("  basename:       %s\n", res.PathBasename)
		}
		fmt.Printf("  artifact_found: %v\n", res.ArtifactFound)
		fmt.Printf("  sha_match:      %v\n", res.SHAMatch)
		if res.ExpectedSHA256 != "" {
			fmt.Printf("  expected_sha:   %s\n", res.ExpectedSHA256)
		}
		if res.ActualSHA256 != "" {
			fmt.Printf("  actual_sha:     %s\n", res.ActualSHA256)
		}
		if res.Reason != "" {
			fmt.Printf("  reason:         %s\n", res.Reason)
		}
		fmt.Printf("  residual:       %s\n", res.Residual)
	}
	if !res.OK {
		// Fail closed: non-zero exit for operators/CI.
		msg := res.Reason
		if msg == "" {
			msg = "LKG on-disk re-verify failed"
		}
		return apperr.New(apperr.CodePolicyDenial, msg)
	}
	return nil
}

func loadUpdateKeys(explicit string) (update.TrustedKeySet, error) {
	if explicit != "" {
		return update.LoadTrustedKeys(explicit)
	}
	paths, err := config.Resolve()
	if err != nil {
		return nil, err
	}
	return update.LoadTrustedKeysFromEnviron(&paths)
}

// normalizeVersionLocal keeps a tiny helper for compare unknown-branch in update-check.
func normalizeVersionLocal(v string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "v")))
}
