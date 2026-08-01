package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	storecrypto "github.com/simonfxr/go-jenkins-mcp/internal/store/crypto"
)

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	offline := fs.Bool("offline", false, "Skip network identity verify (whoAmI)")
	bundle := fs.Bool("bundle", false, "Write a privacy-scrubbed support bundle under XDG cache (OPS-001)")
	previewBundle := fs.Bool("bundle-preview", false, "List support-bundle categories without writing a zip")
	// Mirror serve RO inputs so doctor mutations check matches process posture (Wave 32).
	readOnly := fs.Bool("read-only", false, "Treat CLI --read-only as set (same as serve)")
	allowMutations := fs.Bool("allow-mutations", false, "Treat --allow-mutations as set (same as serve; for mutations doctor check)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"profile": true})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	ps, err := profileStore()
	if err != nil {
		return err
	}
	p, err := ps.Load(*profileFlag)
	if err != nil {
		return err
	}
	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	var polPtr *policy.LoadResult
	if polRes, polErr := policy.LoadFromEnviron(); polErr == nil {
		polPtr = &polRes
	}
	docOpts := diagnostics.DoctorOptions{
		Profile:        p,
		Paths:          &paths,
		Keyring:        keyringStore(),
		Version:        version,
		Commit:         commit,
		BuildTime:      buildTime,
		SkipNetwork:    *offline,
		PolicyResult:   polPtr,
		FlagReadOnly:   *readOnly,
		AllowMutations: *allowMutations,
	}
	rep, err := diagnostics.RunDoctor(context.Background(), docOpts)
	if err != nil {
		return err
	}
	diagnostics.FormatReportText(os.Stdout, rep)

	if *bundle || *previewBundle {
		if err := writeSupportBundle(p, &paths, &rep, docOpts, *previewBundle); err != nil {
			return err
		}
	}

	if rep.Overall == diagnostics.StatusFail {
		return apperr.New(apperr.CodeInternal, "doctor reported one or more failures")
	}
	return nil
}

func runSupportBundle(args []string) error {
	fs := flag.NewFlagSet("support-bundle", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	preview := fs.Bool("preview", false, "List included/excluded categories without writing a zip")
	offline := fs.Bool("offline", true, "Skip network identity verify when embedding doctor (default true)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"profile": true})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	ps, err := profileStore()
	if err != nil {
		return err
	}
	p, err := ps.Load(*profileFlag)
	if err != nil {
		return err
	}
	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	var polPtr *policy.LoadResult
	if polRes, polErr := policy.LoadFromEnviron(); polErr == nil {
		polPtr = &polRes
	}
	docOpts := diagnostics.DoctorOptions{
		Profile:      p,
		Paths:        &paths,
		Keyring:      keyringStore(),
		Version:      version,
		Commit:       commit,
		BuildTime:    buildTime,
		SkipNetwork:  *offline,
		PolicyResult: polPtr,
	}
	return writeSupportBundle(p, &paths, nil, docOpts, *preview)
}

// writeSupportBundle prints the category plan then creates (or previews) the OPS-001 zip.
func writeSupportBundle(p *profile.Profile, paths *config.Paths, rep *diagnostics.Report, docOpts diagnostics.DoctorOptions, preview bool) error {
	if p == nil {
		return apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	docOpts.Profile = p
	if docOpts.Paths == nil {
		docOpts.Paths = paths
	}

	// Acceptance: list included categories before creation.
	fmt.Fprintln(os.Stdout, "support-bundle categories (included):")
	for _, c := range diagnostics.DefaultBundleCategories() {
		fmt.Fprintf(os.Stdout, "  + %s\n", c)
	}
	fmt.Fprintln(os.Stdout, "support-bundle categories (excluded):")
	for _, c := range diagnostics.BundleExcludedCategories {
		fmt.Fprintf(os.Stdout, "  - %s\n", c)
	}

	res, err := diagnostics.CreateSupportBundle(context.Background(), diagnostics.SupportBundleOptions{
		Profile:      p,
		Paths:        paths,
		DoctorReport: rep,
		DoctorOpts:   docOpts,
		// Wave 23 offline members: version/runtime + security self-check + RS residual.
		// PolicyResult enables self-check signature-mode row without re-load when known.
		PolicyResult: docOpts.PolicyResult,
		Version:      firstNonEmptyStr(docOpts.Version, version),
		Commit:       firstNonEmptyStr(docOpts.Commit, commit),
		BuildTime:    firstNonEmptyStr(docOpts.BuildTime, buildTime),
		PreviewOnly:  preview,
	})
	if err != nil {
		return err
	}
	if preview {
		fmt.Fprintf(os.Stdout, "support-bundle preview path would be: %s\n", res.Plan.OutputPath)
		return nil
	}
	fmt.Fprintf(os.Stdout, "support-bundle written: %s (%d bytes)\n", res.Path, res.Bytes)
	fmt.Fprintln(os.Stdout, "redaction: secrets scrubbed; no keyring values, full logs, artifacts, cookies, or Authorization headers")
	return nil
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func runCache(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument, "cache subcommand required: status|verify|repair|key|pin|unpin|pins|eviction-plan|evict|eviction-apply|quota")
	}
	switch args[0] {
	case "status":
		return runCacheStatus(args[1:])
	case "verify":
		return runCacheVerify(args[1:])
	case "repair":
		return runCacheRepair(args[1:])
	case "key":
		return runCacheKey(args[1:])
	case "pin":
		return runCachePin(args[1:])
	case "unpin":
		return runCacheUnpin(args[1:])
	case "pins":
		return runCachePins(args[1:])
	case "eviction-plan":
		return runCacheEvictionPlan(args[1:])
	case "evict", "eviction-apply":
		return runCacheEvict(args[1:])
	case "quota":
		return runCacheQuota(args[1:])
	default:
		return apperr.New(apperr.CodeInvalidArgument, "unknown cache subcommand (status|verify|repair|key|pin|unpin|pins|eviction-plan|evict|eviction-apply|quota)")
	}
}

// ARC-009: cache key lifecycle (key material only in OS keyring).
func runCacheKey(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument, "cache key subcommand required: init|status|rotate")
	}
	switch args[0] {
	case "init":
		return runCacheKeyInit(args[1:], false)
	case "rotate":
		return runCacheKeyInit(args[1:], true)
	case "status":
		return runCacheKeyStatus(args[1:])
	default:
		return apperr.New(apperr.CodeInvalidArgument, "unknown cache key subcommand (init|status|rotate)")
	}
}

func runCacheKeyInit(args []string, rotate bool) error {
	name := "cache key init"
	if rotate {
		name = "cache key rotate"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"profile": true})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	ps, err := profileStore()
	if err != nil {
		return err
	}
	p, err := ps.Load(*profileFlag)
	if err != nil {
		return err
	}
	kr := keyringStore()
	nextVer := 1
	if rotate {
		if p.CacheKeyVersion < 1 {
			return apperr.New(apperr.CodeInvalidArgument,
				"cannot rotate: no existing cache key (run cache key init first)")
		}
		nextVer = p.CacheKeyVersion + 1
	} else if p.CacheKeyVersion >= 1 {
		// Idempotent init when key already present.
		ok, err := kr.HasCacheKey(string(p.ID), p.CacheKeyVersion)
		if err != nil {
			return err
		}
		if ok && p.CacheEncryption {
			fmt.Fprintf(os.Stdout, "cache encryption already enabled profile=%s key_version=%d\n",
				p.ID, p.CacheKeyVersion)
			return nil
		}
		if p.CacheKeyVersion >= 1 {
			nextVer = p.CacheKeyVersion
		}
	}
	k, err := storecrypto.GenerateKey(nextVer)
	if err != nil {
		return err
	}
	if err := kr.SetCacheKey(string(p.ID), k.Version, k.Material); err != nil {
		return err
	}
	// Zero local material ASAP (keyring holds the only copy after Set).
	for i := range k.Material {
		k.Material[i] = 0
	}
	p.CacheEncryption = true
	p.CacheKeyVersion = nextVer
	if err := ps.Save(p); err != nil {
		return err
	}
	// Retention: only the last two versions stay active (write N and prev N-1).
	// Drop N-2 after the profile write version has been bumped so a mid-failure
	// cannot leave readers without the then-current prev key.
	// Missing entries are success; delete failures are soft (rotation already committed).
	if rotate {
		if drop := nextVer - 2; drop >= 1 {
			_ = kr.DeleteCacheKey(string(p.ID), drop)
		}
		fmt.Fprintf(os.Stdout, "cache key rotated profile=%s key_version=%d (reads accept N and N-1; last 2 versions retained; no full rewrite)\n",
			p.ID, nextVer)
	} else {
		fmt.Fprintf(os.Stdout, "cache encryption enabled profile=%s key_version=%d\n", p.ID, nextVer)
	}
	return nil
}

func runCacheKeyStatus(args []string) error {
	fs := flag.NewFlagSet("cache key status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"profile": true})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	ps, err := profileStore()
	if err != nil {
		return err
	}
	p, err := ps.Load(*profileFlag)
	if err != nil {
		return err
	}
	kr := keyringStore()
	writePresent := false
	prevPresent := false
	if p.CacheKeyVersion >= 1 {
		writePresent, _ = kr.HasCacheKey(string(p.ID), p.CacheKeyVersion)
		if p.CacheKeyVersion > 1 {
			prevPresent, _ = kr.HasCacheKey(string(p.ID), p.CacheKeyVersion-1)
		}
	}
	// Secret-free status only: encryption flag, write version, key presence bools.
	// Never print key material, base64, or keyring account values.
	fmt.Fprintf(os.Stdout, "profile=%s cache_encryption=%v key_version=%d write_key_present=%v prev_key_present=%v env_JENKINS_MCP_CACHE_ENCRYPTION=%v\n",
		p.ID, p.CacheEncryption, p.CacheKeyVersion, writePresent, prevPresent, profile.EnvCacheEncryption())
	return nil
}

func runCacheStatus(args []string) error {
	fs := flag.NewFlagSet("cache status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"profile": true})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	ps, err := profileStore()
	if err != nil {
		return err
	}
	p, err := ps.Load(*profileFlag)
	if err != nil {
		return err
	}
	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	st, err := diagnostics.RunCacheStatus(context.Background(), diagnostics.CacheStatusOptions{
		Profile: p,
		Paths:   &paths,
	})
	if err != nil {
		return err
	}
	diagnostics.FormatCacheStatusText(os.Stdout, st)
	return nil
}

func runCacheVerify(args []string) error {
	fs := flag.NewFlagSet("cache verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	full := fs.Bool("full", false, "Verify every pack (cancellable)")
	sample := fs.Int("sample", diagnostics.DefaultVerifySample, "Max packs to check when not --full")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"profile": true, "sample": true})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	ps, err := profileStore()
	if err != nil {
		return err
	}
	p, err := ps.Load(*profileFlag)
	if err != nil {
		return err
	}
	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	rep, err := diagnostics.RunCacheVerify(context.Background(), diagnostics.CacheVerifyOptions{
		Profile: p,
		Paths:   &paths,
		Full:    *full,
		Sample:  *sample,
	})
	// Always print support-safe report; cancel still surfaces as error after.
	diagnostics.FormatCacheVerifyText(os.Stdout, rep)
	if err != nil {
		return err
	}
	if rep.PackFail > 0 {
		return apperr.New(apperr.CodeCorruptCache, fmt.Sprintf("cache verify found %d pack failure(s)", rep.PackFail))
	}
	return nil
}

func runCacheRepair(args []string) error {
	fs := flag.NewFlagSet("cache repair", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	indexOnly := fs.Bool("index-only", true, "Rebuild sidecar indexes only (default; pack bodies never rewritten)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"profile": true})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	ps, err := profileStore()
	if err != nil {
		return err
	}
	p, err := ps.Load(*profileFlag)
	if err != nil {
		return err
	}
	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	rep, err := diagnostics.RunCacheRepair(context.Background(), diagnostics.CacheRepairOptions{
		Profile:   p,
		Paths:     &paths,
		IndexOnly: *indexOnly,
	})
	diagnostics.FormatCacheRepairText(os.Stdout, rep)
	if err != nil {
		return err
	}
	if rep.Failed > 0 {
		return apperr.New(apperr.CodeCorruptCache, fmt.Sprintf("cache repair failed for %d pack(s)", rep.Failed))
	}
	return nil
}
