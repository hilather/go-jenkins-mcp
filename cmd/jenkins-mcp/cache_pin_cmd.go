package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// ARC-007 pin CLI: durable generation/pack pins that protect against eviction
// (not against manual delete-all of the profile data tree).

func runCachePin(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument, "cache pin subcommand required: generation|pack")
	}
	switch args[0] {
	case "generation":
		return runCachePinGeneration(args[1:])
	case "pack":
		return runCachePinPack(args[1:])
	default:
		return apperr.New(apperr.CodeInvalidArgument, "unknown cache pin subcommand (generation|pack)")
	}
}

func runCacheUnpin(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument, "cache unpin subcommand required: generation|pack")
	}
	switch args[0] {
	case "generation":
		return runCacheUnpinGeneration(args[1:])
	case "pack":
		return runCacheUnpinPack(args[1:])
	default:
		return apperr.New(apperr.CodeInvalidArgument, "unknown cache unpin subcommand (generation|pack)")
	}
}

func runCachePinGeneration(args []string) error {
	fs := flag.NewFlagSet("cache pin generation", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	genFlag := fs.String("generation", "", "Log generation SQLite id (required)")
	if err := fs.Parse(reorderFlagArgs(args, valueTakingFlags(fs))); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	genID, err := parsePositiveInt64Flag("generation", *genFlag)
	if err != nil {
		return err
	}
	meta, p, err := openProfileMetaForPins(*profileFlag)
	if err != nil {
		return err
	}
	defer func() { _ = meta.Close() }()
	ctx := context.Background()
	if err := meta.PinGeneration(ctx, genID); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "pinned kind=generation target=%d profile=%s\n", genID, p.ID)
	return nil
}

func runCacheUnpinGeneration(args []string) error {
	fs := flag.NewFlagSet("cache unpin generation", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	genFlag := fs.String("generation", "", "Log generation SQLite id (required)")
	if err := fs.Parse(reorderFlagArgs(args, valueTakingFlags(fs))); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	genID, err := parsePositiveInt64Flag("generation", *genFlag)
	if err != nil {
		return err
	}
	meta, p, err := openProfileMetaForPins(*profileFlag)
	if err != nil {
		return err
	}
	defer func() { _ = meta.Close() }()
	ctx := context.Background()
	if err := meta.UnpinGeneration(ctx, genID); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "unpinned kind=generation target=%d profile=%s\n", genID, p.ID)
	return nil
}

func runCachePinPack(args []string) error {
	fs := flag.NewFlagSet("cache pin pack", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	packFlag := fs.String("pack", "", "L2 pack id (required)")
	if err := fs.Parse(reorderFlagArgs(args, valueTakingFlags(fs))); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	packID := strings.TrimSpace(*packFlag)
	if packID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--pack is required")
	}
	meta, p, err := openProfileMetaForPins(*profileFlag)
	if err != nil {
		return err
	}
	defer func() { _ = meta.Close() }()
	ctx := context.Background()
	if err := meta.PinPack(ctx, packID); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "pinned kind=pack target=%s profile=%s\n", packID, p.ID)
	return nil
}

func runCacheUnpinPack(args []string) error {
	fs := flag.NewFlagSet("cache unpin pack", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	packFlag := fs.String("pack", "", "L2 pack id (required)")
	if err := fs.Parse(reorderFlagArgs(args, valueTakingFlags(fs))); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	packID := strings.TrimSpace(*packFlag)
	if packID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--pack is required")
	}
	meta, p, err := openProfileMetaForPins(*profileFlag)
	if err != nil {
		return err
	}
	defer func() { _ = meta.Close() }()
	ctx := context.Background()
	if err := meta.UnpinPack(ctx, packID); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "unpinned kind=pack target=%s profile=%s\n", packID, p.ID)
	return nil
}

// pinListJSON is secret-free pin listing for --json (ARC-007).
type pinListJSON struct {
	Profile string        `json:"profile"`
	Pins    []pinJSONItem `json:"pins"`
}

type pinJSONItem struct {
	Kind     string `json:"kind"`
	TargetID string `json:"target_id"`
	PinnedAt string `json:"pinned_at,omitempty"`
}

func runCachePins(args []string) error {
	fs := flag.NewFlagSet("cache pins", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	asJSON := fs.Bool("json", false, "Emit pin list as secret-free JSON")
	if err := fs.Parse(reorderFlagArgs(args, valueTakingFlags(fs))); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	meta, p, err := openProfileMetaForPins(*profileFlag)
	if err != nil {
		return err
	}
	defer func() { _ = meta.Close() }()
	ctx := context.Background()
	pins, err := meta.ListPins(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		out := pinListJSON{Profile: string(p.ID), Pins: make([]pinJSONItem, 0, len(pins))}
		for _, pin := range pins {
			item := pinJSONItem{Kind: pin.Kind, TargetID: pin.TargetID}
			if !pin.PinnedAt.IsZero() {
				item.PinnedAt = pin.PinnedAt.UTC().Format(time.RFC3339Nano)
			}
			out.Pins = append(out.Pins, item)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return apperr.Wrap(apperr.CodeInternal, "encode pins JSON", err)
		}
		return nil
	}
	if len(pins) == 0 {
		fmt.Fprintf(os.Stdout, "profile=%s pins=0\n", p.ID)
		return nil
	}
	fmt.Fprintf(os.Stdout, "profile=%s pins=%d\n", p.ID, len(pins))
	for _, pin := range pins {
		at := ""
		if !pin.PinnedAt.IsZero() {
			at = " pinned_at=" + pin.PinnedAt.UTC().Format(time.RFC3339Nano)
		}
		fmt.Fprintf(os.Stdout, "  kind=%s target=%s%s\n", pin.Kind, pin.TargetID, at)
	}
	return nil
}

// openProfileMetaForPins loads the profile and opens its meta store.
// Fail closed: missing profile, missing/invalid data directory, or open errors.
// Does not create a data directory when none exists (pin ops require an existing cache root).
func openProfileMetaForPins(profileID string) (*store.Meta, *profile.Profile, error) {
	ps, err := profileStore()
	if err != nil {
		return nil, nil, err
	}
	p, err := ps.Load(profileID)
	if err != nil {
		return nil, nil, err
	}
	dataDir, err := resolveProfileDataDirPath(p)
	if err != nil {
		return nil, nil, err
	}
	if err := store.ValidateDir(dataDir); err != nil {
		return nil, nil, err
	}
	meta, err := store.Open(dataDir)
	if err != nil {
		return nil, nil, err
	}
	return meta, p, nil
}

// resolveProfileDataDirPath returns the profile data root without creating it.
// Mirrors store.EnsureProfileDataDir path resolution (ARC-007 pin CLI fail-closed).
func resolveProfileDataDirPath(p *profile.Profile) (string, error) {
	if p == nil {
		return "", apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	id := strings.TrimSpace(string(p.ID))
	if id == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}
	var dataRoot string
	if strings.TrimSpace(p.DataDir) != "" {
		dataRoot = p.DataDir
	} else {
		paths, err := config.Resolve()
		if err != nil {
			return "", err
		}
		dataRoot = paths.ProfileDataDir(id)
	}
	clean := filepath.Clean(dataRoot)
	if filepath.Base(clean) == id {
		return clean, nil
	}
	return filepath.Join(clean, id), nil
}

func parsePositiveInt64Flag(name, raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, apperr.New(apperr.CodeInvalidArgument, "--"+name+" is required")
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument, "--"+name+" must be a positive integer")
	}
	return n, nil
}
