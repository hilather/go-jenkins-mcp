package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// pilotEvidence is the secret-free JSON report for REL-001 pilot readiness.
// Never include tokens, cookies, Authorization headers, or private keys.
type pilotEvidence struct {
	Schema      string     `json:"schema"`
	GeneratedAt string     `json:"generated_at"`
	ProfileID   string     `json:"profile_id"`
	Offline     bool       `json:"offline"`
	Overall     string     `json:"overall"` // pass | fail | warn
	Version     string     `json:"version,omitempty"`
	Commit      string     `json:"commit,omitempty"`
	GOOS        string     `json:"goos"`
	GOARCH      string     `json:"goarch"`
	Doctor      doctorSnap `json:"doctor"`
	CacheStatus cacheSnap  `json:"cache_status"`
	CacheVerify verifySnap `json:"cache_verify"`
	Notes       []string   `json:"notes,omitempty"`
}

type doctorSnap struct {
	Overall string              `json:"overall"`
	Checks  []diagnostics.Check `json:"checks"`
}

type cacheSnap struct {
	DataDirOK     bool   `json:"data_dir_ok"`
	StoreOpen     bool   `json:"store_open"`
	SchemaOK      bool   `json:"schema_ok"`
	SchemaVersion int    `json:"schema_version,omitempty"`
	Generations   int64  `json:"generations"`
	Chunks        int64  `json:"chunks"`
	Message       string `json:"message,omitempty"`
}

type verifySnap struct {
	Mode         string `json:"mode"`
	PacksTotal   int    `json:"packs_total"`
	PacksChecked int    `json:"packs_checked"`
	PackOK       int    `json:"pack_ok"`
	PackFail     int    `json:"pack_fail"`
	Message      string `json:"message,omitempty"`
}

func runPilotCheck(args []string) error {
	fs := flag.NewFlagSet("pilot-check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	offline := fs.Bool("offline", false, "Skip network identity verify (whoAmI)")
	sample := fs.Int("sample", diagnostics.DefaultVerifySample, "Max packs to sample-verify")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"profile": true, "sample": true})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if strings.TrimSpace(*profileFlag) == "" {
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

	ctx := context.Background()
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
	docRep, err := diagnostics.RunDoctor(ctx, docOpts)
	if err != nil {
		return err
	}

	cacheSt, err := diagnostics.RunCacheStatus(ctx, diagnostics.CacheStatusOptions{
		Profile: p,
		Paths:   &paths,
	})
	if err != nil {
		return err
	}

	verifyRep, verifyErr := diagnostics.RunCacheVerify(ctx, diagnostics.CacheVerifyOptions{
		Profile: p,
		Paths:   &paths,
		Full:    false,
		Sample:  *sample,
	})
	// verifyErr may be cancel/IO; still emit evidence.

	ev := pilotEvidence{
		Schema:      "jenkins-mcp.pilot-evidence.v1",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		ProfileID:   string(p.ID),
		Offline:     *offline,
		Version:     version,
		Commit:      commit,
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
		Doctor: doctorSnap{
			Overall: string(docRep.Overall),
			Checks:  docRep.Checks,
		},
		CacheStatus: cacheSnap{
			DataDirOK:     cacheSt.DataDirOK,
			StoreOpen:     cacheSt.StoreOpen,
			SchemaOK:      cacheSt.SchemaOK,
			SchemaVersion: cacheSt.SchemaVersion,
			Generations:   cacheSt.Generations,
			Chunks:        cacheSt.Chunks,
			Message:       redact.Secrets(cacheSt.StoreMessage),
		},
		CacheVerify: verifySnap{
			Mode:         verifyRep.Mode,
			PacksTotal:   verifyRep.PacksTotal,
			PacksChecked: verifyRep.PacksChecked,
			PackOK:       verifyRep.PackOK,
			PackFail:     verifyRep.PackFail,
			Message:      redact.Secrets(verifyRep.Message),
		},
		Notes: []string{
			"REL-001 pilot readiness evidence (doctor + cache status + sample verify)",
			"No secrets included; credentials stay in OS Secret Service",
			"Tier-1 pilot platforms: Rocky Linux and Ubuntu only (Windows out of scope)",
		},
	}

	// Overall: fail if doctor fail, cache schema/dir fail, or pack verify fail.
	overall := "pass"
	if docRep.Overall == diagnostics.StatusFail {
		overall = "fail"
	} else if docRep.Overall == diagnostics.StatusWarn && overall == "pass" {
		overall = "warn"
	}
	if !cacheSt.DataDirOK || !cacheSt.StoreOpen || !cacheSt.SchemaOK {
		overall = "fail"
		if cacheSt.DataDirMessage != "" {
			ev.Notes = append(ev.Notes, "cache: "+redact.Secrets(cacheSt.DataDirMessage))
		}
	}
	if verifyRep.PackFail > 0 || verifyErr != nil {
		overall = "fail"
		if verifyErr != nil {
			ev.Notes = append(ev.Notes, "verify: "+redact.Secrets(apperr.ModelMessage(verifyErr)))
		}
	}
	ev.Overall = overall

	// Human-readable summary first, then machine-readable JSON (no secrets).
	fmt.Fprintf(os.Stdout, "pilot-check profile=%s overall=%s offline=%v\n", ev.ProfileID, ev.Overall, ev.Offline)
	fmt.Fprintf(os.Stdout, "doctor: overall=%s checks=%d\n", ev.Doctor.Overall, len(ev.Doctor.Checks))
	fmt.Fprintf(os.Stdout, "cache:  dataDirOk=%v storeOpen=%v schemaOk=%v gens=%d chunks=%d\n",
		ev.CacheStatus.DataDirOK, ev.CacheStatus.StoreOpen, ev.CacheStatus.SchemaOK,
		ev.CacheStatus.Generations, ev.CacheStatus.Chunks)
	fmt.Fprintf(os.Stdout, "verify: mode=%s checked=%d ok=%d fail=%d total=%d\n",
		ev.CacheVerify.Mode, ev.CacheVerify.PacksChecked, ev.CacheVerify.PackOK,
		ev.CacheVerify.PackFail, ev.CacheVerify.PacksTotal)
	fmt.Fprintln(os.Stdout, "--- pilot evidence JSON (secret-free) ---")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(ev); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to encode pilot evidence", err)
	}

	if overall == "fail" {
		return apperr.New(apperr.CodeInternal, "pilot-check reported one or more failures")
	}
	return nil
}
