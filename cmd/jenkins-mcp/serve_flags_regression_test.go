package main

import (
	"flag"
	"reflect"
	"testing"
)

// Regression: the runServe reorder map was hand-maintained and missed 10
// value-taking flags (8 fleet + 2 cache quota). For those, a space-separated
// value was classified as a positional and moved to the end, after which
// flag.Parse made the flag swallow the NEXT flag token as its value —
// e.g. `serve --fleet-roster r.json --fleet-mode` parsed roster="--fleet-mode"
// and silently disabled fleet mode. The reorder set is now derived from the
// registered FlagSet (bool flags excluded via IsBoolFlag), so a newly added
// string flag can never be misclassified again.
func TestValueTakingFlags_DerivedFromFlagSet(t *testing.T) {
	t.Parallel()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("fleet-roster", "", "string flag")
	fs.String("cache-total-quota-bytes", "", "string flag")
	fs.Bool("fleet-mode", false, "bool flag")
	fs.Bool("read-only", false, "bool flag")

	got := valueTakingFlags(fs)
	want := map[string]bool{
		"fleet-roster":            true,
		"cache-total-quota-bytes": true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// The exact mis-parse from the bug report: string flag value followed by a
// bool flag must keep the value attached and leave the bool set.
func TestReorderFlagArgs_StringFlagBeforeBoolFlag(t *testing.T) {
	t.Parallel()
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	roster := fs.String("fleet-roster", "", "")
	member := fs.String("fleet-member-id", "", "")
	mode := fs.Bool("fleet-mode", false, "")

	args := []string{"--profile", "p", "--fleet-member-id", "m1", "--fleet-roster", "r.json", "--fleet-mode"}
	// profile is not registered here; emulate runServe's set plus profile.
	profile := fs.String("profile", "", "")
	if err := fs.Parse(reorderFlagArgs(args, valueTakingFlags(fs))); err != nil {
		t.Fatal(err)
	}
	if *member != "m1" || *roster != "r.json" || !*mode || *profile != "p" {
		t.Fatalf("member=%q roster=%q mode=%v profile=%q", *member, *roster, *mode, *profile)
	}
	if fs.NArg() != 0 {
		t.Fatalf("unexpected positionals: %v", fs.Args())
	}
}
