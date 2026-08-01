package diagnostics

import (
	"fmt"
	"io"
	"strings"
)

// FormatReportText writes a human-readable doctor report to w.
func FormatReportText(w io.Writer, rep Report) {
	fmt.Fprintf(w, "doctor profile=%s overall=%s\n", rep.ProfileID, rep.Overall)
	if rep.Version != "" {
		fmt.Fprintf(w, "version: %s commit=%s\n", rep.Version, rep.Commit)
	}
	for _, c := range rep.Checks {
		fmt.Fprintf(w, "[%s] %s: %s\n", strings.ToUpper(string(c.Status)), c.Name, c.Message)
		for k, v := range c.Details {
			fmt.Fprintf(w, "  %s: %v\n", k, v)
		}
	}
}

// FormatCacheStatusText writes cache status to w.
func FormatCacheStatusText(w io.Writer, st CacheStatus) {
	fmt.Fprintf(w, "cache status profile=%s\n", st.ProfileID)
	fmt.Fprintf(w, "dataDir:        %s\n", st.DataDir)
	fmt.Fprintf(w, "dataDirOk:      %v\n", st.DataDirOK)
	if st.DataDirMode != "" {
		fmt.Fprintf(w, "dataDirMode:    %s\n", st.DataDirMode)
	}
	if st.DataDirMessage != "" {
		fmt.Fprintf(w, "dataDirMessage: %s\n", st.DataDirMessage)
	}
	fmt.Fprintf(w, "storeOpen:      %v\n", st.StoreOpen)
	fmt.Fprintf(w, "schemaVersion:  %d\n", st.SchemaVersion)
	fmt.Fprintf(w, "expectedSchema: %d\n", st.ExpectedSchema)
	fmt.Fprintf(w, "schemaOk:       %v\n", st.SchemaOK)
	fmt.Fprintf(w, "generations:    %d\n", st.Generations)
	fmt.Fprintf(w, "chunks:         %d\n", st.Chunks)
	if st.StoreMessage != "" {
		fmt.Fprintf(w, "storeMessage:   %s\n", st.StoreMessage)
	}
	if st.Metrics != nil {
		fmt.Fprintf(w, "metrics.counters: %v\n", st.Metrics.Counters)
		fmt.Fprintf(w, "metrics.gauges:   %v\n", st.Metrics.Gauges)
	}
}

// FormatCacheVerifyText writes a support-safe verify report (ARC-008).
func FormatCacheVerifyText(w io.Writer, rep CacheVerifyReport) {
	fmt.Fprintf(w, "cache verify profile=%s mode=%s\n", rep.ProfileID, rep.Mode)
	fmt.Fprintf(w, "packsTotal:    %d\n", rep.PacksTotal)
	fmt.Fprintf(w, "packsChecked:  %d\n", rep.PacksChecked)
	fmt.Fprintf(w, "packOk:        %d\n", rep.PackOK)
	fmt.Fprintf(w, "packFail:      %d\n", rep.PackFail)
	if len(rep.IssueCounts) > 0 {
		// Stable key order for support diffs.
		for _, kind := range []string{"pack", "entry", "checksum", "catalog", "index"} {
			if n, ok := rep.IssueCounts[kind]; ok {
				fmt.Fprintf(w, "issues.%s:  %d\n", kind, n)
			}
		}
		for k, n := range rep.IssueCounts {
			switch k {
			case "pack", "entry", "checksum", "catalog", "index":
			default:
				fmt.Fprintf(w, "issues.%s:  %d\n", k, n)
			}
		}
	}
	if rep.Cancelled {
		fmt.Fprintf(w, "cancelled:     true\n")
	}
	if rep.Message != "" {
		fmt.Fprintf(w, "message:       %s\n", rep.Message)
	}
	for _, r := range rep.Results {
		fmt.Fprintf(w, "pack %s pack_ok=%v index_ok=%v trusted=%v rebuild=%v size=%d\n",
			r.PackID, r.PackOK, r.IndexOK, r.IndexTrusted, r.RebuildNeeded, r.SizeBytes)
		for _, iss := range r.Issues {
			fmt.Fprintf(w, "  [%s] %s\n", iss.Kind, iss.Message)
		}
		if r.Error != "" {
			fmt.Fprintf(w, "  error: %s\n", r.Error)
		}
		if r.Quarantined {
			fmt.Fprintf(w, "  quarantined: true\n")
		}
	}
}

// FormatCacheRepairText writes a support-safe repair report (ARC-008).
func FormatCacheRepairText(w io.Writer, rep CacheRepairReport) {
	fmt.Fprintf(w, "cache repair profile=%s index_only=%v\n", rep.ProfileID, rep.IndexOnly)
	fmt.Fprintf(w, "packsSeen:       %d\n", rep.PacksSeen)
	fmt.Fprintf(w, "indexesRebuilt:  %d\n", rep.IndexesRebuilt)
	fmt.Fprintf(w, "skipped:         %d\n", rep.Skipped)
	fmt.Fprintf(w, "failed:          %d\n", rep.Failed)
	if rep.Cancelled {
		fmt.Fprintf(w, "cancelled:       true\n")
	}
	for _, m := range rep.Messages {
		fmt.Fprintf(w, "  %s\n", m)
	}
}
