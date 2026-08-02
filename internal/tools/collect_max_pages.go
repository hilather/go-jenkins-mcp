package tools

import (
	"strconv"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// ResolveCollectMaxPages resolves a policy-collect safety page cap shared by
// list_jobs, get_nodes, and list_views (Wave 41/42).
//
// Precedence (later wins): defaultN → envVal → flagVal.
// Empty / whitespace means unset at that layer. Positive integers are accepted.
// Zero (explicit "0") at the winning layer means defaultN.
// Negative or non-integer values fail closed (error); never clamp silently.
// After resolve, n must be ≤ absoluteMax; oversize values error with a collect
// max pages / maximum / bound message (no secrets).
//
// envName and flagName appear only in non-secret error messages (e.g.
// "JENKINS_MCP_NODES_COLLECT_MAX_PAGES", "--nodes-collect-max-pages").
// label is a short resource name for messages ("list_jobs", "nodes", "views").
func ResolveCollectMaxPages(flagVal, envVal string, defaultN, absoluteMax int, envName, flagName, label string) (int, error) {
	if label == "" {
		label = "collect"
	}
	n := defaultN
	if raw := strings.TrimSpace(envVal); raw != "" {
		src := "env"
		if envName != "" {
			src = "env " + envName
		}
		v, err := parseCollectMaxPagesValue(raw, src, label, defaultN)
		if err != nil {
			return 0, err
		}
		n = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		src := "flag"
		if flagName != "" {
			src = "flag " + flagName
		}
		v, err := parseCollectMaxPagesValue(raw, src, label, defaultN)
		if err != nil {
			return 0, err
		}
		n = v
	}
	if n > absoluteMax {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			label+" collect max pages exceeds absolute maximum bound ("+
				strconv.Itoa(absoluteMax)+")")
	}
	return n, nil
}

func parseCollectMaxPagesValue(raw, source, label string, defaultN int) (int, error) {
	v, err := strconv.ParseInt(raw, 10, 0)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid "+label+" collect max pages from "+source+" (positive integer, or 0 for default): "+raw)
	}
	if v < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			label+" collect max pages from "+source+" must not be negative")
	}
	if v == 0 {
		return defaultN, nil
	}
	return int(v), nil
}

// clampCollectMaxPages applies Set* belt-and-suspenders: non-positive → defaultN;
// oversize → absoluteMax. Resolve already fail-closed over absolute.
func clampCollectMaxPages(n, defaultN, absoluteMax int) int {
	if n <= 0 {
		return defaultN
	}
	if n > absoluteMax {
		return absoluteMax
	}
	return n
}
