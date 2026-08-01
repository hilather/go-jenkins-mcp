package tools

import (
	"strconv"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
)

// Wave 38 / MCP-001: register absolute hard-max resolve canary with diagnostics.
// tools already imports diagnostics (doctor/diagnose); registration avoids a
// diagnostics → tools import cycle while keeping a single ResolveHardMaxBytes
// implementation as the source of truth.
func init() {
	diagnostics.RegisterHardMaxResolveCanary(hardMaxResolveCanary)
}

// hardMaxResolveCanary proves default resolve and AbsoluteMaxHardMaxBytes fail-closed
// (offline; secret-free). Control MCP-001 / Wave 38.
func hardMaxResolveCanary() diagnostics.SelfCheckItem {
	const name = "hard_max_resolve_residual"
	const control = "MCP-001"

	// Default bootstrap.
	n, err := ResolveHardMaxBytes("", "")
	if err != nil {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "ResolveHardMaxBytes default failed: " + err.Error(),
			Control: control,
		}
	}
	if n != DefaultHardMaxBytes {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "ResolveHardMaxBytes default mismatch",
			Control: control,
			Details: map[string]any{
				"got":                         n,
				"want":                        DefaultHardMaxBytes,
				"absolute_max_hard_max_bytes": AbsoluteMaxHardMaxBytes,
			},
		}
	}

	// At absolute cap must accept.
	atCap := strconv.Itoa(AbsoluteMaxHardMaxBytes)
	nCap, err := ResolveHardMaxBytes(atCap, "")
	if err != nil || nCap != AbsoluteMaxHardMaxBytes {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "ResolveHardMaxBytes at AbsoluteMaxHardMaxBytes must succeed",
			Control: control,
			Details: map[string]any{
				"absolute_max_hard_max_bytes": AbsoluteMaxHardMaxBytes,
			},
		}
	}

	// Above absolute cap must fail closed (flag and env).
	over := strconv.Itoa(AbsoluteMaxHardMaxBytes + 1)
	_, errFlag := ResolveHardMaxBytes(over, "")
	_, errEnv := ResolveHardMaxBytes("", over)
	if errFlag == nil || errEnv == nil {
		return diagnostics.SelfCheckItem{
			Name:    name,
			Status:  diagnostics.SelfCheckFail,
			Message: "ResolveHardMaxBytes accepted value above AbsoluteMaxHardMaxBytes (cap not enforced)",
			Control: control,
			Details: map[string]any{
				"absolute_max_hard_max_bytes": AbsoluteMaxHardMaxBytes,
				"flag_rejected":               errFlag != nil,
				"env_rejected":                errEnv != nil,
			},
		}
	}
	// Error text must mention hard max / maximum / bound; never secrets.
	for _, e := range []error{errFlag, errEnv} {
		msg := strings.ToLower(e.Error())
		if !strings.Contains(msg, "hard max") {
			return diagnostics.SelfCheckItem{
				Name:    name,
				Status:  diagnostics.SelfCheckFail,
				Message: "over-cap error missing hard max guidance",
				Control: control,
			}
		}
		if !strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute") {
			return diagnostics.SelfCheckItem{
				Name:    name,
				Status:  diagnostics.SelfCheckFail,
				Message: "over-cap error missing maximum/bound guidance",
				Control: control,
			}
		}
	}

	return diagnostics.SelfCheckItem{
		Name:    name,
		Status:  diagnostics.SelfCheckOK,
		Message: "hard max resolve enforces AbsoluteMaxHardMaxBytes; default resolves to DefaultHardMaxBytes",
		Control: control,
		Details: map[string]any{
			"default_hard_max_bytes":      DefaultHardMaxBytes,
			"absolute_max_hard_max_bytes": AbsoluteMaxHardMaxBytes,
			"default_ok":                  true,
			"at_cap_ok":                   true,
			"over_cap_flag_rejected":      true,
			"over_cap_env_rejected":       true,
		},
	}
}
