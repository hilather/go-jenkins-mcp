package store

import (
	"strconv"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Operator env keys for per-profile physical cache quota (ARC-007).
// Flag values win over env when both set; empty/0 at a layer means product default.
const (
	EnvCacheTotalQuotaBytes = "JENKINS_MCP_CACHE_TOTAL_QUOTA_BYTES"
	EnvCacheLowDiskBytes    = "JENKINS_MCP_CACHE_LOW_DISK_BYTES"
)

// Absolute bounds for operator-resolved quota (fail closed — never silent clamp).
const (
	// MinTotalQuotaBytes is the smallest explicit total quota operators may set (64 MiB).
	MinTotalQuotaBytes int64 = 64 << 20
	// AbsoluteMaxTotalQuotaBytes is the largest total quota (1 TiB).
	AbsoluteMaxTotalQuotaBytes int64 = 1 << 40
	// MinLowDiskBytes is the smallest explicit free-space threshold (16 MiB).
	MinLowDiskBytes int64 = 16 << 20
	// AbsoluteMaxLowDiskBytes matches total max (1 TiB).
	AbsoluteMaxLowDiskBytes int64 = AbsoluteMaxTotalQuotaBytes
)

// ResolveQuotaConfig resolves TotalQuotaBytes and LowDiskBytes for QuotaManager.
//
// Precedence (later wins): default → envVal → flagVal per field independently.
// Empty / whitespace / explicit "0" means product default at that layer
// (DefaultTotalQuotaBytes / DefaultLowDiskBytes).
//
// Rules (fail closed — never clamp silently):
//   - empty/0 at both layers → product defaults (10 GiB total, 1 GiB low-disk)
//   - unparseable integer → error
//   - negative → error
//   - explicit positive below Min* → error
//   - above AbsoluteMax* → error
//
// DiskFree and retention fields are left zero/nil; callers set DiskFree if needed.
// Messages are non-secret (no paths or tokens).
func ResolveQuotaConfig(flagTotal, envTotal, flagLow, envLow string) (QuotaConfig, error) {
	total, err := resolveQuotaBytesField(
		flagTotal, envTotal,
		DefaultTotalQuotaBytes, MinTotalQuotaBytes, AbsoluteMaxTotalQuotaBytes,
		"cache-total-quota-bytes", EnvCacheTotalQuotaBytes, "--cache-total-quota-bytes",
	)
	if err != nil {
		return QuotaConfig{}, err
	}
	low, err := resolveQuotaBytesField(
		flagLow, envLow,
		DefaultLowDiskBytes, MinLowDiskBytes, AbsoluteMaxLowDiskBytes,
		"cache-low-disk-bytes", EnvCacheLowDiskBytes, "--cache-low-disk-bytes",
	)
	if err != nil {
		return QuotaConfig{}, err
	}
	return QuotaConfig{
		TotalQuotaBytes: total,
		LowDiskBytes:    low,
	}, nil
}

// ResolveQuotaConfigFromEnviron is ResolveQuotaConfig with empty flags (env + defaults only).
// Used by offline CLI when no per-invocation flags are set and by admin BFF/MCP ops.
func ResolveQuotaConfigFromEnviron(envTotal, envLow string) (QuotaConfig, error) {
	return ResolveQuotaConfig("", envTotal, "", envLow)
}

func resolveQuotaBytesField(
	flagVal, envVal string,
	def, min, absMax int64,
	fieldName, envName, flagName string,
) (int64, error) {
	v := def
	if raw := strings.TrimSpace(envVal); raw != "" {
		n, err := parseQuotaBytesValue(raw, "env "+envName, fieldName, def, min, absMax)
		if err != nil {
			return 0, err
		}
		v = n
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		n, err := parseQuotaBytesValue(raw, "flag "+flagName, fieldName, def, min, absMax)
		if err != nil {
			return 0, err
		}
		v = n
	}
	// Defense-in-depth if defaults drift outside the window.
	if v < min || v > absMax {
		return 0, apperr.New(apperr.CodeInternal,
			"resolved "+fieldName+" is outside absolute bounds")
	}
	return v, nil
}

func parseQuotaBytesValue(raw, source, fieldName string, def, min, absMax int64) (int64, error) {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid "+fieldName+" from "+source+
				" (use integer bytes; empty/0=default; min "+
				strconv.FormatInt(min, 10)+" max "+strconv.FormatInt(absMax, 10)+"): "+raw)
	}
	if n < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			fieldName+" from "+source+" must be non-negative")
	}
	// Explicit 0 ⇒ product default (plan: empty/0 keeps today's defaults).
	if n == 0 {
		return def, nil
	}
	if n < min {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			fieldName+" from "+source+" is below minimum "+
				strconv.FormatInt(min, 10)+" (got "+strconv.FormatInt(n, 10)+")")
	}
	if n > absMax {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			fieldName+" from "+source+" exceeds absolute maximum "+
				strconv.FormatInt(absMax, 10)+" (got "+strconv.FormatInt(n, 10)+")")
	}
	return n, nil
}
