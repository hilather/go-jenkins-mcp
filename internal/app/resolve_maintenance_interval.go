package app

import (
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// ResolveMaintenanceInterval resolves the serve-time cache maintenance tick
// interval (ARC-007 / Wave 49 Track C).
//
// Precedence (later wins): DefaultMaintenanceInterval → envVal → flagVal.
// Empty / whitespace means unset at that layer.
//
// Rules (fail closed — never clamp silently):
//   - empty / whitespace at both layers → DefaultMaintenanceInterval (5m)
//   - unparseable Go duration → error
//   - ≤0 (including "0", "0s") → error
//   - < MinMaintenanceInterval (30s) → error
//   - > AbsoluteMaxMaintenanceInterval (1h) → error
//
// Messages are non-secret (no paths, tokens, or raw env dumps beyond the
// operator-supplied duration string already known to the caller).
func ResolveMaintenanceInterval(flagVal, envVal string) (time.Duration, error) {
	d := DefaultMaintenanceInterval
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseMaintenanceIntervalValue(raw, "env "+EnvCacheMaintenanceInterval)
		if err != nil {
			return 0, err
		}
		d = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseMaintenanceIntervalValue(raw, "flag --cache-maintenance-interval")
		if err != nil {
			return 0, err
		}
		d = v
	}
	// Defense-in-depth if constants drift outside the allowed window.
	if d < MinMaintenanceInterval || d > AbsoluteMaxMaintenanceInterval {
		return 0, apperr.New(apperr.CodeInternal,
			"resolved cache-maintenance-interval is outside absolute bounds")
	}
	return d, nil
}

func parseMaintenanceIntervalValue(raw, source string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid cache-maintenance-interval from "+source+
				" (use Go duration, e.g. 5m; min "+MinMaintenanceInterval.String()+
				" max "+AbsoluteMaxMaintenanceInterval.String()+"): "+raw)
	}
	if d <= 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"cache-maintenance-interval from "+source+" must be positive")
	}
	if d < MinMaintenanceInterval {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"cache-maintenance-interval from "+source+" is below minimum "+
				MinMaintenanceInterval.String()+" (got "+d.String()+")")
	}
	if d > AbsoluteMaxMaintenanceInterval {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"cache-maintenance-interval from "+source+" exceeds absolute maximum "+
				AbsoluteMaxMaintenanceInterval.String()+" (got "+d.String()+")")
	}
	return d, nil
}
