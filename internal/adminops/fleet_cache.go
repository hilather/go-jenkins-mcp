package adminops

import (
	"context"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// ConfirmPURGE matches fleetcache.PurgeConfirmToken / BFF body.confirm.
const ConfirmPURGE = fleetcache.PurgeConfirmToken // "PURGE"

// FleetCacheStatus returns secret-free process-local fleet-cache status (FLC-063).
// Mode still defaults off via ResolveConfig. Viewer+.
func (s *Service) FleetCacheStatus(_ context.Context) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return nil, err
	}
	cfg, err := s.resolveFleetCacheConfig()
	if err != nil {
		return nil, err
	}
	// Process-local: empty member views; multi-member aggregation residual.
	return fleetcache.StatusSnapshot(cfg, nil, nil, fleetcache.StatusOptions{}), nil
}

// FleetCacheDoctor returns secret-free doctor checks + nested status (FLC-063).
// Viewer+.
func (s *Service) FleetCacheDoctor(_ context.Context) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return nil, err
	}
	cfg, err := s.resolveFleetCacheConfig()
	if err != nil {
		return nil, err
	}
	return fleetcache.DoctorSnapshot(cfg, nil, nil, fleetcache.StatusOptions{}), nil
}

// FleetCachePurgeArgs is the MCP/admin purge input (secret-free fields only).
type FleetCachePurgeArgs struct {
	// Confirm must be exactly "PURGE".
	Confirm string
	// LocatorHash is the sealed object locator (required).
	LocatorHash string
	// ManifestDigest optional version scope.
	ManifestDigest string
	// MaxOwners optional bound (0 → library default).
	MaxOwners int
	// Reason secret-free operator note (scrubbed by library).
	Reason string
	// ProfileID optional audit correlation only (not a secret).
	ProfileID string
}

// FleetCachePurge applies a confirm-gated process-local fleet-cache purge (FLC-063).
// Requires PermCacheDestructive (operator). Confirm must be PURGE.
// Multi-member HTTP peer purge remains residual; tombstones are process-local.
func (s *Service) FleetCachePurge(ctx context.Context, args FleetCachePurgeArgs) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermCacheDestructive); err != nil {
		return nil, err
	}
	if strings.TrimSpace(args.Confirm) != ConfirmPURGE {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"fleet-cache purge requires confirm="+ConfirmPURGE)
	}
	role := string(s.Role())
	// Library accepts operator|policy_admin; console destructive is operator-only
	// (PermCacheDestructive). Map policy_admin if ever granted cache_destructive.
	if role != fleetcache.PurgeRoleOperator && role != fleetcache.PurgeRolePolicyAdmin {
		return nil, apperr.New(apperr.CodeAuthorization,
			"fleet-cache purge requires operator role")
	}

	out, err := fleetcache.AdminPurge(ctx, fleetcache.AdminPurgeOptions{
		Role:           role,
		Confirm:        ConfirmPURGE,
		LocatorHash:    args.LocatorHash,
		ManifestDigest: args.ManifestDigest,
		MaxOwners:      args.MaxOwners,
		Reason:         args.Reason,
		LocalOnly:      true,
	})
	profileID := s.profileID(args.ProfileID)
	dec := audit.DecisionSuccess
	reason := "confirm_PURGE"
	if err != nil {
		dec = audit.DecisionFail
		if out != nil {
			if r, ok := out["residual"].(string); ok && r != "" {
				reason = r
			}
		} else {
			reason = "purge_denied"
		}
	}
	s.emitWriteAudit(profileID, audit.TypeAdminFleetCachePurge, "fleet_cache_purge", dec, reason)
	if err != nil {
		return out, err
	}
	return out, nil
}

func (s *Service) resolveFleetCacheConfig() (fleetcache.Config, error) {
	return fleetcache.ResolveConfig(fleetcache.ResolveOptions{
		Getenv: s.getenv,
	})
}
