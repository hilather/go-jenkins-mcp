package fleetmcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// ManifestLookupClient performs owner-directed HEAD/GET manifest lookups (FLC-030).
// Contacts only the provided owner set — never full-roster broadcast.
type ManifestLookupClient struct {
	Client    *http.Client
	MeshToken string
	Timeout   time.Duration
	// Mode is fleet-cache mode (off|shadow|read|full). Empty treated as off for safety
	// when unset by callers that forgot to wire config (fail closed: no peer I/O).
	// Lookup runs only for ModeRead and ModeFull. ModeOff/ModeShadow skip peers.
	Mode fleetcache.Mode
}

// LookupOwners queries each OwnerContact in order until a verified hit or exhaustion.
// When Mode is off (or empty) or shadow, returns LookupModeOff without contacting peers.
func (c *ManifestLookupClient) LookupOwners(ctx context.Context, fleetID, locatorHash string, owners []fleetcache.OwnerContact, originFallback bool) (fleetcache.LookupResult, error) {
	if c == nil {
		return fleetcache.LookupResult{
			Status:                    fleetcache.LookupModeOff,
			Residual:                  "lookup client nil; origin fallback recommended",
			OriginFallbackRecommended: true,
		}, nil
	}
	mode := c.Mode
	if mode == "" {
		mode = fleetcache.ModeOff
	}
	if mode == fleetcache.ModeOff || mode == fleetcache.ModeShadow {
		return fleetcache.LookupResult{
			Status:                    fleetcache.LookupModeOff,
			Residual:                  "fleet-cache mode off or shadow; peer lookup skipped",
			OriginFallbackRecommended: originFallback || mode == fleetcache.ModeOff,
		}, nil
	}
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	if len(locatorHash) != 64 {
		return fleetcache.LookupResult{Status: fleetcache.LookupInvalidLocator},
			apperr.New(apperr.CodeInvalidArgument, "locator_hash invalid")
	}
	if strings.TrimSpace(c.MeshToken) == "" {
		return fleetcache.LookupResult{Status: fleetcache.LookupPartial, Residual: "lookup client not configured", OriginFallbackRecommended: true},
			apperr.New(apperr.CodePolicyDenial, "manifest lookup requires mesh token")
	}
	to := c.Timeout
	if to <= 0 {
		to = DefaultPeerTimeout
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: to}
	}
	var peers []fleetcache.PeerManifestResult
	for _, o := range owners {
		pr := fleetcache.PeerManifestResult{MemberID: o.MemberID}
		if strings.TrimSpace(o.PeerURL) == "" {
			pr.OK = false
			pr.ErrorCode = "no_url"
			pr.Residual = "owner peer_url missing"
			peers = append(peers, pr)
			continue
		}
		base := strings.TrimRight(strings.TrimSpace(o.PeerURL), "/")
		u := base + ManifestPath(locatorHash)
		reqCtx, cancel := context.WithTimeout(ctx, to)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
		if err != nil {
			cancel()
			pr.OK = false
			pr.ErrorCode = "request"
			pr.Residual = "build request failed"
			peers = append(peers, pr)
			continue
		}
		req.Header.Set(MeshTokenHeader, c.MeshToken)
		req.Header.Set("Accept", "application/json")
		res, err := client.Do(req)
		if err != nil {
			cancel()
			pr.OK = false
			if reqCtx.Err() != nil {
				pr.ErrorCode = "timeout"
				pr.Residual = "peer timeout"
			} else {
				pr.ErrorCode = "peer_error"
				pr.Residual = "peer unreachable"
			}
			peers = append(peers, pr)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, fleetcache.MaxWireManifestBytes+4096))
		_ = res.Body.Close()
		cancel()
		if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
			pr.OK = false
			pr.ErrorCode = "auth_failed"
			pr.Residual = "peer auth failed"
			peers = append(peers, pr)
			continue
		}
		if res.StatusCode == http.StatusNotFound {
			pr.OK = true
			pr.Hit = false
			peers = append(peers, pr)
			continue
		}
		if res.StatusCode == http.StatusConflict {
			pr.OK = false
			pr.ErrorCode = "wrong_fleet"
			pr.Residual = "peer wrong fleet"
			peers = append(peers, pr)
			continue
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			pr.OK = false
			pr.ErrorCode = "http_error"
			pr.Residual = "peer HTTP error"
			peers = append(peers, pr)
			continue
		}
		var wrap struct {
			Hit      bool                     `json:"hit"`
			Manifest *fleetcache.WireManifest `json:"manifest"`
		}
		if err := json.Unmarshal(body, &wrap); err != nil {
			pr.OK = false
			pr.ErrorCode = "protocol"
			pr.Residual = "invalid peer JSON"
			peers = append(peers, pr)
			continue
		}
		pr.OK = true
		pr.Hit = wrap.Hit && wrap.Manifest != nil
		if pr.Hit {
			pr.Manifest = wrap.Manifest
		}
		peers = append(peers, pr)
	}
	return fleetcache.MergeOwnerManifestResults(locatorHash, fleetID, owners, peers, originFallback)
}
