package fleetmcp

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// CachePathPrefix is the dedicated peer cache surface (not ops JSON fan-out).
const CachePathPrefix = "/fleet/cache/v1"

// PeerMuxOptions extends the fleet peer mux with optional cache lookup/read/frame routes (FLC-030…032, FLC-022).
type PeerMuxOptions struct {
	// Catalog when non-nil registers owner-directed HEAD/GET manifest routes.
	Catalog ManifestCatalog
	// DecodedRead when non-nil (with AssertionAuth.Key) registers POST decoded read.
	DecodedRead DecodedReadBackend
	// FrameExport when non-nil (with AssertionAuth.Key) registers GET pure-zstd frame export (FLC-022).
	FrameExport FrameExportBackend
	// FrameAdmission caps concurrent frame exports (nil → DefaultMaxPeerStreams on first use).
	FrameAdmission *fleetcache.StreamAdmission
	// AssertionAuth is required for DecodedRead / FrameExport (HMAC key + nonces).
	AssertionAuth AssertionAuth
}

// NewPeerMuxWithOptions returns ops + optional cache lookup/read/frame handlers.
func NewPeerMuxWithOptions(cfg Config, local *LocalProvider, opts PeerMuxOptions) http.Handler {
	mux := http.NewServeMux()
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !meshTokenOK(r.Header.Get(MeshTokenHeader), cfg.MeshToken) {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	handle := func(c Collection) http.HandlerFunc {
		return auth(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			payload, err := local.SnapshotLocal(r.Context(), c)
			if err != nil {
				http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
				return
			}
			write(w, payload)
		})
	}
	mux.HandleFunc(PeerPathPrefix+"/health", handle(CollectionHealth))
	mux.HandleFunc(PeerPathPrefix+"/version", handle(CollectionVersion))
	mux.HandleFunc(PeerPathPrefix+"/metrics", handle(CollectionMetrics))
	mux.HandleFunc(PeerPathPrefix+"/residual-status", handle(CollectionResidual))
	mux.HandleFunc(PeerPathPrefix+"/doctor", handle(CollectionDoctor))
	mux.HandleFunc(PeerPathPrefix+"/cache-status", handle(CollectionCache))
	mux.HandleFunc(PeerPathPrefix+"/member", auth(func(w http.ResponseWriter, r *http.Request) {
		self := cfg.Roster.MemberByID(cfg.MemberID)
		out := map[string]any{
			"id":         cfg.MemberID,
			"fleet_id":   cfg.Roster.FleetID,
			"bundle_seq": cfg.Roster.BundleSeq,
		}
		if self != nil {
			out["profile_id"] = self.ProfileID
			out["display_name"] = self.DisplayName
		}
		write(w, out)
	}))

	needCache := opts.Catalog != nil ||
		(opts.DecodedRead != nil && len(opts.AssertionAuth.Key) >= 16) ||
		(opts.FrameExport != nil && len(opts.AssertionAuth.Key) >= 16)
	if needCache {
		registerCacheRoutes(mux, cfg, opts.Catalog, opts.DecodedRead, opts.FrameExport, opts.FrameAdmission, opts.AssertionAuth, auth, write)
	}
	return mux
}

// ManifestPath builds the peer path for a locator hash.
func ManifestPath(locatorHash string) string {
	return CachePathPrefix + "/objects/" + strings.ToLower(strings.TrimSpace(locatorHash)) + "/manifest"
}
