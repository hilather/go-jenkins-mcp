package fleetmcp

import (
	"encoding/json"
	"net/http"
	"strings"
)

// CachePathPrefix is the dedicated peer cache surface (not ops JSON fan-out).
const CachePathPrefix = "/fleet/cache/v1"

// PeerMuxOptions extends the fleet peer mux with optional cache lookup routes (FLC-030).
type PeerMuxOptions struct {
	// Catalog when non-nil registers owner-directed HEAD/GET manifest routes.
	Catalog ManifestCatalog
}

// NewPeerMuxWithOptions returns ops + optional cache lookup handlers.
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

	if opts.Catalog != nil {
		registerCacheLookupRoutes(mux, cfg, opts.Catalog, auth, write)
	}
	return mux
}

func registerCacheLookupRoutes(mux *http.ServeMux, cfg Config, cat ManifestCatalog, auth func(http.HandlerFunc) http.HandlerFunc, write func(http.ResponseWriter, any)) {
	// Pattern: /fleet/cache/v1/objects/{locator_hash}/manifest
	// Go 1.22+ ServeMux wildcards; also support path trim for older style via prefix handler.
	mux.HandleFunc(CachePathPrefix+"/objects/", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		// path: /fleet/cache/v1/objects/<hash>/manifest
		rest := strings.TrimPrefix(r.URL.Path, CachePathPrefix+"/objects/")
		parts := strings.Split(strings.Trim(rest, "/"), "/")
		if len(parts) != 2 || parts[1] != "manifest" {
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
			return
		}
		lh := strings.ToLower(strings.TrimSpace(parts[0]))
		if len(lh) != 64 {
			http.Error(w, `{"error":"invalid_locator"}`, http.StatusBadRequest)
			return
		}
		m, ok := cat.Get(lh)
		if !ok {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			write(w, map[string]any{"hit": false, "locator_hash": lh})
			return
		}
		// Wrong fleet residual: catalog is local; still stamp fleet id from config when set.
		if cfg.Roster != nil && cfg.Roster.FleetID != "" && m.FleetID != "" && m.FleetID != cfg.Roster.FleetID {
			http.Error(w, `{"error":"wrong_fleet"}`, http.StatusConflict)
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("X-Fleet-Cache-Hit", "1")
			w.Header().Set("X-Fleet-Locator-Hash", lh)
			if m.ManifestDigest != "" {
				w.Header().Set("X-Fleet-Manifest-Digest", m.ManifestDigest)
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		write(w, map[string]any{
			"hit":      true,
			"manifest": m,
		})
	}))
}

// ManifestPath builds the peer path for a locator hash.
func ManifestPath(locatorHash string) string {
	return CachePathPrefix + "/objects/" + strings.ToLower(strings.TrimSpace(locatorHash)) + "/manifest"
}
