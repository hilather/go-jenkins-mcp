package fleetmcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// PeerPathPrefix is the dedicated peer HTTP surface (not admin BFF).
const PeerPathPrefix = "/fleet/v1"

// PeerFetcher fetches one collection from a peer (injectable for tests).
type PeerFetcher interface {
	Fetch(ctx context.Context, peer RosterMember, collection Collection) (payload any, latency time.Duration, err error)
}

// HTTPPeerFetcher implements PeerFetcher over HTTP with mesh-token auth.
type HTTPPeerFetcher struct {
	Client    *http.Client
	MeshToken string
	Timeout   time.Duration
}

// Fetch GETs peer_url + /fleet/v1/{collection}.
func (f *HTTPPeerFetcher) Fetch(ctx context.Context, peer RosterMember, collection Collection) (any, time.Duration, error) {
	if f == nil || strings.TrimSpace(f.MeshToken) == "" {
		return nil, 0, apperr.New(apperr.CodePolicyDenial, "fleet peer fetch requires mesh token")
	}
	base := strings.TrimRight(strings.TrimSpace(peer.PeerURL), "/")
	path := collectionPath(collection)
	if path == "" {
		return nil, 0, apperr.New(apperr.CodeInvalidArgument, "unknown fleet collection")
	}
	u := base + PeerPathPrefix + path
	to := f.Timeout
	if to <= 0 {
		to = DefaultPeerTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, apperr.Wrap(apperr.CodeInvalidArgument, "build peer request", err)
	}
	req.Header.Set(MeshTokenHeader, f.MeshToken)
	req.Header.Set("Accept", "application/json")
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: to}
	}
	start := time.Now()
	res, err := client.Do(req)
	lat := time.Since(start)
	if err != nil {
		if reqCtx.Err() != nil {
			return nil, lat, apperr.New(apperr.CodeTimeout, "peer timeout")
		}
		return nil, lat, apperr.Wrap(apperr.CodeUpstreamProtocol, "peer request failed", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, lat, apperr.Wrap(apperr.CodeUpstreamProtocol, "peer body read failed", err)
	}
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return nil, lat, apperr.New(apperr.CodeAuthorization, "peer auth failed")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, lat, apperr.New(apperr.CodeUpstreamProtocol, "peer HTTP error")
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, lat, apperr.New(apperr.CodeUpstreamProtocol, "peer JSON invalid")
	}
	return payload, lat, nil
}

func collectionPath(c Collection) string {
	switch c {
	case CollectionHealth:
		return "/health"
	case CollectionVersion:
		return "/version"
	case CollectionMetrics:
		return "/metrics"
	case CollectionResidual:
		return "/residual-status"
	case CollectionDoctor:
		return "/doctor"
	case CollectionCache:
		return "/cache-status"
	case CollectionMembers:
		return "/member"
	default:
		return ""
	}
}

// NewPeerMux returns an http.Handler for /fleet/v1/* using LocalProvider + mesh token auth.
func NewPeerMux(cfg Config, local *LocalProvider) http.Handler {
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
		enc := json.NewEncoder(w)
		_ = enc.Encode(v)
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
	return mux
}

func meshTokenOK(got, want string) bool {
	got = strings.TrimSpace(got)
	want = strings.TrimSpace(want)
	if want == "" || got == "" {
		return false
	}
	// Constant-time compare for small tokens.
	if len(got) != len(want) {
		return false
	}
	var v byte
	for i := 0; i < len(want); i++ {
		v |= got[i] ^ want[i]
	}
	return v == 0
}

// FanOut runs local + peer fetches for a collection.
// Peer hosts come only from roster (never from tool args).
func FanOut(ctx context.Context, cfg Config, local *LocalProvider, peers PeerFetcher, collection Collection) AggregateEnvelope {
	if !cfg.Enabled || cfg.Roster == nil {
		return BuildEnvelope(cfg, collection, nil, nil)
	}
	overall := cfg.Overall
	if overall <= 0 {
		overall = DefaultOverallTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, overall)
	defer cancel()

	var members []MemberResult
	var mu sync.Mutex
	add := func(m MemberResult) {
		mu.Lock()
		members = append(members, m)
		mu.Unlock()
	}

	// Local first (deterministic order start).
	start := time.Now()
	payload, err := local.SnapshotLocal(ctx, collection)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		add(MemberResult{
			ID:        cfg.MemberID,
			Source:    "local",
			OK:        false,
			LatencyMS: lat,
			ErrorCode: "local_error",
			Residual:  "local snapshot failed",
		})
	} else {
		add(MemberResult{
			ID:        cfg.MemberID,
			Source:    "local",
			OK:        true,
			LatencyMS: lat,
			Payload:   payload,
		})
	}

	peerList := cfg.Roster.PeerMembers(cfg.MemberID)
	maxP := cfg.MaxParallel
	if maxP <= 0 {
		maxP = DefaultMaxPeerParallel
	}
	sem := make(chan struct{}, maxP)
	var wg sync.WaitGroup
	for _, peer := range peerList {
		peer := peer
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				add(MemberResult{
					ID:        peer.ID,
					Source:    "peer",
					OK:        false,
					ErrorCode: "cancelled",
					Residual:  "fan-out budget exhausted",
				})
				return
			}
			if peers == nil {
				add(MemberResult{
					ID:        peer.ID,
					Source:    "peer",
					OK:        false,
					ErrorCode: "no_fetcher",
					Residual:  "peer fetcher not configured",
				})
				return
			}
			pl, d, ferr := peers.Fetch(ctx, peer, collection)
			if ferr != nil {
				code := "peer_error"
				msg := "peer unreachable or failed"
				switch apperr.CodeOf(ferr) {
				case apperr.CodeTimeout:
					code = "timeout"
					msg = "peer unreachable within deadline"
				case apperr.CodeAuthorization:
					code = "auth_failed"
					msg = "peer auth failed"
				}
				add(MemberResult{
					ID:        peer.ID,
					Source:    "peer",
					OK:        false,
					LatencyMS: d.Milliseconds(),
					ErrorCode: code,
					Residual:  msg,
				})
				return
			}
			add(MemberResult{
				ID:        peer.ID,
				Source:    "peer",
				OK:        true,
				LatencyMS: d.Milliseconds(),
				Payload:   pl,
			})
		}()
	}
	wg.Wait()

	// Stable order: roster order.
	byID := make(map[string]MemberResult, len(members))
	for _, m := range members {
		byID[m.ID] = m
	}
	ordered := make([]MemberResult, 0, len(cfg.Roster.Members))
	for _, rm := range cfg.Roster.Members {
		if m, ok := byID[rm.ID]; ok {
			ordered = append(ordered, m)
		}
	}

	var agg map[string]any
	if collection == CollectionMetrics {
		if sums := SumAllowlistedCounters(ordered); len(sums) > 0 {
			agg = map[string]any{
				"allowlisted_counter_sums": sums,
				"residual":                 "sums are process-local counter totals across reachable members only; restarts reset counters",
			}
		}
	}
	return BuildEnvelope(cfg, collection, ordered, agg)
}
