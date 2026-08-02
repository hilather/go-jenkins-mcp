package fleetmcp

import (
	"net"
	"net/url"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// PeerURLOptions controls transport identity fail-closed rules (FLC-016).
type PeerURLOptions struct {
	// AllowInsecureHTTP permits http:// for non-loopback peers (lab residual only).
	// Default false: non-loopback peers must use https.
	AllowInsecureHTTP bool
}

// TrustResidual describes pilot vs production peer identity (secret-free).
type TrustResidual struct {
	// MeshTokenPilot is true when fleet-wide mesh token is the only peer auth.
	MeshTokenPilot bool
	// UniqueNodeIdentity is false until mTLS or per-node signing lands.
	UniqueNodeIdentity bool
	// Residual human-readable note (no secrets).
	Residual string
}

// DefaultTrustResidual is the honest pilot posture (mesh token; not unique node identity).
func DefaultTrustResidual() TrustResidual {
	return TrustResidual{
		MeshTokenPilot:     true,
		UniqueNodeIdentity: false,
		Residual:           "pilot mesh-token peer auth; production unique node identity (mTLS/signing) residual (FLC-016)",
	}
}

// ValidatePeerURLTransport enforces scheme/host rules for peer cache/ops transport.
// Loopback may use http for lab; non-loopback requires https unless AllowInsecureHTTP.
// Credentials in URLs remain rejected (secret-free roster).
func ValidatePeerURLTransport(raw string, opts PeerURLOptions) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return apperr.New(apperr.CodeInvalidArgument, "roster member peer_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return apperr.New(apperr.CodeInvalidArgument, "roster member peer_url is invalid")
	}
	if u.User != nil {
		return apperr.New(apperr.CodeInvalidArgument, "roster member peer_url must not contain credentials")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return apperr.New(apperr.CodeInvalidArgument, "roster member peer_url must be http or https")
	}
	host := u.Hostname()
	if host == "" {
		return apperr.New(apperr.CodeInvalidArgument, "roster member peer_url host is required")
	}
	if scheme == "http" && !isLoopbackHost(host) && !opts.AllowInsecureHTTP {
		return apperr.New(apperr.CodeInvalidArgument,
			"non-loopback peer_url requires https (set lab allow-insecure only for local residual)")
	}
	return nil
}

// ValidateRosterTransport applies ValidatePeerURLTransport to every member.
func ValidateRosterTransport(r *Roster, opts PeerURLOptions) error {
	if r == nil {
		return apperr.New(apperr.CodeInvalidArgument, "fleet roster is nil")
	}
	for i := range r.Members {
		if err := ValidatePeerURLTransport(r.Members[i].PeerURL, opts); err != nil {
			return err
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]" {
		return true
	}
	ip := net.ParseIP(h)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}
