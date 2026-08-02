package fleetmcp

import (
	"os"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Env keys for fleet mode (operator).
const (
	EnvFleetMode       = "JENKINS_MCP_FLEET_MODE"
	EnvFleetMemberID   = "JENKINS_MCP_FLEET_MEMBER_ID"
	EnvFleetRoster     = "JENKINS_MCP_FLEET_ROSTER"
	EnvFleetMeshToken  = "JENKINS_MCP_FLEET_MESH_TOKEN"
	EnvFleetPeerListen = "JENKINS_MCP_FLEET_PEER_LISTEN"
)

// MeshTokenHeader is the HTTP header peers and coordinators use for mesh-token auth.
const MeshTokenHeader = "X-Jenkins-MCP-Fleet-Token"

// Default budgets for fan-out.
const (
	DefaultPeerTimeout     = 2 * time.Second
	DefaultOverallTimeout  = 5 * time.Second
	DefaultMaxPeerParallel = 8
)

// Config is a fully resolved fleet mode configuration (fail closed if invalid).
type Config struct {
	Enabled     bool
	MemberID    string
	Roster      *Roster
	MeshToken   string // non-empty when trust configured (never log raw)
	PeerListen  string // optional peer HTTP bind (e.g. 127.0.0.1:9443)
	PeerTimeout time.Duration
	Overall     time.Duration
	MaxParallel int
	// TrustConfigured is true when mesh token (or future mTLS) is present.
	TrustConfigured bool
}

// ResolveOptions are operator inputs for ResolveConfig.
type ResolveOptions struct {
	// ModeFlag empty → env JENKINS_MCP_FLEET_MODE; truthy enables attempt.
	ModeFlag string
	// MemberID flag wins over env.
	MemberIDFlag string
	// RosterPath flag wins over env.
	RosterPathFlag string
	// MeshTokenFile path to token file (0600 expected); or MeshTokenEnv value.
	MeshTokenFile string
	// MeshTokenInline for tests only (never log); empty → read file/env.
	MeshTokenInline string
	// PeerListen optional.
	PeerListenFlag string
	// Getenv optional (default os.Getenv).
	Getenv func(string) string
	// ReadFile optional (default os.ReadFile).
	ReadFile func(string) ([]byte, error)
}

// ResolveConfig fails closed: returns Enabled=false and error reason when incomplete.
// When mode is off, returns Enabled=false, nil error (not an error to be off).
func ResolveConfig(opts ResolveOptions) (Config, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	readFile := opts.ReadFile
	if readFile == nil {
		readFile = os.ReadFile
	}

	modeOn := truthy(firstNonEmpty(opts.ModeFlag, getenv(EnvFleetMode)))
	if !modeOn {
		return Config{Enabled: false}, nil
	}

	memberID := strings.TrimSpace(firstNonEmpty(opts.MemberIDFlag, getenv(EnvFleetMemberID)))
	if memberID == "" {
		return Config{}, apperr.New(apperr.CodeInvalidArgument, "fleet mode requires member id (--fleet-member-id or "+EnvFleetMemberID+")")
	}

	rosterPath := strings.TrimSpace(firstNonEmpty(opts.RosterPathFlag, getenv(EnvFleetRoster)))
	if rosterPath == "" {
		return Config{}, apperr.New(apperr.CodeInvalidArgument, "fleet mode requires roster path (--fleet-roster or "+EnvFleetRoster+")")
	}
	raw, err := readFile(rosterPath)
	if err != nil {
		return Config{}, apperr.Wrap(apperr.CodeNotFound, "read fleet roster", err)
	}
	roster, err := ParseRoster(raw)
	if err != nil {
		return Config{}, err
	}
	if roster.MemberByID(memberID) == nil {
		return Config{}, apperr.New(apperr.CodeInvalidArgument, "fleet member id is not in roster")
	}

	token := strings.TrimSpace(opts.MeshTokenInline)
	if token == "" {
		token = strings.TrimSpace(getenv(EnvFleetMeshToken))
	}
	if token == "" && strings.TrimSpace(opts.MeshTokenFile) != "" {
		b, err := readFile(strings.TrimSpace(opts.MeshTokenFile))
		if err != nil {
			return Config{}, apperr.Wrap(apperr.CodeNotFound, "read fleet mesh token file", err)
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		return Config{}, apperr.New(apperr.CodeInvalidArgument, "fleet mode requires mesh trust ("+EnvFleetMeshToken+" or mesh token file); empty trust fails closed")
	}

	listen := strings.TrimSpace(firstNonEmpty(opts.PeerListenFlag, getenv(EnvFleetPeerListen)))

	return Config{
		Enabled:         true,
		MemberID:        memberID,
		Roster:          roster,
		MeshToken:       token,
		PeerListen:      listen,
		PeerTimeout:     DefaultPeerTimeout,
		Overall:         DefaultOverallTimeout,
		MaxParallel:     DefaultMaxPeerParallel,
		TrustConfigured: true,
	}, nil
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
