package fleetmcp

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// RosterSnapshot is an atomic, last-known-good roster view for placement and fleet ops.
// Concurrent readers always see a fully validated roster pointer (never a partial parse).
type RosterSnapshot struct {
	mu sync.RWMutex

	current  *Roster
	previous *Roster // last superseded snapshot (grace / residual for placement epoch)

	// path is optional; Reload reads from path when set.
	path string

	// readFile injectable for tests.
	readFile func(string) ([]byte, error)

	// allowBundleSeqRollback is fail-closed false by default (FLC-013).
	allowBundleSeqRollback bool

	// rosterParse peer URL transport (strict HTTPS by default).
	rosterParse RosterParseOptions

	loadedAt time.Time
}

// SnapshotOptions configures RosterSnapshot construction.
type SnapshotOptions struct {
	// Path optional; used by Reload.
	Path string
	// AllowBundleSeqRollback when true permits applying a lower bundle_seq (break-glass).
	AllowBundleSeqRollback bool
	// AllowInsecureHTTP when true allows non-loopback http peer URLs (lab residual).
	AllowInsecureHTTP bool
	// ReadFile optional (default os.ReadFile).
	ReadFile func(string) ([]byte, error)
}

// NewRosterSnapshot creates an empty snapshot store. Call Load/Apply before Current is useful.
func NewRosterSnapshot(opts SnapshotOptions) *RosterSnapshot {
	rf := opts.ReadFile
	if rf == nil {
		rf = os.ReadFile
	}
	return &RosterSnapshot{
		path:                   strings.TrimSpace(opts.Path),
		readFile:               rf,
		allowBundleSeqRollback: opts.AllowBundleSeqRollback,
		rosterParse: RosterParseOptions{
			PeerURL: PeerURLOptions{AllowInsecureHTTP: opts.AllowInsecureHTTP},
		},
	}
}

func (s *RosterSnapshot) parseOpts() RosterParseOptions {
	if s == nil {
		return RosterParseOptions{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rosterParse
}

// LoadFile parses path, validates, and installs as current (initial or replace with rules).
func (s *RosterSnapshot) LoadFile(path string) error {
	if s == nil {
		return apperr.New(apperr.CodeInternal, "roster snapshot is nil")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return apperr.New(apperr.CodeInvalidArgument, "roster path is empty")
	}
	raw, err := s.readFile(path)
	if err != nil {
		return apperr.Wrap(apperr.CodeNotFound, "read fleet roster", err)
	}
	r, err := ParseRosterOpts(raw, s.parseOpts())
	if err != nil {
		return err
	}
	if err := s.Apply(r); err != nil {
		return err
	}
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
	return nil
}

// Reload re-reads the configured path. On failure, last-known-good is retained and error returned.
func (s *RosterSnapshot) Reload() error {
	if s == nil {
		return apperr.New(apperr.CodeInternal, "roster snapshot is nil")
	}
	s.mu.RLock()
	path := s.path
	s.mu.RUnlock()
	if path == "" {
		return apperr.New(apperr.CodeInvalidArgument, "roster snapshot has no path")
	}
	raw, err := s.readFile(path)
	if err != nil {
		// LKG retained.
		return apperr.Wrap(apperr.CodeNotFound, "reload fleet roster", err)
	}
	r, err := ParseRosterOpts(raw, s.parseOpts())
	if err != nil {
		// Invalid parse → keep LKG.
		return err
	}
	return s.Apply(r)
}

// Apply validates candidate and atomically swaps it in when bundle_seq rules pass.
// Callers must not mutate r after a successful Apply.
func (s *RosterSnapshot) Apply(candidate *Roster) error {
	if s == nil {
		return apperr.New(apperr.CodeInternal, "roster snapshot is nil")
	}
	if err := ValidateRosterOpts(candidate, s.parseOpts()); err != nil {
		return err
	}
	// Clone membership into a private snapshot so callers cannot half-mutate under RLock.
	next := cloneRoster(candidate)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil {
		if err := checkBundleSeqAdvance(s.current, next, s.allowBundleSeqRollback); err != nil {
			return err
		}
		s.previous = s.current
	}
	s.current = next
	s.loadedAt = time.Now().UTC()
	return nil
}

// Current returns the active roster (nil if never loaded). The returned pointer must
// be treated as immutable by callers.
func (s *RosterSnapshot) Current() *Roster {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Previous returns the last superseded roster (may be nil).
func (s *RosterSnapshot) Previous() *Roster {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.previous
}

// LoadedAt is the UTC time of the last successful Apply.
func (s *RosterSnapshot) LoadedAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadedAt
}

// Path returns the configured roster file path (may be empty).
func (s *RosterSnapshot) Path() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.path
}

// SetAllowBundleSeqRollback is the explicit authorized path for seq downgrade.
func (s *RosterSnapshot) SetAllowBundleSeqRollback(allow bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.allowBundleSeqRollback = allow
	s.mu.Unlock()
}

func checkBundleSeqAdvance(cur, next *Roster, allowRollback bool) error {
	if cur == nil || next == nil {
		return nil
	}
	// Different fleet_id is a hard change — require higher or equal seq still, but flag mismatch.
	if cur.FleetID != next.FleetID {
		return apperr.New(apperr.CodeInvalidArgument, "fleet_id change requires process restart (fail closed)")
	}
	if next.BundleSeq < cur.BundleSeq && !allowRollback {
		return apperr.New(apperr.CodeInvalidArgument, "roster bundle_seq rollback rejected")
	}
	return nil
}

func cloneRoster(r *Roster) *Roster {
	if r == nil {
		return nil
	}
	out := *r
	if r.Members != nil {
		out.Members = make([]RosterMember, len(r.Members))
		for i := range r.Members {
			out.Members[i] = cloneMember(r.Members[i])
		}
	}
	return &out
}

func cloneMember(m RosterMember) RosterMember {
	out := m
	if m.Labels != nil {
		out.Labels = make(map[string]string, len(m.Labels))
		for k, v := range m.Labels {
			out.Labels[k] = v
		}
	}
	if m.Cache != nil {
		c := *m.Cache
		if m.Cache.Protocols != nil {
			c.Protocols = append([]string(nil), m.Cache.Protocols...)
		}
		out.Cache = &c
	}
	return out
}
