package resourcecache

import "time"

// FreshnessPolicy decides whether a ready entry may be served without re-fetch.
type FreshnessPolicy struct {
	// TerminalTTL is max age for completed (non-building) builds. Zero ⇒ no wall TTL.
	TerminalTTL time.Duration
	// BuildingTTL is max age while Jenkins reports building. Zero ⇒ 30s default.
	BuildingTTL time.Duration
}

// DefaultFreshness returns product defaults: terminal durable, building short-lived.
func DefaultFreshness() FreshnessPolicy {
	return FreshnessPolicy{
		TerminalTTL: 0, // terminal builds immutable enough; rely on content digest
		BuildingTTL: 30 * time.Second,
	}
}

// IsFresh reports whether e may be used as a cache hit at now.
func (p FreshnessPolicy) IsFresh(e Entry, now time.Time) bool {
	if e.State != StateReady {
		return false
	}
	if e.Completeness == Incomplete {
		return false
	}
	if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
		return false
	}
	if e.BuildBuilding {
		ttl := p.BuildingTTL
		if ttl <= 0 {
			ttl = 30 * time.Second
		}
		if e.FetchedAt.IsZero() || now.Sub(e.FetchedAt) > ttl {
			return false
		}
		return true
	}
	if p.TerminalTTL > 0 && !e.FetchedAt.IsZero() && now.Sub(e.FetchedAt) > p.TerminalTTL {
		return false
	}
	return true
}
