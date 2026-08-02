package fleetmcp

import (
	"sync"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// ManifestCatalog is the local sealed-object index for owner-directed lookup (FLC-030).
type ManifestCatalog interface {
	// Get returns a sealed wire manifest by locator hash.
	Get(locatorHash string) (fleetcache.WireManifest, bool)
	// Put stores/replaces a sealed manifest (idempotent for same digest).
	Put(m fleetcache.WireManifest) error
}

// MemoryCatalog is a process-local catalog for tests and pilot residual.
type MemoryCatalog struct {
	mu   sync.RWMutex
	byLH map[string]fleetcache.WireManifest
}

// NewMemoryCatalog creates an empty catalog.
func NewMemoryCatalog() *MemoryCatalog {
	return &MemoryCatalog{byLH: make(map[string]fleetcache.WireManifest)}
}

// Get implements ManifestCatalog.
func (c *MemoryCatalog) Get(locatorHash string) (fleetcache.WireManifest, bool) {
	if c == nil {
		return fleetcache.WireManifest{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	m, ok := c.byLH[locatorHash]
	return m, ok
}

// Put implements ManifestCatalog.
func (c *MemoryCatalog) Put(m fleetcache.WireManifest) error {
	if c == nil {
		return nil
	}
	if err := fleetcache.ValidateWireManifest(m); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byLH == nil {
		c.byLH = make(map[string]fleetcache.WireManifest)
	}
	c.byLH[m.LocatorHash] = m
	return nil
}
