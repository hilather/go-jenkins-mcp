package adapter

import (
	"context"
	"strings"
	"sync"
)

// INT-004 built-in adapter ID: work-item / ticket-system lookup stub (no network).
const IDWorkItems = "work-items"

// WorkItemLookupRequest asks for minimal ticket metadata by already-extracted refs.
// MVP stub does not call external systems; it returns the same refs labeled as stub.
type WorkItemLookupRequest struct {
	// Refs are opaque work-item identifiers (JIRA keys, issue URLs, …) already
	// extracted from Jenkins metadata. Max applied by caller.
	Refs []string
}

// WorkItemLookupResult is a bounded, source-labeled stub response.
type WorkItemLookupResult struct {
	// Refs are echo/passthrough refs (no private discussion content).
	Refs []WorkItemStubRef `json:"refs"`
	// Residuals document that real ticket APIs are not implemented.
	Residuals []string `json:"residuals,omitempty"`
	// Message status.
	Message string `json:"message,omitempty"`
}

// WorkItemStubRef is a future-ticket-system reference only (no network body).
type WorkItemStubRef struct {
	ID             string `json:"id"`
	SourceLabel    string `json:"source_label"`
	Freshness      string `json:"freshness"`
	EvidenceSource string `json:"evidence_source"`
	Note           string `json:"note,omitempty"`
}

// WorkItemLookup is the optional capability for ticket system enrichment.
// MVP implementation never opens network connections.
type WorkItemLookup interface {
	LookupWorkItems(ctx context.Context, req WorkItemLookupRequest) (WorkItemLookupResult, error)
}

const residualWorkItemsSaaS = "ticket system API residual (INT-004 MVP: work-items adapter returns refs only; no Jira/GitHub network lookup)"

// WorkItems is a lifecycle + CapWorkItem stub adapter (no credentials, no network).
type WorkItems struct {
	host    Host
	mu      sync.Mutex
	started bool
	stopped bool
}

// NewWorkItems constructs the work-items stub adapter.
func NewWorkItems(host Host) (Adapter, error) {
	return &WorkItems{host: host}, nil
}

func (w *WorkItems) ID() string { return IDWorkItems }

func (w *WorkItems) Capabilities() []Capability {
	return []Capability{CapLifecycle, CapWorkItem}
}

func (w *WorkItems) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	w.started = true
	w.stopped = false
	w.mu.Unlock()
	w.host.logf("adapter work-items: started (refs only; no ticket network)")
	return nil
}

func (w *WorkItems) Stop(ctx context.Context) error {
	_ = ctx
	w.mu.Lock()
	w.stopped = true
	w.started = false
	w.mu.Unlock()
	w.host.logf("adapter work-items: stopped")
	return nil
}

func (w *WorkItems) Health(ctx context.Context) Health {
	_ = ctx
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case w.stopped && !w.started:
		return Health{Status: HealthStopped, Message: "stopped", CheckedAt: w.host.now()}
	case w.started:
		return Health{
			Status:    HealthHealthy,
			Message:   "work-item correlation stub (refs only; no network)",
			CheckedAt: w.host.now(),
		}
	default:
		return Health{Status: HealthUnknown, Message: "not started", CheckedAt: w.host.now()}
	}
}

// LookupWorkItems implements WorkItemLookup: echo bounded refs with stub labels.
// No network. Does not fetch ticket titles, comments, or private discussion.
func (w *WorkItems) LookupWorkItems(ctx context.Context, req WorkItemLookupRequest) (WorkItemLookupResult, error) {
	if err := ctx.Err(); err != nil {
		return WorkItemLookupResult{}, err
	}
	w.mu.Lock()
	started := w.started
	w.mu.Unlock()
	if !started {
		return WorkItemLookupResult{
			Refs:      []WorkItemStubRef{},
			Residuals: []string{residualWorkItemsSaaS},
			Message:   "work-items adapter not started",
		}, nil
	}
	const max = 32
	out := WorkItemLookupResult{
		Refs:      make([]WorkItemStubRef, 0, len(req.Refs)),
		Residuals: []string{residualWorkItemsSaaS},
		Message:   "stub lookup: refs only; no ticket system network call",
	}
	seen := map[string]struct{}{}
	for _, id := range req.Refs {
		id = trimWorkItemID(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if len(out.Refs) >= max {
			break
		}
		out.Refs = append(out.Refs, WorkItemStubRef{
			ID:             id,
			SourceLabel:    "work-items-stub",
			Freshness:      "stub",
			EvidenceSource: "work_item_adapter_stub",
			Note:           "identifier passthrough only; no remote ticket fetch",
		})
	}
	return out, nil
}

func trimWorkItemID(id string) string {
	// Bound length; strip control noise.
	const maxID = 256
	id = strings.TrimSpace(id)
	if len(id) > maxID {
		id = id[:maxID]
	}
	return id
}
