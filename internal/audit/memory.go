package audit

import (
	"context"
	"sync"
)

// Memory is an in-process sink for tests. Events are kept in emit order.
type Memory struct {
	mu     sync.Mutex
	events []Event
	// Max caps retained events (0 = unlimited). Oldest dropped when exceeded.
	Max int
}

// Emit implements Sink.
func (m *Memory) Emit(ctx context.Context, e Event) error {
	if m == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e = e.Normalize()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	if m.Max > 0 && len(m.events) > m.Max {
		// Drop oldest.
		drop := len(m.events) - m.Max
		m.events = append([]Event(nil), m.events[drop:]...)
	}
	return nil
}

// Close implements Sink.
func (m *Memory) Close() error { return nil }

// Events returns a copy of recorded events in emit order.
func (m *Memory) Events() []Event {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, len(m.events))
	copy(out, m.events)
	return out
}

// Len returns the number of retained events.
func (m *Memory) Len() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

// Reset clears retained events.
func (m *Memory) Reset() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = nil
}
