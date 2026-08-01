package keyring

import (
	"sync"
)

// Memory is an in-process Backend for unit tests. It is never the production default.
type Memory struct {
	mu   sync.Mutex
	data map[string]string
}

// NewMemory returns an empty memory backend.
func NewMemory() *Memory {
	return &Memory{data: make(map[string]string)}
}

func memKey(service, user string) string {
	return service + "\x00" + user
}

// Set implements Backend.
func (m *Memory) Set(service, user, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = make(map[string]string)
	}
	m.data[memKey(service, user)] = password
	return nil
}

// Get implements Backend.
func (m *Memory) Get(service, user string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[memKey(service, user)]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// Delete implements Backend.
func (m *Memory) Delete(service, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey(service, user)
	if _, ok := m.data[k]; !ok {
		return ErrNotFound
	}
	delete(m.data, k)
	return nil
}

// Len returns the number of stored entries (test helper).
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.data)
}
