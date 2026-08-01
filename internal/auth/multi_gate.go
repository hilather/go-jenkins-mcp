package auth

import (
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Gate is the Check() contract shared with tools.AuthGate (duck-typed; auth
// does not import tools to preserve package boundaries).
type Gate interface {
	Check() error
}

// MultiGate runs multiple gates in order and short-circuits on the first error.
// Use for compose: epoch/LiveSessionSource first, then IdentityReverifyGate.
//
// Nil MultiGate or zero gates fails closed. Nil entries in Gates are skipped.
type MultiGate struct {
	Gates []Gate
}

// MultiGates builds a MultiGate from ordered gates (nil entries allowed).
func MultiGates(gates ...Gate) *MultiGate {
	out := make([]Gate, 0, len(gates))
	for _, g := range gates {
		if g != nil {
			out = append(out, g)
		}
	}
	return &MultiGate{Gates: out}
}

// Check implements tools.AuthGate. First failing gate wins (fail closed).
func (m *MultiGate) Check() error {
	if m == nil || len(m.Gates) == 0 {
		return apperr.New(apperr.CodeAuthentication, "auth multi-gate is not configured (fail closed)")
	}
	for _, g := range m.Gates {
		if g == nil {
			continue
		}
		if err := g.Check(); err != nil {
			return err
		}
	}
	return nil
}
