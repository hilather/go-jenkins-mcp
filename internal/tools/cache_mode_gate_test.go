package tools_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

// fixedGate implements tools.CacheModeGate for external compile-check only.
// Behavioral coverage lives in package tools: cache_mode_enforcement_test.go
// (loadSurveyBuildSummary process L1 + durable; getCachedBuildDetails; getOrFetchCached).
type fixedGate struct {
	lookup, fill map[string]bool
}

func (g fixedGate) AllowLookup(typeID string) bool {
	if g.lookup == nil {
		return true
	}
	v, ok := g.lookup[typeID]
	if !ok {
		return true
	}
	return v
}
func (g fixedGate) AllowFill(typeID string) bool {
	if g.fill == nil {
		return true
	}
	v, ok := g.fill[typeID]
	if !ok {
		return true
	}
	return v
}

var _ tools.CacheModeGate = fixedGate{}

func TestCacheModeGate_InterfaceExported(t *testing.T) {
	g := fixedGate{
		lookup: map[string]bool{"diagnostic_fetch": false, "survey_summary": false},
		fill:   map[string]bool{"diagnostic_fetch": false, "survey_summary": true},
	}
	if g.AllowLookup("diagnostic_fetch") || g.AllowLookup("survey_summary") {
		t.Fatal("lookup off")
	}
	if g.AllowFill("diagnostic_fetch") {
		t.Fatal("fill off")
	}
	if !g.AllowFill("survey_summary") {
		t.Fatal("survey fill on")
	}
}
