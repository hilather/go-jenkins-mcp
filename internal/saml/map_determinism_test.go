package saml_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/saml"
)

// Regression: the groups-attribute fallback (and firstAttr) iterated a Go map
// and took the FIRST case-insensitive/suffix match — random iteration order.
// An assertion carrying both a URI-style claim key and a short-name key could
// yield either group set per login, and the chosen groups feed role mapping
// (ResolveAdminRole) — authorization-relevant nondeterminism. The fallback
// now picks the lexicographically smallest matching key deterministically.
func TestMapIdentity_FallbackAttributeDeterministic(t *testing.T) {
	t.Parallel()
	cfg := testCfg() // GroupsAttribute: "groups"
	attrs := saml.AttributeValues{
		// Exact key absent; two suffix/case-insensitive matches with
		// different values.
		"http://schemas.xmlsoap.org/claims/Groups": {"uri-group"},
		"custom/groups": {"short-group"},
	}
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		id, err := saml.MapIdentity(cfg, "bob", attrs, cfg.IdPEntityID)
		if err != nil {
			t.Fatal(err)
		}
		if len(id.Groups) != 1 {
			t.Fatalf("groups: %v", id.Groups)
		}
		seen[id.Groups[0]]++
	}
	if len(seen) != 1 {
		t.Fatalf("nondeterministic group mapping across calls: %v", seen)
	}
	// Deterministic winner: lexicographically smallest matching key
	// ("custom/groups" < "http://...").
	if _, ok := seen["short-group"]; !ok {
		t.Fatalf("deterministic winner must be the smallest matching key: %v", seen)
	}
}
