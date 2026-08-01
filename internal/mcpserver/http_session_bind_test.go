package mcpserver

import (
	"strings"
	"testing"
)

func TestIdentityFingerprint_IncludesGroups(t *testing.T) {
	t.Parallel()
	base := RequestIdentity{ExternalSubject: "alice", Tenant: "t"}
	withG := RequestIdentity{ExternalSubject: "alice", Tenant: "t", Groups: []string{"ops", "dev"}}
	if IdentityFingerprint(base) == IdentityFingerprint(withG) {
		t.Fatal("groups must participate in fingerprint")
	}
	// Order-independent.
	a := IdentityFingerprint(RequestIdentity{ExternalSubject: "a", Groups: []string{"x", "y"}})
	b := IdentityFingerprint(RequestIdentity{ExternalSubject: "a", Groups: []string{"y", "x"}})
	if a != b {
		t.Fatal("sorted groups must yield stable fingerprint")
	}
}

// HOST-001 unit: sessionIdentityTable bind-once / mismatch fail closed.
func TestSessionIdentityTable_BindOrCheck(t *testing.T) {
	t.Parallel()
	tab := newSessionIdentityTable(8)
	fpAlice := IdentityFingerprint(RequestIdentity{ExternalSubject: "alice"})
	fpBob := IdentityFingerprint(RequestIdentity{ExternalSubject: "bob"})
	if fpAlice == fpBob {
		t.Fatal("alice/bob fingerprints must differ")
	}

	// Empty session / fingerprint → no-op.
	if err := tab.BindOrCheck("", fpAlice); err != nil {
		t.Fatal(err)
	}
	if err := tab.BindOrCheck("s1", ""); err != nil {
		t.Fatal(err)
	}
	if tab.Len() != 0 {
		t.Fatalf("len=%d", tab.Len())
	}

	// First bind.
	if err := tab.BindOrCheck("s1", fpAlice); err != nil {
		t.Fatal(err)
	}
	if tab.Len() != 1 {
		t.Fatalf("len=%d", tab.Len())
	}
	// Same fingerprint OK.
	if err := tab.BindOrCheck("s1", fpAlice); err != nil {
		t.Fatal(err)
	}
	// Swap fail closed.
	err := tab.BindOrCheck("s1", fpBob)
	if err == nil {
		t.Fatal("expected mismatch")
	}
	if strings.Contains(err.Error(), "alice") || strings.Contains(err.Error(), "bob") ||
		strings.Contains(err.Error(), fpAlice) || strings.Contains(err.Error(), fpBob) {
		t.Fatalf("error must not echo fingerprint/subject: %v", err)
	}

	// Independent session.
	if err := tab.BindOrCheck("s2", fpBob); err != nil {
		t.Fatal(err)
	}
	if tab.Len() != 2 {
		t.Fatalf("len=%d", tab.Len())
	}

	// Oversize session id fail closed.
	big := strings.Repeat("x", MaxMCPSessionIDBytes+1)
	if err := tab.BindOrCheck(big, fpAlice); err == nil {
		t.Fatal("want oversize fail")
	}

	// Drop.
	tab.Drop("s1")
	if err := tab.BindOrCheck("s1", fpBob); err != nil {
		t.Fatalf("after drop re-bind as bob: %v", err)
	}
}

func TestSessionIdentityTable_MaxEvict(t *testing.T) {
	t.Parallel()
	tab := newSessionIdentityTable(2)
	fp := IdentityFingerprint(RequestIdentity{ExternalSubject: "u"})
	if err := tab.BindOrCheck("a", fp); err != nil {
		t.Fatal(err)
	}
	if err := tab.BindOrCheck("b", fp); err != nil {
		t.Fatal(err)
	}
	if tab.Len() != 2 {
		t.Fatalf("len=%d", tab.Len())
	}
	// Third bind may evict one; must not error.
	if err := tab.BindOrCheck("c", fp); err != nil {
		t.Fatal(err)
	}
	if tab.Len() != 2 {
		t.Fatalf("after overflow len=%d want 2", tab.Len())
	}
}

func TestSessionIdentityTable_NilReceiver(t *testing.T) {
	t.Parallel()
	var tab *sessionIdentityTable
	if err := tab.BindOrCheck("s", "fp"); err == nil {
		t.Fatal("nil table must fail closed")
	}
	if tab.Len() != 0 {
		t.Fatal("nil Len")
	}
	tab.Drop("s") // no panic
}
