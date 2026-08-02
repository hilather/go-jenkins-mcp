package auth_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
)

func TestSessionGuard_RevokeAndLogout(t *testing.T) {
	t.Parallel()
	g := auth.NewSessionGuard("fp1")
	if err := g.Check(); err != nil {
		t.Fatal(err)
	}
	st := g.Status()
	if st["usable"] != true {
		t.Fatalf("%v", st)
	}
	g.MarkRevoked()
	if err := g.Check(); err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("%v", err)
	}
	g2 := auth.NewSessionGuard("fp1")
	g2.Disable()
	if err := g2.Check(); err == nil {
		t.Fatal("logout must fail closed")
	}
	// Nil receiver fails closed.
	var nilG *auth.SessionGuard
	if err := nilG.Check(); err == nil {
		t.Fatal("nil guard")
	}
}

func TestSessionGuard_IdentityChange(t *testing.T) {
	t.Parallel()
	g := auth.NewSessionGuard("")
	if err := g.CheckIdentity("a"); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckIdentity("a"); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckIdentity("b"); err == nil {
		t.Fatal("identity change must fail")
	}
}
