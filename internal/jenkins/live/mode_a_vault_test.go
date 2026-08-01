//go:build live_jenkins

package live

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// TestLive_ModeAVaultObtain_WhoAmI is the Mode A live-lab path (HOST-009 / S1):
// personal API token in a file vault → Obtain → Basic wire → WhoAmI against
// disposable Jenkins. Cross-subject miss fail-closed. Secret-free errors.
//
// Does NOT flip residual-status mode_a_live_obtain_qualified (offline residual
// surface stays false until deliberate production pin evidence).
func TestLive_ModeAVaultObtain_WhoAmI(t *testing.T) {
	base := strings.TrimSpace(os.Getenv(envURL))
	if base == "" {
		t.Skip("JENKINS_URL unset; skipping Mode A vault live lab")
	}
	user := envOr("JENKINS_USER", "admin")
	token := strings.TrimSpace(os.Getenv("JENKINS_API_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("JENKINS_TOKEN"))
	}
	if token == "" {
		t.Skip("JENKINS_API_TOKEN unset; skipping Mode A vault live lab")
	}

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "apitoken_vault.json")
	v, err := gateway.NewFileAPITokenVault(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	alice := gateway.Caller{
		Subject:   "alice-lab",
		Tenant:    "lab",
		ProfileID: "live",
	}
	bob := gateway.Caller{
		Subject:   "bob-lab",
		Tenant:    "lab",
		ProfileID: "live",
	}
	if err := v.Put(context.Background(), gateway.SubjectKey(alice), user, token); err != nil {
		t.Fatal(err)
	}
	// Bob intentionally missing — isolation canary.

	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode() != gateway.ModeAPITokenVault {
		t.Fatalf("mode %s", p.Mode())
	}
	if !p.Status(context.Background()).Ready {
		t.Fatal("Mode A vault must be Ready offline when vault path is open")
	}

	// Cross-subject: Bob not_found, no alice token leak.
	_, err = p.Obtain(context.Background(), bob)
	if err == nil || apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("bob want not_found: %v", err)
	}
	assertNoSecret(t, token, err.Error())

	ha, err := gateway.ObtainHTTPAuth(context.Background(), p, alice)
	if err != nil {
		assertNoSecret(t, token, err.Error())
		t.Fatalf("ObtainHTTPAuth alice: %v", err)
	}
	if ha.Scheme != gateway.HTTPAuthSchemeBasic || ha.Username != user {
		t.Fatalf("want Basic username=%q got %+v", user, ha)
	}
	if ha.Token != token {
		t.Fatal("alice token mismatch")
	}
	assertNoSecret(t, token, ha.String())

	// Wire Obtain into Jenkins client AuthProvider (gateway multi-user shape).
	c := jenkins.NewClient(base, "", "")
	if c == nil {
		t.Fatal("nil client")
	}
	prov := p
	caller := alice
	c.WithAuthProvider(nil)
	c.WithAuthProviderCtx(func(ctx context.Context) (u, secret string, sch jenkins.AuthScheme, err error) {
		auth, err := gateway.ObtainHTTPAuth(ctx, prov, caller)
		if err != nil {
			return "", "", "", err
		}
		if auth.Scheme == gateway.HTTPAuthSchemeBasic {
			return auth.Username, auth.Token, jenkins.AuthSchemeBasic, nil
		}
		return "", auth.Token, jenkins.AuthSchemeBearer, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	who, err := c.WhoAmI(ctx)
	if err != nil {
		assertNoSecret(t, token, err.Error())
		t.Fatalf("WhoAmI via Mode A vault Obtain: %v", err)
	}
	assertNoSecret(t, token, who.ID, who.FullName)
	if who.Anonymous || !who.Authenticated {
		t.Fatalf("expected authenticated whoAmI via vault token: %+v", who)
	}
	t.Logf("Mode A vault live WhoAmI id=%q (subject=%s)", who.ID, alice.Subject)

	// Residual honesty: CLI residual map never claims production live GO.
	st := diagnostics.BuildGatewayResidualStatus(func(k string) string {
		switch k {
		case gateway.EnvGatewayCredentialMode:
			return string(gateway.CredentialModeAPITokenVault)
		case gateway.EnvGatewayVaultPath:
			return vaultPath
		default:
			return ""
		}
	})
	if v, _ := st["mode_a_live_obtain_qualified"].(bool); v {
		t.Fatal("mode_a_live_obtain_qualified must stay false without production pin evidence")
	}
}
