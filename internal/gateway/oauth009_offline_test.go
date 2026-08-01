package gateway_test

import (
	"context"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// OAUTH-009 offline foundations (gateway side): Mode B Obtain is Bearer-only;
// invalid/missing JWT vault material never falls through to Basic (Mode A).
// ID token never stored as API credential. Live jwt-auth-filter pin residual.
func TestOAUTH009_ModeB_ObtainNoBasicFallthrough(t *testing.T) {
	t.Parallel()
	const (
		canaryA = "OAUTH009_modeA_canary_never_log_xyz"
		canaryB = "OAUTH009_modeB_canary_never_log_abc"
	)
	caller := gateway.Caller{
		Subject:   "oauth009-user",
		Tenant:    "t1",
		ProfileID: contracts.ProfileID("corp"),
	}

	// Co-resident Mode A vault must never be used by Mode B Obtain.
	apiVault := gateway.NewMemoryAPITokenVault()
	if err := apiVault.Put(context.Background(), gateway.SubjectKey(caller), "alice", canaryA); err != nil {
		t.Fatal(err)
	}

	t.Run("empty_jwt_vault_fail_closed", func(t *testing.T) {
		t.Parallel()
		jwtVault := gateway.NewMemoryJWTVault()
		pB, err := gateway.RequireJWTRSBearerSetup(jwtVault)
		if err != nil {
			t.Fatal(err)
		}
		ha, err := gateway.ObtainHTTPAuth(context.Background(), pB, caller)
		if err == nil {
			t.Fatalf("empty Mode B vault must fail closed, got %+v", ha)
		}
		if ha.Scheme != "" || ha.Token != "" || ha.Username != "" {
			t.Fatalf("must not return any auth material: %+v", ha)
		}
		if apperr.CodeOf(err) != apperr.CodeNotFound {
			t.Fatalf("code %v", apperr.CodeOf(err))
		}
		if strings.Contains(err.Error(), canaryA) {
			t.Fatal("Mode A canary in Mode B error (Basic fallthrough)")
		}
	})

	t.Run("jwt_hit_bearer_not_basic", func(t *testing.T) {
		t.Parallel()
		jwtVault := gateway.NewMemoryJWTVault()
		// Opaque lab token (not id_token-shaped).
		if err := jwtVault.Put(context.Background(), gateway.SubjectKey(caller), canaryB); err != nil {
			t.Fatal(err)
		}
		pB, err := gateway.RequireJWTRSBearerSetup(jwtVault)
		if err != nil {
			t.Fatal(err)
		}
		ha, err := gateway.ObtainHTTPAuth(context.Background(), pB, caller)
		if err != nil {
			t.Fatal(err)
		}
		if ha.Scheme != gateway.HTTPAuthSchemeBearer {
			t.Fatalf("Mode B must be Bearer got %s", ha.Scheme)
		}
		if ha.Username != "" {
			t.Fatalf("Bearer must not set Basic username: %+v", ha)
		}
		if ha.Token != canaryB {
			t.Fatal("token mismatch")
		}
		if ha.Token == canaryA {
			t.Fatal("Mode B must not use Mode A token")
		}
		if strings.Contains(ha.String(), canaryB) || strings.Contains(ha.String(), canaryA) {
			t.Fatal("HTTPAuth.String leaked canary")
		}
	})

	t.Run("id_token_never_api_credential", func(t *testing.T) {
		t.Parallel()
		jwtVault := gateway.NewMemoryJWTVault()
		idTok := compactJWTWithClaims(t, map[string]string{
			"sub":       "oauth009-user",
			"token_use": "id_token",
			"aud":       "api://jenkins",
		})
		err := jwtVault.Put(context.Background(), gateway.SubjectKey(caller), idTok)
		if err == nil {
			t.Fatal("id_token must be rejected as API credential")
		}
		if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("code %v", apperr.CodeOf(err))
		}
		if strings.Contains(err.Error(), idTok) {
			t.Fatal("id_token material in error")
		}
		// Mode B residual provider also fail closed (no ambient Basic).
		res := gateway.NewResidualJWTRSProvider()
		cred, err := res.Obtain(context.Background(), caller)
		if err == nil || cred.AccessToken != "" {
			t.Fatal("residual Mode B must not return credentials")
		}
	})

	t.Run("mode_matrix_residual_oauth009", func(t *testing.T) {
		t.Parallel()
		env := map[string]string{
			gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeJWTRSBearer),
		}
		mx, err := gateway.ModeMatrixFromEnviron(func(k string) string { return env[k] })
		if err != nil {
			t.Fatal(err)
		}
		if mx.Primary != gateway.CredentialModeJWTRSBearer {
			t.Fatalf("primary %s", mx.Primary)
		}
		if mx.Residual == "" || !strings.Contains(mx.Residual, "OAUTH-009") {
			t.Fatalf("Mode B residual must note OAUTH-009 live pin: %q", mx.Residual)
		}
		if !strings.Contains(mx.Residual, "jwt-auth-filter") && !strings.Contains(mx.Residual, "live") {
			t.Fatalf("residual must be honest about live RS: %q", mx.Residual)
		}
	})
}

// Offline fallthrough classifier fixtures remain available for gateway qualify
// cross-check (no network; secret-free).
func TestOAUTH009_OfflineFallthroughClassifier_Available(t *testing.T) {
	t.Parallel()
	fixtures := auth.OfflineFallthroughFixtures()
	if len(fixtures) < 12 {
		t.Fatalf("fixture floor: %d", len(fixtures))
	}
	// Invalid-bearer authenticated success is always FallthroughDetected.
	eval := auth.ClassifyFallthroughProbe(auth.FallthroughProbeInput{
		StatusCode:          200,
		BodyClass:           auth.BodyClassWhoAmIAuthenticated,
		WhoAmIAuthenticated: true,
	})
	if !eval.FallthroughDetected {
		t.Fatalf("expected fallthrough detection: %+v", eval)
	}
	// 401 Bearer challenge is Denied (pass).
	pass := auth.ClassifyFallthroughProbe(auth.FallthroughProbeInput{
		StatusCode:      401,
		WWWAuthenticate: `Bearer realm="Jenkins", error="invalid_token"`,
		BodyClass:       auth.BodyClassEmpty,
	})
	if !pass.Denied || pass.FallthroughDetected {
		t.Fatalf("expected deny: %+v", pass)
	}
}
