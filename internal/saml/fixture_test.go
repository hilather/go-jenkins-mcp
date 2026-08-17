package saml_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/saml"
)

func testRSA(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return priv, &priv.PublicKey
}

func testCfg() saml.Config {
	return saml.Config{
		SchemaVersion: 1,
		Enabled:       true,
		SPEntityID:    "https://mcp.example/sp",
		ACSURL:        "https://mcp.example/admin/v1/saml/acs",
		IdPEntityID:   "https://idp.example/metadata",
		AttributeMap: saml.AttributeMap{
			GroupsAttribute: "groups",
		},
		GroupRoles: map[string]string{
			"mcp-admins":    "policy_admin",
			"mcp-operators": "operator",
			"mcp-viewers":   "viewer",
		},
		MaxGroups: 8,
	}
}

func buildAssertionXML(t *testing.T, priv *rsa.PrivateKey, mut func(body *string)) []byte {
	t.Helper()
	now := time.Now().UTC()
	nb := now.Add(-1 * time.Minute).Format(time.RFC3339)
	na := now.Add(10 * time.Minute).Format(time.RFC3339)
	body := fmt.Sprintf(`<Assertion ID="a1" IssueInstant="%s">
  <Issuer>https://idp.example/metadata</Issuer>
  <Subject>
    <NameID>alice@example.com</NameID>
    <SubjectConfirmation>
      <SubjectConfirmationData Recipient="https://mcp.example/admin/v1/saml/acs" NotOnOrAfter="%s"/>
    </SubjectConfirmation>
  </Subject>
  <Conditions NotBefore="%s" NotOnOrAfter="%s">
    <AudienceRestriction>
      <Audience>https://mcp.example/sp</Audience>
    </AudienceRestriction>
  </Conditions>
  <AttributeStatement>
    <Attribute Name="groups">
      <AttributeValue>mcp-operators</AttributeValue>
      <AttributeValue>readers</AttributeValue>
    </Attribute>
  </AttributeStatement>
</Assertion>`, now.Format(time.RFC3339), na, nb, na)
	if mut != nil {
		mut(&body)
	}
	// Sign body without Signature element
	sigB64, err := saml.SignPayloadRSASHA256(priv, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	// Insert signature after Issuer
	signed := strings.Replace(body, "</Issuer>",
		"</Issuer><Signature><SignatureValue>"+sigB64+"</SignatureValue></Signature>", 1)
	return []byte(signed)
}

func TestSAML_ValidateAndMap_Success(t *testing.T) {
	t.Parallel()
	priv, pub := testRSA(t)
	cfg := testCfg()
	raw := buildAssertionXML(t, priv, nil)
	id, err := saml.ValidateAndMap(cfg, raw, saml.ValidateOptions{
		Now:   time.Now().UTC(),
		Trust: saml.TrustMaterial{PublicKey: pub},
	})
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "alice@example.com" {
		t.Fatalf("subject: %q", id.Subject)
	}
	if len(id.Groups) != 2 {
		t.Fatalf("groups: %v", id.Groups)
	}
	if id.SubjectRedacted == "" {
		t.Fatal("expected redacted subject")
	}
	// Canary: identity must not contain raw XML
	if strings.Contains(id.Subject, "<") || strings.Contains(id.Subject, "Signature") {
		t.Fatal("subject must not carry XML")
	}
}

func TestSAML_FailClosed_BadSignature(t *testing.T) {
	t.Parallel()
	priv, _ := testRSA(t)
	_, pubOther := testRSA(t)
	cfg := testCfg()
	raw := buildAssertionXML(t, priv, nil)
	_, err := saml.ValidateAndMap(cfg, raw, saml.ValidateOptions{
		Trust: saml.TrustMaterial{PublicKey: pubOther},
	})
	if err == nil {
		t.Fatal("expected bad signature fail")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code: %v", err)
	}
	// Secret-free: error must not echo SignatureValue or NameID dump
	es := err.Error()
	if strings.Contains(es, "alice@example.com") || strings.Contains(es, "SignatureValue") {
		t.Fatalf("error leaks identity/sig: %s", es)
	}
}

func TestSAML_FailClosed_WrongAudience(t *testing.T) {
	t.Parallel()
	priv, pub := testRSA(t)
	cfg := testCfg()
	raw := buildAssertionXML(t, priv, func(body *string) {
		*body = strings.ReplaceAll(*body, "https://mcp.example/sp", "https://evil.example/sp")
	})
	_, err := saml.ValidateAndMap(cfg, raw, saml.ValidateOptions{Trust: saml.TrustMaterial{PublicKey: pub}})
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("want audience error, got %v", err)
	}
}

func TestSAML_FailClosed_WrongRecipient(t *testing.T) {
	t.Parallel()
	priv, pub := testRSA(t)
	cfg := testCfg()
	raw := buildAssertionXML(t, priv, func(body *string) {
		*body = strings.ReplaceAll(*body, "https://mcp.example/admin/v1/saml/acs", "https://evil.example/acs")
	})
	_, err := saml.ValidateAndMap(cfg, raw, saml.ValidateOptions{Trust: saml.TrustMaterial{PublicKey: pub}})
	if err == nil || !strings.Contains(err.Error(), "recipient") {
		t.Fatalf("want recipient error, got %v", err)
	}
}

func TestSAML_FailClosed_Expired(t *testing.T) {
	t.Parallel()
	priv, pub := testRSA(t)
	cfg := testCfg()
	raw := buildAssertionXML(t, priv, nil)
	_, err := saml.ValidateAndMap(cfg, raw, saml.ValidateOptions{
		Now:   time.Now().UTC().Add(2 * time.Hour),
		Trust: saml.TrustMaterial{PublicKey: pub},
	})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("want expired, got %v", err)
	}
}

func TestSAML_FailClosed_NotYetValid(t *testing.T) {
	t.Parallel()
	priv, pub := testRSA(t)
	cfg := testCfg()
	raw := buildAssertionXML(t, priv, nil)
	_, err := saml.ValidateAndMap(cfg, raw, saml.ValidateOptions{
		Now:   time.Now().UTC().Add(-2 * time.Hour),
		Trust: saml.TrustMaterial{PublicKey: pub},
	})
	if err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("want not yet valid, got %v", err)
	}
}

func TestSAML_FailClosed_UntrustedIssuer(t *testing.T) {
	t.Parallel()
	priv, pub := testRSA(t)
	cfg := testCfg()
	raw := buildAssertionXML(t, priv, func(body *string) {
		*body = strings.ReplaceAll(*body, "https://idp.example/metadata", "https://evil-idp.example")
	})
	_, err := saml.ValidateAndMap(cfg, raw, saml.ValidateOptions{Trust: saml.TrustMaterial{PublicKey: pub}})
	if err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("want issuer error, got %v", err)
	}
}

func TestSAML_FailClosed_GroupOverage(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	cfg.MaxGroups = 2
	// 3 groups → overage
	attrs := saml.AttributeValues{"groups": {"g1", "g2", "g3"}}
	_, err := saml.MapIdentity(cfg, "bob", attrs, cfg.IdPEntityID)
	if err == nil {
		t.Fatal("expected group overage fail closed")
	}
}

func TestSAML_FailClosed_MissingSignature(t *testing.T) {
	t.Parallel()
	_, pub := testRSA(t)
	cfg := testCfg()
	raw := []byte(`<Assertion ID="a1"><Issuer>https://idp.example/metadata</Issuer>
  <Subject><NameID>x</NameID><SubjectConfirmation><SubjectConfirmationData Recipient="https://mcp.example/admin/v1/saml/acs"/></SubjectConfirmation></Subject>
  <Conditions NotOnOrAfter="2099-01-01T00:00:00Z"><AudienceRestriction><Audience>https://mcp.example/sp</Audience></AudienceRestriction></Conditions>
</Assertion>`)
	_, err := saml.ValidateAndMap(cfg, raw, saml.ValidateOptions{Trust: saml.TrustMaterial{PublicKey: pub}})
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("want missing signature, got %v", err)
	}
}

func TestSAML_POL006_GroupDenyAfterBind(t *testing.T) {
	t.Parallel()
	priv, pub := testRSA(t)
	cfg := testCfg()
	raw := buildAssertionXML(t, priv, nil)
	id, err := saml.ValidateAndMap(cfg, raw, saml.ValidateOptions{Trust: saml.TrustMaterial{PublicKey: pub}})
	if err != nil {
		t.Fatal(err)
	}
	// Overlay: group "mcp-operators" denies jenkins_get_build_logs
	ov := &policy.Overlay{
		Version: 1,
		Subjects: &policy.SubjectBindings{
			Groups: []policy.GroupBinding{{
				GroupID:   "mcp-operators",
				DenyTools: []string{"jenkins_get_build_logs"},
			}},
		},
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	subj := id.PolicySubject(contracts.ProfileID("corp"), "alice")
	d := ev.Evaluate(subj, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{})
	if d.Allowed() {
		t.Fatalf("SAML-bound group should deny tool: %+v groups=%v", d, subj.Groups)
	}
	// Different group membership
	id2 := id
	id2.Groups = []string{"readers-only"}
	subj2 := id2.PolicySubject(contracts.ProfileID("corp"), "alice")
	d2 := ev.Evaluate(subj2, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{})
	if d2.Denied() {
		t.Fatalf("unmatched groups should allow: %+v", d2)
	}
}

func TestSAML_AdminRoleMap(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	role, g, err := saml.ResolveAdminRole(cfg, []string{"other", "mcp-operators"})
	if err != nil || role != "operator" || g != "mcp-operators" {
		t.Fatalf("role=%q g=%q err=%v", role, g, err)
	}
	// Most privileged wins
	role, _, err = saml.ResolveAdminRole(cfg, []string{"mcp-viewers", "mcp-admins"})
	if err != nil || role != "policy_admin" {
		t.Fatalf("want policy_admin, got %q err=%v", role, err)
	}
	// Unmapped
	_, _, err = saml.ResolveAdminRole(cfg, []string{"contractors"})
	if err == nil {
		t.Fatal("unmapped must fail closed")
	}
	// Canary: error free of assertion bodies
	if strings.Contains(err.Error(), "<Assertion") {
		t.Fatal("error must not contain assertion XML")
	}
}

func TestSAML_ConfigLoadAndStatusSecretFree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "saml.json")
	raw := `{
		"schema_version": 1,
		"enabled": true,
		"sp_entity_id": "https://mcp.example/sp",
		"acs_url": "https://mcp.example/acs",
		"idp_entity_id": "https://idp.example",
		"attribute_map": {"groups_attribute": "groups"},
		"group_roles": {"ops": "operator"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := saml.LoadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st := cfg.StatusMap()
	blob := fmt.Sprintf("%v", st)
	if strings.Contains(blob, "BEGIN CERTIFICATE") {
		t.Fatalf("status leaks cert: %s", blob)
	}
	// full filesystem path should not appear (basename honesty only if we ever include path)
	if strings.Contains(blob, dir) {
		t.Fatalf("status leaks directory path: %s", blob)
	}
}

func TestSAML_TrustPEMRoundTrip(t *testing.T) {
	t.Parallel()
	priv, _ := testRSA(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	dir := t.TempDir()
	p := filepath.Join(dir, "idp.pem")
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	trust, err := saml.LoadTrustFromPEMFile(p)
	if err != nil || trust.PublicKey == nil {
		t.Fatalf("trust: %+v err=%v", trust, err)
	}
}

func TestSAML_DecodeSAMLResponse(t *testing.T) {
	t.Parallel()
	priv, pub := testRSA(t)
	raw := buildAssertionXML(t, priv, nil)
	b64 := base64.StdEncoding.EncodeToString(raw)
	decoded, err := saml.DecodeSAMLResponse(b64)
	if err != nil {
		t.Fatal(err)
	}
	id, err := saml.ValidateAndMap(testCfg(), decoded, saml.ValidateOptions{Trust: saml.TrustMaterial{PublicKey: pub}})
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject == "" {
		t.Fatal("empty subject")
	}
}
