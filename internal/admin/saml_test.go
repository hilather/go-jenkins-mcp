package admin_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/admin"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/saml"
)

func TestAdminSAML_ACS_RoleMap_AndCanary(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mem := &audit.Memory{}
	cfg := admin.Config{
		Addr:        admin.DefaultAddr,
		Role:        admin.RoleViewer,
		BearerToken: "pilot-token-not-for-saml",
		SAML: admin.SAMLOptions{
			Config: saml.Config{
				SchemaVersion: 1,
				Enabled:       true,
				Require:       false,
				SPEntityID:    "https://mcp.example/sp",
				ACSURL:        "https://mcp.example/admin/v1/saml/acs",
				IdPEntityID:   "https://idp.example/metadata",
				AttributeMap:  saml.AttributeMap{GroupsAttribute: "groups"},
				GroupRoles: map[string]string{
					"mcp-operators": "operator",
				},
			},
			Trust: saml.TrustMaterial{PublicKey: &priv.PublicKey},
			Audit: mem,
			Now:   func() time.Time { return time.Now().UTC() },
		},
	}
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Status is public and secret-free
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/saml/status", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "BEGIN") || strings.Contains(rr.Body.String(), "PRIVATE") {
		t.Fatal("status leaked trust material")
	}

	raw := buildAdminSAMLAssertion(t, priv, "mcp-operators")
	form := url.Values{}
	form.Set("SAMLResponse", base64.StdEncoding.EncodeToString(raw))
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/admin/v1/saml/acs", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("acs: %d %s", rr2.Code, rr2.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr2.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["role"] != "operator" {
		t.Fatalf("role: %v", body["role"])
	}
	// Canary: response must not contain assertion XML or full SAMLResponse
	if strings.Contains(rr2.Body.String(), "<Assertion") || strings.Contains(rr2.Body.String(), "SAMLResponse") {
		t.Fatal("ACS response leaked assertion")
	}
	// Cookie set
	var cookie *http.Cookie
	for _, c := range rr2.Result().Cookies() {
		if c.Name == admin.CookieSAMLSession {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatal("expected SAML session cookie")
	}

	// /me without token but with cookie uses operator role
	rr3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/admin/v1/me", nil)
	req3.AddCookie(cookie)
	// Bearer wrong — SAML session still authenticates when token not required-only
	// With token configured, middleware accepts SAML session OR token.
	h.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("me: %d %s", rr3.Code, rr3.Body.String())
	}
	if !strings.Contains(rr3.Body.String(), `"role":"operator"`) {
		t.Fatalf("me body: %s", rr3.Body.String())
	}

	// Unmapped groups fail closed
	rawBad := buildAdminSAMLAssertion(t, priv, "contractors-only")
	form2 := url.Values{}
	form2.Set("SAMLResponse", base64.StdEncoding.EncodeToString(rawBad))
	rr4 := httptest.NewRecorder()
	req4 := httptest.NewRequest(http.MethodPost, "/admin/v1/saml/acs", strings.NewReader(form2.Encode()))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rr4, req4)
	if rr4.Code != http.StatusForbidden {
		t.Fatalf("unmapped want 403 got %d %s", rr4.Code, rr4.Body.String())
	}

	// Audit canary: no assertion XML in memory events
	for _, ev := range mem.Events() {
		blob := fmt.Sprintf("%+v", ev)
		if strings.Contains(blob, "<Assertion") || strings.Contains(blob, base64.StdEncoding.EncodeToString(raw)[:20]) {
			t.Fatalf("audit leaked assertion material: %s", blob)
		}
	}
}

func TestAdminSAML_RequireBlocksWithoutSession(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := admin.Config{
		Addr:        admin.DefaultAddr,
		Role:        admin.RoleViewer,
		BearerToken: "secret",
		SAML: admin.SAMLOptions{
			Config: saml.Config{
				SchemaVersion: 1,
				Enabled:       true,
				Require:       true,
				SPEntityID:    "https://mcp.example/sp",
				ACSURL:        "https://mcp.example/admin/v1/saml/acs",
				IdPEntityID:   "https://idp.example/metadata",
				AttributeMap:  saml.AttributeMap{GroupsAttribute: "groups"},
				GroupRoles:    map[string]string{"mcp-viewers": "viewer"},
			},
			Trust: saml.TrustMaterial{PublicKey: &priv.PublicKey},
		},
	}
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Token alone insufficient when require=true
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("require SAML: want 401 got %d", rr.Code)
	}
}

func buildAdminSAMLAssertion(t *testing.T, priv *rsa.PrivateKey, group string) []byte {
	t.Helper()
	now := time.Now().UTC()
	nb := now.Add(-time.Minute).Format(time.RFC3339)
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
    <AudienceRestriction><Audience>https://mcp.example/sp</Audience></AudienceRestriction>
  </Conditions>
  <AttributeStatement>
    <Attribute Name="groups"><AttributeValue>%s</AttributeValue></Attribute>
  </AttributeStatement>
</Assertion>`, now.Format(time.RFC3339), na, nb, na, group)
	sig, err := saml.SignPayloadRSASHA256(priv, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	signed := strings.Replace(body, "</Issuer>",
		"</Issuer><Signature><SignatureValue>"+sig+"</SignatureValue></Signature>", 1)
	return []byte(signed)
}
