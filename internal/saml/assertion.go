package saml

import (
	"encoding/base64"
	"encoding/xml"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// ParsedAssertion is the secret-free structural view of a SAML Assertion.
// SignatureValue is base64 RSA-SHA256 over SHA256(SignedPayload).
type ParsedAssertion struct {
	ID                string
	Issuer            string
	NameID            string
	Audience          string
	Recipient         string
	NotBefore         time.Time
	NotOnOrAfter      time.Time
	Attributes        AttributeValues
	SignatureValueB64 string
	// SignedPayload is the exact byte slice that was signed (fixture contract).
	// When empty, validators use CanonicalPayload().
	SignedPayload []byte
}

// xmlAssertion is a minimal SAML Assertion shape for offline fixtures.
type xmlAssertion struct {
	XMLName      xml.Name `xml:"Assertion"`
	ID           string   `xml:"ID,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Issuer       string   `xml:"Issuer"`
	Signature    *xmlSig  `xml:"Signature"`
	Subject      xmlSubject
	Conditions   xmlConditions
	Attributes   xmlAttributeStatement `xml:"AttributeStatement"`
}

type xmlSig struct {
	SignatureValue string `xml:"SignatureValue"`
}

type xmlSubject struct {
	NameID              string `xml:"NameID"`
	SubjectConfirmation *struct {
		SubjectConfirmationData *struct {
			Recipient    string `xml:"Recipient,attr"`
			NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
		} `xml:"SubjectConfirmationData"`
	} `xml:"SubjectConfirmation"`
}

type xmlConditions struct {
	NotBefore    string `xml:"NotBefore,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	Audience     string `xml:"AudienceRestriction>Audience"`
}

type xmlAttributeStatement struct {
	Attributes []xmlAttribute `xml:"Attribute"`
}

type xmlAttribute struct {
	Name   string   `xml:"Name,attr"`
	Values []string `xml:"AttributeValue"`
}

// ParseAssertionXML parses a SAML Assertion element (or Response/Assertion wrapper lite).
func ParseAssertionXML(raw []byte) (ParsedAssertion, error) {
	raw = bytesTrimSpace(raw)
	if len(raw) == 0 {
		return ParsedAssertion{}, apperr.New(apperr.CodeInvalidArgument, "saml assertion is empty")
	}
	// Allow full Response wrapper: extract first Assertion block if needed.
	payload := raw
	if !bytesContains(raw, []byte("<Assertion")) && bytesContains(raw, []byte("<Assertion ")) {
		// no-op
	}
	// If this is a Response, try to find Assertion sub-document.
	if bytesContains(raw, []byte("<Response")) || bytesContains(raw, []byte(":Response")) {
		if sub, ok := extractElement(raw, "Assertion"); ok {
			payload = sub
		}
	}

	var xa xmlAssertion
	if err := xml.Unmarshal(payload, &xa); err != nil {
		return ParsedAssertion{}, apperr.Wrap(apperr.CodeInvalidArgument, "saml assertion XML invalid", err)
	}
	if strings.TrimSpace(xa.Issuer) == "" && strings.TrimSpace(xa.ID) == "" {
		return ParsedAssertion{}, apperr.New(apperr.CodeInvalidArgument, "saml assertion missing issuer/id")
	}

	attrs := make(AttributeValues)
	for _, a := range xa.Attributes.Attributes {
		name := strings.TrimSpace(a.Name)
		if name == "" {
			continue
		}
		for _, v := range a.Values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			attrs[name] = append(attrs[name], v)
		}
	}

	pa := ParsedAssertion{
		ID:         strings.TrimSpace(xa.ID),
		Issuer:     strings.TrimSpace(xa.Issuer),
		NameID:     strings.TrimSpace(xa.Subject.NameID),
		Audience:   strings.TrimSpace(xa.Conditions.Audience),
		Attributes: attrs,
	}
	if xa.Signature != nil {
		pa.SignatureValueB64 = strings.TrimSpace(xa.Signature.SignatureValue)
	}
	if xa.Subject.SubjectConfirmation != nil && xa.Subject.SubjectConfirmation.SubjectConfirmationData != nil {
		pa.Recipient = strings.TrimSpace(xa.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient)
		t, err := parseSecurityTimeAttr("SubjectConfirmationData.NotOnOrAfter", xa.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter)
		if err != nil {
			return ParsedAssertion{}, err
		}
		if !t.IsZero() && (pa.NotOnOrAfter.IsZero() || t.Before(pa.NotOnOrAfter)) {
			pa.NotOnOrAfter = t
		}
	}
	nb, err := parseSecurityTimeAttr("Conditions.NotBefore", xa.Conditions.NotBefore)
	if err != nil {
		return ParsedAssertion{}, err
	}
	if !nb.IsZero() {
		pa.NotBefore = nb
	}
	noa, err := parseSecurityTimeAttr("Conditions.NotOnOrAfter", xa.Conditions.NotOnOrAfter)
	if err != nil {
		return ParsedAssertion{}, err
	}
	if !noa.IsZero() && (pa.NotOnOrAfter.IsZero() || noa.Before(pa.NotOnOrAfter)) {
		pa.NotOnOrAfter = noa
	}
	// Signed payload = assertion without Signature element (fixture contract).
	pa.SignedPayload = stripSignatureElement(payload)
	return pa, nil
}

// DecodeSAMLResponse decodes a base64 SAMLResponse form field (POST binding lite).
func DecodeSAMLResponse(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "SAMLResponse is empty")
	}
	// Tolerate whitespace in form posts.
	b64 = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, b64)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeInvalidArgument, "SAMLResponse is not valid base64", err)
		}
	}
	return raw, nil
}

// parseSecurityTimeAttr parses a security-critical SAML timestamp attribute.
// Absent (empty) is not an error here — ValidateParsed enforces presence of
// the expiry. Present-but-malformed fails closed: previously a malformed
// timestamp was silently treated as "absent", which used to mean the
// assertion had no time bound at all.
func parseSecurityTimeAttr(attr, raw string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, nil
	}
	t, err := parseSAMLTime(raw)
	if err != nil {
		return time.Time{}, apperr.New(apperr.CodeInvalidArgument,
			"saml assertion has malformed "+attr+" timestamp")
	}
	return t, nil
}

func parseSAMLTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, apperr.New(apperr.CodeInvalidArgument, "empty time")
	}
	// RFC3339 and SAML common formats.
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	return time.ParseInLocation("2006-01-02T15:04:05.999Z07:00", s, time.UTC)
}

func stripSignatureElement(raw []byte) []byte {
	// Remove <Signature>...</Signature> including ds: prefix variants (non-greedy-ish scan).
	s := string(raw)
	for {
		start := indexFold(s, "<Signature")
		if start < 0 {
			start = indexFold(s, ":Signature")
			if start < 0 {
				break
			}
			// back up to '<'
			for start > 0 && s[start] != '<' {
				start--
			}
		}
		endTag := "</Signature>"
		end := indexFold(s[start:], endTag)
		if end < 0 {
			// self-closing or malformed — stop
			break
		}
		end = start + end + len(endTag)
		s = s[:start] + s[end:]
	}
	return []byte(s)
}

func indexFold(s, sub string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(sub))
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func bytesContains(b, sub []byte) bool {
	return strings.Contains(string(b), string(sub))
}

func extractElement(raw []byte, local string) ([]byte, bool) {
	s := string(raw)
	// Find <local or :local
	open := indexFold(s, "<"+local)
	if open < 0 {
		open = indexFold(s, ":"+local)
		if open < 0 {
			return nil, false
		}
		for open > 0 && s[open] != '<' {
			open--
		}
	}
	closeTag := "</" + local + ">"
	closeIdx := indexFold(s[open:], closeTag)
	if closeIdx < 0 {
		// try with namespace prefix on close — scan for </
		rest := s[open:]
		// crude: find last matching close
		ci := strings.LastIndex(strings.ToLower(rest), strings.ToLower(local+">"))
		if ci < 0 {
			return nil, false
		}
		// include </ns:local>
		startClose := ci
		for startClose > 0 && rest[startClose] != '<' {
			startClose--
		}
		return []byte(rest[:startClose+len(rest[startClose:ci])+len(local)+1]), true
	}
	end := open + closeIdx + len(closeTag)
	return []byte(s[open:end]), true
}
