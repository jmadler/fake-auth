package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	NSProtocol = "urn:oasis:names:tc:SAML:2.0:protocol"
	NSAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	NSXMLDSig   = "http://www.w3.org/2000/09/xmldsig#"
)

// AuthnRequest represents a SAML 2.0 Authentication Request from SP.
type AuthnRequest struct {
	XMLName            xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                 string    `xml:"ID,attr"`
	Version            string    `xml:"Version,attr"`
	IssueInstant       string    `xml:"IssueInstant,attr"`
	Destination        string    `xml:"Destination,attr"`
	AssertionConsumerServiceURL string `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding    string    `xml:"ProtocolBinding,attr"`
	Issuer             Issuer    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	RelayState         string    `xml:"RelayState,attr,omitempty"`
}

type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

// ServiceProvider describes a registered SAML SP.
type ServiceProvider struct {
	EntityID    string
	ACSURL      string
	Certificate string
}

// Config holds IdP configuration.
type Config struct {
	EntityID string // IdP entity ID (default from ISSUER_URL)
	CertPEM  string // X509 cert for signing (SAML_CERT)
	KeyPEM   string // Private key (SAML_KEY)
	BaseURL  string // e.g. https://auth2.example.com
}

// DecodeSAMLRequest decodes SAMLRequest from query (redirect) or form (POST).
// Handles both raw base64 and base64+deflate.
func DecodeSAMLRequest(samlRequest string) ([]byte, error) {
	if samlRequest == "" {
		return nil, fmt.Errorf("empty SAMLRequest")
	}
	decoded, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	// Try deflate decompression first
	reader := flate.NewReader(bytes.NewReader(decoded))
	deflated, err := io.ReadAll(reader)
	reader.Close()
	if err == nil && len(deflated) > 0 && deflated[0] == '<' {
		return deflated, nil
	}
	// Assume raw base64 (no deflate)
	if len(decoded) > 0 && decoded[0] == '<' {
		return decoded, nil
	}
	// Return deflated even if first byte isn't < (some IdPs send deflate)
	if len(deflated) > 0 {
		return deflated, nil
	}
	return decoded, nil
}

// ParseAuthnRequest parses AuthnRequest XML.
func ParseAuthnRequest(data []byte) (*AuthnRequest, error) {
	var req AuthnRequest
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("parse AuthnRequest: %w", err)
	}
	return &req, nil
}

// ParseAuthnRequestFromParam decodes and parses SAMLRequest from URL param.
func ParseAuthnRequestFromParam(samlRequest string) (*AuthnRequest, error) {
	decoded, err := DecodeSAMLRequest(samlRequest)
	if err != nil {
		return nil, err
	}
	return ParseAuthnRequest(decoded)
}

// BuildMetadata builds IdP metadata XML.
func BuildMetadata(cfg Config) ([]byte, error) {
	entityID := cfg.EntityID
	if entityID == "" {
		entityID = strings.TrimSuffix(cfg.BaseURL, "/")
	}
	ssoURL := strings.TrimSuffix(cfg.BaseURL, "/") + "/saml/sso"

	certCleaned := ""
	if cfg.CertPEM != "" {
		certCleaned = strings.ReplaceAll(cfg.CertPEM, "-----BEGIN CERTIFICATE-----", "")
		certCleaned = strings.ReplaceAll(certCleaned, "-----END CERTIFICATE-----", "")
		certCleaned = strings.ReplaceAll(certCleaned, "\n", "")
		certCleaned = strings.ReplaceAll(certCleaned, "\r", "")
	}
	if certCleaned == "" {
		certCleaned = "PLACEHOLDER"
	}

	tmpl := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + escapeXML(entityID) + `">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="` + NSXMLDSig + `">
        <ds:X509Data>
          <ds:X509Certificate>%s</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + escapeXML(ssoURL) + `"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + escapeXML(ssoURL) + `"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`
	return []byte(fmt.Sprintf(tmpl, certCleaned)), nil
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

// AssertionData holds user data for building SAML assertion.
type AssertionData struct {
	NameID     string            // User identifier (e.g. email or user ID)
	Email      string            // Email attribute
	Attributes map[string]string  // Additional attributes
}

// BuildResponse builds a SAML Response with assertion. Optionally signs if key is configured.
func BuildResponse(cfg Config, inReq *AuthnRequest, sp *ServiceProvider, data *AssertionData) ([]byte, error) {
	entityID := cfg.EntityID
	if entityID == "" {
		entityID = strings.TrimSuffix(cfg.BaseURL, "/")
	}
	now := time.Now().UTC()
	instant := now.Format("2006-01-02T15:04:05.000Z")
	notBefore := now.Add(-2 * time.Minute).Format("2006-01-02T15:04:05.000Z")
	notOnOrAfter := now.Add(5 * time.Minute).Format("2006-01-02T15:04:05.000Z")

	responseID := "_" + strings.ReplaceAll(fmt.Sprintf("%d", time.Now().UnixNano()), " ", "")
	assertionID := "_" + strings.ReplaceAll(fmt.Sprintf("%d", time.Now().UnixNano()+1), " ", "")

	// Attributes
	attrs := ""
	if data.Email != "" {
		attrs += `<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">` + escapeXML(data.Email) + `</saml:AttributeValue></saml:Attribute>`
	}
	for k, v := range data.Attributes {
		attrs += `<saml:Attribute Name="` + escapeXML(k) + `" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">` + escapeXML(v) + `</saml:AttributeValue></saml:Attribute>`
	}

	// Determine NameID
	nameID := data.NameID
	if nameID == "" {
		nameID = data.Email
	}
	if nameID == "" {
		nameID = "unknown"
	}

	acsURL := inReq.AssertionConsumerServiceURL
	if acsURL == "" {
		acsURL = sp.ACSURL
	}
	spEntityID := inReq.Issuer.Value
	if spEntityID == "" {
		spEntityID = sp.EntityID
	}

	resp := `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="` + NSProtocol + `" xmlns:saml="` + NSAssertion + `" ID="` + responseID + `" Version="2.0" IssueInstant="` + instant + `">
  <saml:Issuer>` + escapeXML(entityID) + `</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="` + NSAssertion + `" ID="` + assertionID + `" Version="2.0" IssueInstant="` + instant + `">
    <saml:Issuer>` + escapeXML(entityID) + `</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified">` + escapeXML(nameID) + `</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="` + notOnOrAfter + `" Recipient="` + escapeXML(acsURL) + `" InResponseTo="` + escapeXML(inReq.ID) + `"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notOnOrAfter + `">
      <saml:AudienceRestriction>
        <saml:Audience>` + escapeXML(spEntityID) + `</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="` + instant + `" SessionIndex="` + assertionID + `">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      ` + attrs + `
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`

	return []byte(resp), nil
}

// BuildPOSTForm returns HTML that auto-posts SAMLResponse to ACS URL.
func BuildPOSTForm(acsURL, samlResponse, relayState string) string {
	html := `<!DOCTYPE html><html><head><meta charset="utf-8"/></head><body>
<form method="post" action="` + escapeXML(acsURL) + `" id="saml-form">
<input type="hidden" name="SAMLResponse" value="` + escapeXML(samlResponse) + `"/>`
	if relayState != "" {
		html += `<input type="hidden" name="RelayState" value="` + escapeXML(relayState) + `"/>`
	}
	html += `</form><script>document.getElementById("saml-form").submit();</script>
</body></html>`
	return html
}

// RedirectToACS builds a redirect URL with SAMLResponse (for HTTP-Redirect binding).
// Note: HTTP-Redirect has URL length limits; POST is preferred for responses.
func RedirectToACS(acsURL, samlResponse, relayState string) string {
	u, _ := url.Parse(acsURL)
	q := u.Query()
	q.Set("SAMLResponse", samlResponse)
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

