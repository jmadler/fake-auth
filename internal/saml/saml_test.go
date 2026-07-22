package saml

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDecodeSAMLRequest_Empty(t *testing.T) {
	_, err := DecodeSAMLRequest("")
	if err == nil {
		t.Error("Empty SAMLRequest should fail")
	}
}

func TestDecodeSAMLRequest_RawBase64(t *testing.T) {
	raw := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id1" Version="2.0"/>`
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	decoded, err := DecodeSAMLRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeSAMLRequest: %v", err)
	}
	if string(decoded) != raw {
		t.Errorf("decoded %q, want %q", decoded, raw)
	}
}

func TestParseAuthnRequest(t *testing.T) {
	xml := `<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="req1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" AssertionConsumerServiceURL="https://sp.example.com/acs"/>`
	req, err := ParseAuthnRequest([]byte(xml))
	if err != nil {
		t.Fatalf("ParseAuthnRequest: %v", err)
	}
	if req.ID != "req1" {
		t.Errorf("ID = %q", req.ID)
	}
	if req.AssertionConsumerServiceURL != "https://sp.example.com/acs" {
		t.Errorf("ACSURL = %q", req.AssertionConsumerServiceURL)
	}
}

func TestParseAuthnRequestFromParam(t *testing.T) {
	xml := `<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="p1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"/>`
	encoded := base64.StdEncoding.EncodeToString([]byte(xml))
	req, err := ParseAuthnRequestFromParam(encoded)
	if err != nil {
		t.Fatalf("ParseAuthnRequestFromParam: %v", err)
	}
	if req.ID != "p1" {
		t.Errorf("ID = %q", req.ID)
	}
}

func TestBuildMetadata(t *testing.T) {
	cfg := Config{
		EntityID: "https://auth.example.com",
		CertPEM:  `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRK5fMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAvK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7
fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG
8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJwIDAQABo1MwUTAd
BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFJ0Z8K0Z8K0Z8
K0Z8K0Z8K0Z8K0Z8MB8GA1UdIwQYMBaAFJ0Z8K0Z8K0Z8K0Z8K0Z8K0Z8K0Z8MA0G
CSqGSIb3DQEBCwUAA4IBAQBvK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG
8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8nJ3vK7fG8
-----END CERTIFICATE-----`,
		BaseURL: "https://auth.example.com",
	}
	meta, err := BuildMetadata(cfg)
	if err != nil {
		t.Fatalf("BuildMetadata: %v", err)
	}
	s := string(meta)
	if !strings.Contains(s, "EntityDescriptor") {
		t.Error("Metadata should contain EntityDescriptor")
	}
	if !strings.Contains(s, cfg.EntityID) {
		t.Error("Metadata should contain entity ID")
	}
}

