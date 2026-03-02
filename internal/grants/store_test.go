package grants

import (
	"testing"
	"time"
)

func TestAuthCodeStore(t *testing.T) {
	s := NewStore(1*time.Minute, 24*time.Hour)
	ac := &AuthCode{UserID: "user|1", ClientID: "client", RedirectURI: "http://localhost/cb", Scope: "openid"}
	s.SaveCode("code123", ac)
	consumed, ok := s.ConsumeCode("code123")
	if !ok {
		t.Fatal("expected to consume code")
	}
	if consumed.UserID != "user|1" {
		t.Errorf("UserID = %q, want user|1", consumed.UserID)
	}
	_, ok = s.ConsumeCode("code123")
	if ok {
		t.Fatal("code should be consumed (one-time use)")
	}
}

func TestAuthCodeExpiry(t *testing.T) {
	s := NewStore(1*time.Millisecond, 24*time.Hour)
	s.SaveCode("code123", &AuthCode{UserID: "user|1", ClientID: "c", RedirectURI: "http://x", Scope: "openid"})
	time.Sleep(10 * time.Millisecond)
	_, ok := s.ConsumeCode("code123")
	if ok {
		t.Fatal("expired code should not be consumable")
	}
}

func TestRefreshTokenStore(t *testing.T) {
	s := NewStore(1*time.Minute, 24*time.Hour)
	rg := &RefreshGrant{UserID: "user|1", ClientID: "client", Scope: "openid offline_access"}
	s.SaveRefreshToken("rt_abc", rg)
	consumed, ok := s.ConsumeRefreshToken("rt_abc")
	if !ok {
		t.Fatal("expected to consume refresh token")
	}
	if consumed.UserID != "user|1" {
		t.Errorf("UserID = %q, want user|1", consumed.UserID)
	}
	_, ok = s.ConsumeRefreshToken("rt_abc")
	if ok {
		t.Fatal("refresh token should be consumed (one-time use)")
	}
}

func TestDeviceCodeSaveAndConsume(t *testing.T) {
	s := NewStore(1*time.Minute, 24*time.Hour)
	dc := &DeviceCode{
		DeviceCode: "dev_abc123",
		UserCode:   "ABCD-EFGH",
		ClientID:   "client1",
		Scope:      "openid offline_access",
		Audience:   "",
	}
	s.SaveDeviceCode("dev_abc123", "ABCD-EFGH", dc)

	ok := s.AuthorizeDeviceCode("ABCD-EFGH", "user|1")
	if !ok {
		t.Fatal("AuthorizeDeviceCode should succeed")
	}

	grant, ok := s.ConsumeDeviceCode("dev_abc123")
	if !ok {
		t.Fatal("ConsumeDeviceCode should return grant after authorization")
	}
	if grant.UserID != "user|1" {
		t.Errorf("UserID = %q, want user|1", grant.UserID)
	}
	if grant.ClientID != "client1" {
		t.Errorf("ClientID = %q, want client1", grant.ClientID)
	}

	_, ok = s.ConsumeDeviceCode("dev_abc123")
	if ok {
		t.Fatal("device code should be consumed (one-time use)")
	}
}

func TestDeviceCodeExpired(t *testing.T) {
	s := NewStore(1*time.Minute, 24*time.Hour, 1*time.Millisecond)
	dc := &DeviceCode{
		DeviceCode: "dev_expired",
		UserCode:   "WXYZ-1234",
		ClientID:   "client1",
		Scope:      "openid",
	}
	s.SaveDeviceCode("dev_expired", "WXYZ-1234", dc)
	s.AuthorizeDeviceCode("WXYZ-1234", "user|1")

	time.Sleep(10 * time.Millisecond)

	_, ok := s.ConsumeDeviceCode("dev_expired")
	if ok {
		t.Fatal("expired device code should not be consumable")
	}
}

func TestDeviceCodeNotAuthorized(t *testing.T) {
	s := NewStore(1*time.Minute, 24*time.Hour)
	dc := &DeviceCode{
		DeviceCode: "dev_unauth",
		UserCode:   "MNOP-QRST",
		ClientID:   "client1",
		Scope:      "openid",
	}
	s.SaveDeviceCode("dev_unauth", "MNOP-QRST", dc)
	// Do NOT call AuthorizeDeviceCode

	_, ok := s.ConsumeDeviceCode("dev_unauth")
	if ok {
		t.Fatal("ConsumeDeviceCode should fail when device code not authorized")
	}
}
