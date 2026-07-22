package sms

import (
	"os"
	"testing"
)

func TestNormalizePhone(t *testing.T) {
	// normalizePhone is unexported - test via SendOTP error path
	// SendOTP with empty phone returns error
	err := SendOTP("", "123456")
	if err == nil {
		t.Error("SendOTP with empty phone should error")
	}
	err = SendOTP("  ", "123456")
	if err == nil {
		t.Error("SendOTP with blank phone should error")
	}
}

func TestSendOTP_NoProvider(t *testing.T) {
	os.Unsetenv("TWILIO_ACCOUNT_SID")
	os.Unsetenv("SMS_API_URL")
	// No provider: returns nil (no-op)
	err := SendOTP("+15551234567", "123456")
	if err != nil {
		t.Errorf("SendOTP with no provider should return nil, got %v", err)
	}
}

func TestSendOTP_EmptyCode(t *testing.T) {
	err := SendOTP("+15551234567", "")
	if err == nil {
		t.Error("SendOTP with empty code should error")
	}
}

func TestIsConfigured(t *testing.T) {
	os.Unsetenv("TWILIO_ACCOUNT_SID")
	os.Unsetenv("SMS_API_URL")
	if IsConfigured() {
		t.Error("IsConfigured should be false when no provider set")
	}
	os.Setenv("TWILIO_ACCOUNT_SID", "test")
	defer os.Unsetenv("TWILIO_ACCOUNT_SID")
	if !IsConfigured() {
		t.Error("IsConfigured should be true when Twilio SID set")
	}
	os.Unsetenv("TWILIO_ACCOUNT_SID")
	os.Setenv("SMS_API_URL", "https://api.example.com/sms")
	defer os.Unsetenv("SMS_API_URL")
	if !IsConfigured() {
		t.Error("IsConfigured should be true when SMS_API_URL set")
	}
}

func TestSendOTP_ValidPhoneFormat(t *testing.T) {
	os.Unsetenv("TWILIO_ACCOUNT_SID")
	os.Unsetenv("SMS_API_URL")
	// Valid phone with leading + - no provider so returns nil
	err := SendOTP("+15551234567", "123456")
	if err != nil {
		t.Errorf("SendOTP valid phone, no provider: %v", err)
	}
	// Phone without + gets normalized
	err = SendOTP("15551234567", "123456")
	if err != nil {
		t.Errorf("SendOTP without +: %v", err)
	}
}
