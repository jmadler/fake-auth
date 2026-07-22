package audit

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestLog(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer SetOutput(os.Stdout)

	Log(Event{
		Type:    "custom",
		UserID:  "user|123",
		Success: true,
	})

	out := buf.String()
	if !strings.Contains(out, `"type":"custom"`) {
		t.Errorf("output should contain type: %q", out)
	}
	if !strings.Contains(out, `"user_id":"user|123"`) {
		t.Errorf("output should contain user_id: %q", out)
	}
	if !strings.Contains(out, `"success":true`) {
		t.Errorf("output should contain success: %q", out)
	}
}

func TestLogLogin(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer SetOutput(os.Stdout)

	LogLogin("user|456", "u@example.com", "client1", true, nil)

	out := buf.String()
	if !strings.Contains(out, `"type":"login"`) {
		t.Errorf("output should contain type login: %q", out)
	}
	if !strings.Contains(out, `"user_id":"user|456"`) {
		t.Errorf("output should contain user_id: %q", out)
	}
	if !strings.Contains(out, `"email":"u@example.com"`) {
		t.Errorf("output should contain email: %q", out)
	}
	if !strings.Contains(out, `"client_id":"client1"`) {
		t.Errorf("output should contain client_id: %q", out)
	}
	if !strings.Contains(out, `"success":true`) {
		t.Errorf("output should contain success: %q", out)
	}
}

func TestLogSignup(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer SetOutput(os.Stdout)

	LogSignup("user|789", "new@example.com", nil)

	out := buf.String()
	if !strings.Contains(out, `"type":"signup"`) {
		t.Errorf("output should contain type signup: %q", out)
	}
	if !strings.Contains(out, `"user_id":"user|789"`) {
		t.Errorf("output should contain user_id: %q", out)
	}
	if !strings.Contains(out, `"email":"new@example.com"`) {
		t.Errorf("output should contain email: %q", out)
	}
	if !strings.Contains(out, `"success":true`) {
		t.Errorf("output should contain success: %q", out)
	}
}

func TestLogToken(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer SetOutput(os.Stdout)

	LogToken("authorization_code", "user|999", "client2", true, nil)

	out := buf.String()
	if !strings.Contains(out, `"type":"token"`) {
		t.Errorf("output should contain type token: %q", out)
	}
	if !strings.Contains(out, `"user_id":"user|999"`) {
		t.Errorf("output should contain user_id: %q", out)
	}
	if !strings.Contains(out, `"client_id":"client2"`) {
		t.Errorf("output should contain client_id: %q", out)
	}
	if !strings.Contains(out, `"success":true`) {
		t.Errorf("output should contain success: %q", out)
	}
	if !strings.Contains(out, `"grant_type":"authorization_code"`) {
		t.Errorf("output should contain grant_type in details: %q", out)
	}
}

func TestRedact(t *testing.T) {
	m := map[string]interface{}{
		"client_secret": "my-secret",
		"password":      "pwd123",
		"access_token":  "eyJ...",
		"grant_type":    "password",
		"safe_field":    "ok",
	}
	redacted := Redact(m)
	if redacted["client_secret"] != "[REDACTED]" {
		t.Errorf("client_secret should be redacted, got %v", redacted["client_secret"])
	}
	if redacted["password"] != "[REDACTED]" {
		t.Errorf("password should be redacted, got %v", redacted["password"])
	}
	if redacted["access_token"] != "[REDACTED]" {
		t.Errorf("access_token should be redacted, got %v", redacted["access_token"])
	}
	if redacted["grant_type"] != "password" {
		t.Errorf("grant_type should not be redacted, got %v", redacted["grant_type"])
	}
	if redacted["safe_field"] != "ok" {
		t.Errorf("safe_field should not be redacted, got %v", redacted["safe_field"])
	}
}

func TestLogRedactsSensitiveDetails(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer SetOutput(os.Stdout)

	Log(Event{
		Type:    "login",
		Success: false,
		Details: map[string]interface{}{
			"password":     "secret123",
			"client_id":    "abc",
			"reason":       "invalid_credentials",
		},
	})

	out := buf.String()
	if strings.Contains(out, "secret123") {
		t.Errorf("password must not appear in log: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("sensitive field should be redacted: %q", out)
	}
	if !strings.Contains(out, "client_id") {
		t.Errorf("client_id is not sensitive, should appear: %q", out)
	}
}
