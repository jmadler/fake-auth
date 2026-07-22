package email

import (
	"os"
	"testing"
)

func TestLoadFromEnv_NotConfigured(t *testing.T) {
	os.Unsetenv("SMTP_HOST")
	c := LoadFromEnv()
	if c != nil {
		t.Error("LoadFromEnv should return nil when SMTP_HOST unset")
	}
}

func TestLoadFromEnv_Configured(t *testing.T) {
	os.Setenv("SMTP_HOST", "smtp.example.com")
	os.Setenv("SMTP_USER", "user")
	os.Setenv("SMTP_PASS", "pass")
	os.Setenv("SMTP_FROM", "from@example.com")
	defer func() {
		os.Unsetenv("SMTP_HOST")
		os.Unsetenv("SMTP_USER")
		os.Unsetenv("SMTP_PASS")
		os.Unsetenv("SMTP_FROM")
	}()
	c := LoadFromEnv()
	if c == nil {
		t.Fatal("LoadFromEnv should return config")
	}
	if c.Host != "smtp.example.com" {
		t.Errorf("Host = %q", c.Host)
	}
	if c.From != "from@example.com" {
		t.Errorf("From = %q", c.From)
	}
}

func TestLoadFromEnv_FromDefaultsToUser(t *testing.T) {
	os.Setenv("SMTP_HOST", "smtp.example.com")
	os.Setenv("SMTP_USER", "noreply@example.com")
	os.Unsetenv("SMTP_FROM")
	defer func() {
		os.Unsetenv("SMTP_HOST")
		os.Unsetenv("SMTP_USER")
	}()
	c := LoadFromEnv()
	if c.From != "noreply@example.com" {
		t.Errorf("From should default to User, got %q", c.From)
	}
}

func TestSendMagicLink_NilConfig(t *testing.T) {
	var cfg *Config
	// When cfg is nil, SendMagicLink returns nil (no-op)
	err := cfg.SendMagicLink("user@example.com", "https://example.com/verify?token=abc")
	if err != nil {
		t.Errorf("SendMagicLink with nil config should return nil, got %v", err)
	}
}
