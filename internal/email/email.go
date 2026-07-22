package email

import (
	"fmt"
	"net/smtp"
	"os"
	"strings"
)

// Config holds SMTP configuration from env.
type Config struct {
	Host string
	User string
	Pass string
	From string
}

// LoadFromEnv reads SMTP_* env vars. Returns nil if not configured.
func LoadFromEnv() *Config {
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		return nil
	}
	c := &Config{Host: host}
	c.User = os.Getenv("SMTP_USER")
	c.Pass = os.Getenv("SMTP_PASS")
	c.From = os.Getenv("SMTP_FROM")
	if c.From == "" && c.User != "" {
		c.From = c.User
	}
	return c
}

// SendMagicLink sends a magic link email. No-op if cfg is nil.
func (c *Config) SendMagicLink(to, link string) error {
	if c == nil {
		return nil
	}
	subject := "Sign in to your account"
	body := fmt.Sprintf("Click the link below to sign in:\n\n%s\n\nThis link expires in 1 hour.", link)
	return c.send(to, subject, body)
}

func (c *Config) send(to, subject, body string) error {
	if c.Host == "" {
		return nil
	}
	msg := []byte(
		"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"Content-Type: text/plain; charset=UTF-8\r\n" +
			"\r\n" + body + "\r\n")
	hostPort := c.Host
	if !strings.Contains(hostPort, ":") {
		hostPort = hostPort + ":587"
	}
	host := c.Host
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	auth := smtp.PlainAuth("", c.User, c.Pass, host)
	return smtp.SendMail(hostPort, auth, c.From, []string{to}, msg)
}
