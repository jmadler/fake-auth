package sms

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// SendOTP sends a 6-digit OTP to the given phone number.
// Uses Twilio if TWILIO_* env vars are set, otherwise generic SMS_API_URL.
// Returns nil if sent successfully or if no provider configured (no-op).
func SendOTP(phone, code string) error {
	phone = normalizePhone(phone)
	if phone == "" || code == "" {
		return fmt.Errorf("phone and code required")
	}
	body := fmt.Sprintf("Your verification code is: %s", code)

	// Twilio
	if sid := os.Getenv("TWILIO_ACCOUNT_SID"); sid != "" {
		return sendViaTwilio(phone, body, sid)
	}

	// Generic SMS API
	if apiURL := os.Getenv("SMS_API_URL"); apiURL != "" {
		return sendViaGenericAPI(phone, body, apiURL)
	}

	return nil // no provider configured; no-op
}

func normalizePhone(phone string) string {
	phone = strings.TrimSpace(strings.TrimPrefix(phone, "+"))
	if phone == "" {
		return ""
	}
	return "+" + phone
}

func sendViaTwilio(to, body, accountSID string) error {
	authToken := os.Getenv("TWILIO_AUTH_TOKEN")
	from := os.Getenv("TWILIO_FROM")
	if authToken == "" || from == "" {
		return fmt.Errorf("TWILIO_AUTH_TOKEN and TWILIO_FROM required for Twilio")
	}

	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", accountSID)
	data := url.Values{}
	data.Set("To", to)
	data.Set("From", from)
	data.Set("Body", body)

	req, err := http.NewRequest("POST", apiURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(accountSID, authToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("twilio api error: status %d", resp.StatusCode)
	}
	return nil
}

func sendViaGenericAPI(to, body, apiURL string) error {
	apiKey := os.Getenv("SMS_API_KEY")

	// Generic API expects JSON: {"to": "+1...", "body": "..."} or form
	data := url.Values{}
	data.Set("to", to)
	data.Set("body", body)
	// Some providers use "message" or "text"
	data.Set("message", body)
	data.Set("phone", to)

	req, err := http.NewRequest("POST", apiURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("X-API-Key", apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sms api error: status %d", resp.StatusCode)
	}
	return nil
}

// IsConfigured returns true if an SMS provider is configured.
func IsConfigured() bool {
	return os.Getenv("TWILIO_ACCOUNT_SID") != "" || os.Getenv("SMS_API_URL") != ""
}
