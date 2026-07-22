package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Sensitive keys that must never be logged. Values are redacted.
var sensitiveKeys = map[string]bool{
	"client_secret": true, "password": true, "access_token": true,
	"refresh_token": true, "id_token": true, "token": true,
	"secret": true, "code": true, "code_verifier": true,
	"authorization": true,
}

// Event represents an audit log entry.
type Event struct {
	Time       time.Time              `json:"time"`
	Type       string                 `json:"type"`
	UserID     string                 `json:"user_id,omitempty"`
	Email      string                 `json:"email,omitempty"`
	ClientID   string                 `json:"client_id,omitempty"`
	Success    bool                   `json:"success"`
	Details    map[string]interface{} `json:"details,omitempty"`
	IP         string                 `json:"ip,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
}

var (
	mu          sync.Mutex
	logger      *log.Logger
	webhookURL  string
	webhookMu   sync.RWMutex
)

func init() {
	logger = log.New(os.Stdout, "[audit] ", log.LstdFlags)
}

// SetWebhookURL configures an optional webhook. When set and AUDIT_STORE is db or stdout,
// each audit event is POSTed (JSON) to the URL. Fire-and-forget; does not block.
func SetWebhookURL(url string) {
	webhookMu.Lock()
	defer webhookMu.Unlock()
	webhookURL = strings.TrimSpace(url)
}

func getWebhookURL() string {
	webhookMu.RLock()
	defer webhookMu.RUnlock()
	return webhookURL
}

// SetOutput sets the output for audit logging. Used for testing.
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	logger = log.New(w, "[audit] ", log.LstdFlags)
}

// Redact returns a copy of m with sensitive keys replaced by "[REDACTED]".
func Redact(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		keyLower := strings.ToLower(k)
		if sensitiveKeys[keyLower] {
			out[k] = "[REDACTED]"
			continue
		}
		// Recursively redact nested maps
		if nested, ok := v.(map[string]interface{}); ok {
			out[k] = Redact(nested)
		} else {
			out[k] = v
		}
	}
	return out
}

// Log writes an audit event. Safe for concurrent use.
// Sensitive fields (client_secret, password, tokens) in Details are redacted.
// When an AuditStore is configured (e.g. via SetStore), events are sent there;
// otherwise they are written to stdout.
// When SetWebhookURL is configured, events are also POSTed to the webhook (fire-and-forget).
func Log(evt Event) {
	evt.Time = time.Now()
	if evt.Details != nil {
		evt.Details = Redact(evt.Details)
	}
	if s := getStore(); s != nil {
		s.Append(context.Background(), evt)
	} else {
		mu.Lock()
		b, _ := json.Marshal(evt)
		logger.Println(string(b))
		mu.Unlock()
	}
	if url := getWebhookURL(); url != "" {
		go postWebhook(evt, url)
	}
}

// LogLogin records a login attempt.
func LogLogin(userID, email, clientID string, success bool, details map[string]interface{}) {
	Log(Event{
		Type:     "login",
		UserID:   userID,
		Email:    email,
		ClientID: clientID,
		Success:  success,
		Details:  details,
	})
}

// LogSignup records a user signup.
func LogSignup(userID, email string, details map[string]interface{}) {
	Log(Event{
		Type:     "signup",
		UserID:   userID,
		Email:    email,
		Success:  true,
		Details:  details,
	})
}

// LogToken records a token issuance.
func LogToken(grantType, userID, clientID string, success bool, details map[string]interface{}) {
	Log(Event{
		Type:     "token",
		UserID:   userID,
		ClientID: clientID,
		Success:  success,
		Details:  mergeMap(details, map[string]interface{}{"grant_type": grantType}),
	})
}

// LogUserChange records user updates (PATCH, delete, etc.).
func LogUserChange(action, userID string, success bool, details map[string]interface{}) {
	Log(Event{
		Type:    "user_change",
		UserID:  userID,
		Success: success,
		Details: mergeMap(details, map[string]interface{}{"action": action}),
	})
}

func postWebhook(evt Event, url string) {
	payload := map[string]interface{}{
		"event_type": evt.Type,
		"timestamp":  evt.Time,
		"user_id":    evt.UserID,
		"client_id":  evt.ClientID,
		"details":    evt.Details,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	_, _ = client.Do(req) // fire-and-forget; ignore response
}

func mergeMap(a, b map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{})
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
