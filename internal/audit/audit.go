package audit

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

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
	mu     sync.Mutex
	logger *log.Logger
)

func init() {
	logger = log.New(os.Stdout, "[audit] ", log.LstdFlags)
}

// SetOutput sets the output for audit logging. Used for testing.
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	logger = log.New(w, "[audit] ", log.LstdFlags)
}

// Log writes an audit event. Safe for concurrent use.
func Log(evt Event) {
	evt.Time = time.Now()
	mu.Lock()
	defer mu.Unlock()
	b, _ := json.Marshal(evt)
	logger.Println(string(b))
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
