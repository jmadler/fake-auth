package acl

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/jmadler/auth2/internal/logging"
)

// Rule represents a single ACL rule. Fields are optional; empty means "match any".
type Rule struct {
	Action   string `json:"action"`   // "allow" or "deny"
	Path     string `json:"path"`     // glob pattern, e.g. "/oauth/*"
	IP       string `json:"ip"`       // CIDR, e.g. "1.2.3.0/24", or single IP
	ClientID string `json:"client_id"` // exact client_id match
}

// ACL evaluates rules in order; first match wins.
type ACL struct {
	rules []Rule
}

// LoadFromEnv reads ACL_RULES (JSON) or ACL_RULES_FILE path.
// Returns nil if no rules; middleware then allows all.
func LoadFromEnv() *ACL {
	// Inline JSON takes precedence
	if raw := os.Getenv("ACL_RULES"); raw != "" {
		var rules []Rule
		if err := json.Unmarshal([]byte(raw), &rules); err != nil {
			logging.Warn(context.Background(), "ACL_RULES invalid JSON", "error", err)
			return nil
		}
		return New(rules)
	}
	if filePath := os.Getenv("ACL_RULES_FILE"); filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			logging.Warn(context.Background(), "ACL_RULES_FILE read failed", "path", filePath, "error", err)
			return nil
		}
		var rules []Rule
		if err := json.Unmarshal(data, &rules); err != nil {
			logging.Warn(context.Background(), "ACL_RULES_FILE invalid JSON", "path", filePath, "error", err)
			return nil
		}
		return New(rules)
	}
	// Default: try acl_rules.json in cwd
	if data, err := os.ReadFile("acl_rules.json"); err == nil {
		var rules []Rule
		if err := json.Unmarshal(data, &rules); err != nil {
			logging.Warn(context.Background(), "acl_rules.json invalid JSON", "error", err)
			return nil
		}
		return New(rules)
	}
	return nil
}

// New creates an ACL with the given rules.
func New(rules []Rule) *ACL {
	if len(rules) == 0 {
		return nil
	}
	return &ACL{rules: rules}
}

// Middleware returns a handler that enforces ACL rules.
// If acl is nil, allows all. First matching rule wins.
// Denied requests receive 403 Forbidden.
func Middleware(acl *ACL) func(http.Handler) http.Handler {
	if acl == nil {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allowed := acl.Allow(r)
			if !allowed {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"access_denied","error_description":"Access denied by ACL"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Allow returns true if the request is allowed, false if denied.
// Evaluates rules in order; first match wins.
func (a *ACL) Allow(r *http.Request) bool {
	reqPath := path.Clean(r.URL.Path)
	if !strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/" {
		reqPath = strings.TrimSuffix(reqPath, "/")
	}
	reqPath = "/" + strings.TrimPrefix(reqPath, "/")
	clientIP := clientIPFromRequest(r)
	clientID := extractClientID(r)

	for _, rule := range a.rules {
		if !matchRule(rule, reqPath, clientIP, clientID) {
			continue
		}
		return strings.ToLower(rule.Action) == "allow"
	}
	// No rule matched: default allow
	return true
}

func matchRule(rule Rule, reqPath, clientIP, clientID string) bool {
	if rule.Path != "" {
		pattern := path.Clean(rule.Path)
		pattern = "/" + strings.TrimPrefix(pattern, "/")
		matched := false
		if ok, err := path.Match(pattern, reqPath); err == nil && ok {
			matched = true
		} else if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if prefix == "" || prefix == "/" {
				prefix = "/"
			}
			if strings.HasPrefix(reqPath, prefix) {
				rest := strings.TrimPrefix(reqPath, prefix)
				if rest == "" || rest == "/" || strings.HasPrefix(rest, "/") {
					matched = true
				}
			}
		}
		if !matched {
			return false
		}
	}
	if rule.IP != "" {
		if clientIP == "" {
			return false
		}
		if strings.Contains(rule.IP, "/") {
			_, network, err := net.ParseCIDR(rule.IP)
			if err != nil {
				return false
			}
			ip := net.ParseIP(clientIP)
			if ip == nil || !network.Contains(ip) {
				return false
			}
		} else {
			allowedIP := net.ParseIP(rule.IP)
			if allowedIP == nil || allowedIP.String() != clientIP {
				return false
			}
		}
	}
	if rule.ClientID != "" {
		if clientID == "" || rule.ClientID != clientID {
			return false
		}
	}
	return true
}

func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func extractClientID(r *http.Request) string {
	// Query param (authorize, etc.)
	if cid := r.URL.Query().Get("client_id"); cid != "" {
		return strings.TrimSpace(cid)
	}
	// Header
	if cid := r.Header.Get("X-Client-ID"); cid != "" {
		return strings.TrimSpace(cid)
	}
	// POST body: form or JSON (read and restore body so downstream handlers can use it)
	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return ""
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "application/json") {
			var params map[string]interface{}
			if json.Unmarshal(body, &params) == nil {
				if v, ok := params["client_id"].(string); ok && v != "" {
					return strings.TrimSpace(v)
				}
			}
		} else {
			vals, err := url.ParseQuery(string(body))
			if err == nil {
				return strings.TrimSpace(vals.Get("client_id"))
			}
		}
	}
	return ""
}
