package ratelimit

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultRPM = 100
const defaultClientRPM = 200
const defaultSuspiciousFailedThreshold = 5
const defaultSuspiciousStrictRPM = 5

// Limiter performs per-IP rate limiting with a sliding window.
// Optional: when FailedTracker is set and IP is suspicious (>N failed auth attempts),
// uses StrictRPM instead of RPM.
type Limiter struct {
	mu           sync.Mutex
	counters     map[string]*window
	rpm          int
	strictRPM    int
	window       time.Duration
	cleanup      *time.Ticker
	FailedTracker *FailedAttemptTracker
}

type window struct {
	count   int
	startAt time.Time
}

// FailedAttemptTracker tracks failed auth attempts per IP. When an IP exceeds
// the threshold in the window, it is considered suspicious and gets stricter rate limits.
// Reset on successful auth. Env: SUSPICIOUS_IP_FAILED_THRESHOLD (default 5),
// SUSPICIOUS_IP_STRICT_RPM (default 5).
type FailedAttemptTracker struct {
	mu        sync.Mutex
	counters  map[string]*window
	threshold int
	window    time.Duration
	cleanup   *time.Ticker
}

// NewFailedAttemptTracker creates a tracker for suspicious IP throttling.
func NewFailedAttemptTracker() *FailedAttemptTracker {
	threshold := parseIntEnv("SUSPICIOUS_IP_FAILED_THRESHOLD", defaultSuspiciousFailedThreshold)
	tr := &FailedAttemptTracker{
		counters:  make(map[string]*window),
		threshold: threshold,
		window:    time.Minute,
	}
	tr.cleanup = time.NewTicker(2 * time.Minute)
	go tr.cleanupLoop()
	return tr
}

func (tr *FailedAttemptTracker) cleanupLoop() {
	for range tr.cleanup.C {
		tr.mu.Lock()
		now := time.Now()
		for ip, w := range tr.counters {
			if now.Sub(w.startAt) > tr.window {
				delete(tr.counters, ip)
			}
		}
		tr.mu.Unlock()
	}
}

// RecordFailedAuth increments failed auth count for the IP.
func (tr *FailedAttemptTracker) RecordFailedAuth(ip string) {
	if ip == "" {
		return
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	now := time.Now()
	w := tr.counters[ip]
	if w == nil {
		tr.counters[ip] = &window{count: 1, startAt: now}
		return
	}
	if now.Sub(w.startAt) >= tr.window {
		w.count = 1
		w.startAt = now
		return
	}
	w.count++
}

// RecordSuccessAuth resets failed count for the IP.
func (tr *FailedAttemptTracker) RecordSuccessAuth(ip string) {
	if ip == "" {
		return
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	delete(tr.counters, ip)
}

// IsSuspicious returns true if the IP has exceeded the failed-attempt threshold.
func (tr *FailedAttemptTracker) IsSuspicious(ip string) bool {
	if ip == "" {
		return false
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	w := tr.counters[ip]
	if w == nil {
		return false
	}
	if time.Now().Sub(w.startAt) >= tr.window {
		return false
	}
	return w.count >= tr.threshold
}

// New creates a per-IP rate limiter.
// RATE_LIMIT_RPM env sets requests per minute (default 100).
// Call SetSuspiciousIPTracker to enable suspicious IP throttling.
func New() *Limiter {
	rpm := parseIntEnv("RATE_LIMIT_RPM", defaultRPM)
	strictRPM := parseIntEnv("SUSPICIOUS_IP_STRICT_RPM", defaultSuspiciousStrictRPM)
	lim := &Limiter{
		counters:  make(map[string]*window),
		rpm:       rpm,
		strictRPM: strictRPM,
		window:    time.Minute,
	}
	lim.cleanup = time.NewTicker(2 * time.Minute)
	go lim.cleanupLoop()
	return lim
}

// SetSuspiciousIPTracker enables stricter rate limiting for IPs with many failed auth attempts.
func (l *Limiter) SetSuspiciousIPTracker(tr *FailedAttemptTracker) {
	l.FailedTracker = tr
}

func parseIntEnv(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	return defaultVal
}

func (l *Limiter) cleanupLoop() {
	for range l.cleanup.C {
		l.mu.Lock()
		now := time.Now()
		for ip, w := range l.counters {
			if now.Sub(w.startAt) > l.window {
				delete(l.counters, ip)
			}
		}
		l.mu.Unlock()
	}
}

// Allow returns true if the request is allowed, false if rate limited.
// When FailedTracker is set and IP is suspicious, uses stricter RPM.
func (l *Limiter) Allow(ip string) bool {
	if ip == "" {
		return true
	}
	rpm := l.rpm
	if l.FailedTracker != nil && l.FailedTracker.IsSuspicious(ip) {
		rpm = l.strictRPM
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w := l.counters[ip]
	if w == nil {
		l.counters[ip] = &window{count: 1, startAt: now}
		return true
	}
	if now.Sub(w.startAt) >= l.window {
		w.count = 1
		w.startAt = now
		return true
	}
	if w.count >= rpm {
		return false
	}
	w.count++
	return true
}

// Status returns (remaining, limit) for the given IP. Used for X-RateLimit-* headers.
func (l *Limiter) Status(ip string) (remaining, limit int) {
	if ip == "" {
		return defaultRPM, defaultRPM
	}
	rpm := l.rpm
	if l.FailedTracker != nil && l.FailedTracker.IsSuspicious(ip) {
		rpm = l.strictRPM
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.counters[ip]
	if w == nil {
		return rpm, rpm
	}
	if time.Since(w.startAt) >= l.window {
		return rpm, rpm
	}
	rem := rpm - w.count
	if rem < 0 {
		rem = 0
	}
	return rem, rpm
}

// ClientLimiter performs per-client_id rate limiting. Separate from per-IP limit.
// Used for /oauth/token and /oauth/device/code. RATE_LIMIT_CLIENT_RPM env (default 200).
type ClientLimiter struct {
	mu       sync.Mutex
	counters map[string]*window
	rpm      int
	window   time.Duration
	cleanup  *time.Ticker
}

// NewClientLimiter creates a per-client rate limiter.
func NewClientLimiter() *ClientLimiter {
	rpm := parseIntEnv("RATE_LIMIT_CLIENT_RPM", defaultClientRPM)
	cl := &ClientLimiter{
		counters: make(map[string]*window),
		rpm:      rpm,
		window:   time.Minute,
	}
	cl.cleanup = time.NewTicker(2 * time.Minute)
	go cl.cleanupLoop()
	return cl
}

func (cl *ClientLimiter) cleanupLoop() {
	for range cl.cleanup.C {
		cl.mu.Lock()
		now := time.Now()
		for cid, w := range cl.counters {
			if now.Sub(w.startAt) > cl.window {
				delete(cl.counters, cid)
			}
		}
		cl.mu.Unlock()
	}
}

// Allow returns true if the request is allowed for this client_id.
func (cl *ClientLimiter) Allow(clientID string) bool {
	if clientID == "" {
		return true
	}
	cl.mu.Lock()
	defer cl.mu.Unlock()
	now := time.Now()
	w := cl.counters[clientID]
	if w == nil {
		cl.counters[clientID] = &window{count: 1, startAt: now}
		return true
	}
	if now.Sub(w.startAt) >= cl.window {
		w.count = 1
		w.startAt = now
		return true
	}
	if w.count >= cl.rpm {
		return false
	}
	w.count++
	return true
}

// extractClientIDFromBody reads the request body, extracts client_id from form or JSON,
// and restores the body for downstream handlers. Returns client_id or empty string.
func extractClientIDFromBody(r *http.Request, path string) string {
	if r.Method != http.MethodPost {
		return ""
	}
	if path != "/oauth/token" && path != "/oauth/device/code" {
		return ""
	}
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
		return ""
	}
	// application/x-www-form-urlencoded
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(vals.Get("client_id"))
}

// Per-client paths: /oauth/token and /oauth/device/code.
var clientLimitPaths = map[string]bool{
	"/oauth/token":      true,
	"/oauth/device/code": true,
}

// TokenAuthPaths are paths that get rate-limited (login, token, signup).
var TokenAuthPaths = []string{
	"/oauth/token", "/oauth/revoke", "/oauth/device/code",
	"/login", "/u/login", "/usernamepassword/login",
	"/authorize", "/dbconnections/signup", "/passwordless/start",
}

// AuthResultPaths are paths where we record failed/success auth for suspicious IP tracking.
var AuthResultPaths = map[string]bool{
	"/oauth/token": true, "/login": true, "/u/login": true, "/usernamepassword/login": true,
	"/oauth/device/authorize": true,
}

// responseRecorder captures status and body for auth result recording.
type responseRecorder struct {
	http.ResponseWriter
	status int
	body   *bytes.Buffer
}

func (rw *responseRecorder) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseRecorder) Write(b []byte) (int, error) {
	if rw.body != nil {
		rw.body.Write(b)
	}
	return rw.ResponseWriter.Write(b)
}

func isAuthFailure(path string, status int, body []byte) bool {
	if status != 400 && status != 401 {
		return false
	}
	path = strings.TrimSuffix(path, "/")
	if path == "/oauth/token" {
		return bytes.Contains(body, []byte(`"error":"invalid_grant"`)) ||
			bytes.Contains(body, []byte(`"error": "invalid_grant"`))
	}
	if path == "/login" || path == "/u/login" || path == "/usernamepassword/login" {
		return status == 401 || bytes.Contains(body, []byte("Invalid credentials"))
	}
	if path == "/oauth/device/authorize" {
		return bytes.Contains(body, []byte("Invalid credentials"))
	}
	return false
}

// Middleware returns a handler that rate-limits by client IP.
// When clientLimiter is non-nil, also applies per-client_id rate limit on /oauth/token and /oauth/device/code.
// When limitPaths is nil or empty, limits all paths. Otherwise limits only those paths.
// When limit is exceeded, responds with 429 Too Many Requests.
func Middleware(lim *Limiter, limitPaths []string) func(http.Handler) http.Handler {
	return MiddlewareWithClientLimiter(lim, nil, nil, limitPaths)
}

// MiddlewareWithClientLimiter adds optional per-client rate limiting for token/device endpoints.
// When failedTracker is non-nil, records auth failures/successes for suspicious IP throttling.
func MiddlewareWithClientLimiter(lim *Limiter, clientLim *ClientLimiter, failedTracker *FailedAttemptTracker, limitPaths []string) func(http.Handler) http.Handler {
	pathSet := make(map[string]bool)
	for _, p := range limitPaths {
		pathSet[strings.TrimSuffix(p, "/")] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := strings.TrimSuffix(r.URL.Path, "/")
			shouldLimit := len(pathSet) == 0
			if !shouldLimit {
				shouldLimit = pathSet[path]
			}
			if !shouldLimit {
				next.ServeHTTP(w, r)
				return
			}
			ip := clientIP(r)
			if !lim.Allow(ip) {
				_, limit := lim.Status(ip)
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"too_many_requests","error_description":"Rate limit exceeded"}`))
				return
			}
			rem, limit := lim.Status(ip)
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(rem))
			// Per-client rate limit for /oauth/token and /oauth/device/code
			if clientLim != nil && clientLimitPaths[path] {
				clientID := extractClientIDFromBody(r, path)
				if clientID == "" {
					clientID = r.Header.Get("X-Client-ID")
				}
				if clientID != "" && !clientLim.Allow(clientID) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					w.Write([]byte(`{"error":"too_many_requests","error_description":"Client rate limit exceeded"}`))
					return
				}
			}
			// Wrap response for auth result recording
			if failedTracker != nil && AuthResultPaths[path] {
				rec := &responseRecorder{
					ResponseWriter: w,
					status:        200,
					body:           &bytes.Buffer{},
				}
				next.ServeHTTP(rec, r)
				if rec.status == 200 || rec.status == 201 || rec.status == 302 {
					failedTracker.RecordSuccessAuth(ip)
				} else if isAuthFailure(path, rec.status, rec.body.Bytes()) {
					failedTracker.RecordFailedAuth(ip)
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First IP is the client; rest are proxies
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
