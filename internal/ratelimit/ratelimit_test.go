package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestFailedAttemptTracker_Basic(t *testing.T) {
	os.Setenv("SUSPICIOUS_IP_FAILED_THRESHOLD", "3")
	os.Setenv("SUSPICIOUS_IP_STRICT_RPM", "5")
	defer func() {
		os.Unsetenv("SUSPICIOUS_IP_FAILED_THRESHOLD")
		os.Unsetenv("SUSPICIOUS_IP_STRICT_RPM")
	}()

	tr := NewFailedAttemptTracker()
	ip := "192.168.1.1"

	if tr.IsSuspicious(ip) {
		t.Error("fresh IP should not be suspicious")
	}
	tr.RecordFailedAuth(ip)
	tr.RecordFailedAuth(ip)
	if tr.IsSuspicious(ip) {
		t.Error("2 failures should not exceed threshold 3")
	}
	tr.RecordFailedAuth(ip)
	if !tr.IsSuspicious(ip) {
		t.Error("3 failures should make IP suspicious")
	}
	tr.RecordSuccessAuth(ip)
	if tr.IsSuspicious(ip) {
		t.Error("after success, IP should not be suspicious")
	}
}

func TestSuspiciousIP_StricterLimit(t *testing.T) {
	os.Setenv("SUSPICIOUS_IP_FAILED_THRESHOLD", "2")
	os.Setenv("SUSPICIOUS_IP_STRICT_RPM", "3")
	os.Setenv("RATE_LIMIT_RPM", "100")
	defer func() {
		os.Unsetenv("SUSPICIOUS_IP_FAILED_THRESHOLD")
		os.Unsetenv("SUSPICIOUS_IP_STRICT_RPM")
		os.Unsetenv("RATE_LIMIT_RPM")
	}()

	tr := NewFailedAttemptTracker()
	lim := New()
	lim.SetSuspiciousIPTracker(tr)

	ip := "10.0.0.1"
	// Make IP suspicious
	tr.RecordFailedAuth(ip)
	tr.RecordFailedAuth(ip)

	// Should allow only 3 requests (strict RPM) within window
	for i := 0; i < 3; i++ {
		if !lim.Allow(ip) {
			t.Errorf("request %d should be allowed", i+1)
		}
	}
	if lim.Allow(ip) {
		t.Error("4th request should be rate limited (suspicious IP)")
	}

	// Reset - should use normal RPM again
	tr.RecordSuccessAuth(ip)
	// Need new limiter or different IP to test normal RPM since counter is per-IP
	lim2 := New()
	lim2.SetSuspiciousIPTracker(tr)
	for i := 0; i < 5; i++ {
		if !lim2.Allow(ip) {
			t.Errorf("after reset, request %d should be allowed", i+1)
		}
	}
}

func TestMiddleware_AuthResultRecording(t *testing.T) {
	tr := NewFailedAttemptTracker()
	lim := New()
	lim.SetSuspiciousIPTracker(tr)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"Wrong email or password."}`))
	})
	h := MiddlewareWithClientLimiter(lim, nil, tr, []string{"/oauth/token"})(next)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=password&username=u&password=p&client_id=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.2.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Errorf("status = %d", rec.Code)
	}
	// Record 5 failures to exceed threshold
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=password&username=u&password=p&client_id=test"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.168.2.1:12345"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		_ = rec
	}
	if !tr.IsSuspicious("192.168.2.1") {
		t.Error("IP with 5 failed auth attempts should be suspicious")
	}
}

func TestClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:80"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	ip := clientIP(req)
	if ip != "203.0.113.1" {
		t.Errorf("clientIP = %q, want 203.0.113.1", ip)
	}
}

func TestClientIP_XForwardedForMultiple(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 70.41.3.18")
	ip := clientIP(req)
	if ip != "203.0.113.1" {
		t.Errorf("clientIP = %q, want 203.0.113.1 (first)", ip)
	}
}

func TestLimiter_Concurrent(t *testing.T) {
	lim := New()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lim.Allow("1.2.3.4")
		}()
	}
	wg.Wait()
}

func TestLimiter_Status(t *testing.T) {
	os.Setenv("RATE_LIMIT_RPM", "10")
	defer os.Unsetenv("RATE_LIMIT_RPM")

	lim := New()
	ip := "10.0.0.5"
	rem, limit := lim.Status(ip)
	if limit != 10 {
		t.Errorf("limit = %d, want 10", limit)
	}
	if rem != 10 {
		t.Errorf("initial remaining = %d, want 10", rem)
	}
	lim.Allow(ip)
	lim.Allow(ip)
	rem, _ = lim.Status(ip)
	if rem != 8 {
		t.Errorf("after 2 requests remaining = %d", rem)
	}
}

func TestMiddleware_RateLimitExceeded(t *testing.T) {
	os.Setenv("RATE_LIMIT_RPM", "2")
	defer os.Unsetenv("RATE_LIMIT_RPM")

	lim := New()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(lim, []string{"/oauth/token"})(next)

	ip := "192.168.99.1"
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=password&client_id=c&username=u&password=p"))
		req.RemoteAddr = ip + ":80"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d: %d", i+1, rec.Code)
		}
	}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=password&client_id=c&username=u&password=p"))
	req.RemoteAddr = ip + ":80"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("rate limited: %d", rec.Code)
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Errorf("X-RateLimit-Remaining = %q", rec.Header().Get("X-RateLimit-Remaining"))
	}
}

func TestClientLimiter(t *testing.T) {
	os.Setenv("RATE_LIMIT_CLIENT_RPM", "3")
	defer os.Unsetenv("RATE_LIMIT_CLIENT_RPM")

	cl := NewClientLimiter()
	if !cl.Allow("client-a") {
		t.Error("first request should allow")
	}
	cl.Allow("client-a")
	cl.Allow("client-a")
	if cl.Allow("client-a") {
		t.Error("4th request for same client should be limited")
	}
	if !cl.Allow("client-b") {
		t.Error("different client should be allowed")
	}
}

func TestLimiter_EmptyIP(t *testing.T) {
	lim := New()
	if !lim.Allow("") {
		t.Error("empty IP should always allow")
	}
	rem, limit := lim.Status("")
	if rem != 100 || limit != 100 {
		t.Errorf("empty IP Status: rem=%d limit=%d", rem, limit)
	}
}

func TestClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:80"
	req.Header.Set("X-Real-IP", "198.51.100.1")
	ip := clientIP(req)
	if ip != "198.51.100.1" {
		t.Errorf("clientIP = %q, want 198.51.100.1", ip)
	}
}

func TestClientLimiter_EmptyClientID(t *testing.T) {
	cl := NewClientLimiter()
	if !cl.Allow("") {
		t.Error("empty client ID should allow")
	}
}

func TestMiddleware_ClientRateLimitExceeded(t *testing.T) {
	os.Setenv("RATE_LIMIT_RPM", "100")
	os.Setenv("RATE_LIMIT_CLIENT_RPM", "2")
	defer func() {
		os.Unsetenv("RATE_LIMIT_RPM")
		os.Unsetenv("RATE_LIMIT_CLIENT_RPM")
	}()

	lim := New()
	cl := NewClientLimiter()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := MiddlewareWithClientLimiter(lim, cl, nil, []string{"/oauth/token"})(next)

	// Same client_id 3 times - third should be rate limited
	body := "grant_type=password&client_id=rate-client&username=u&password=p"
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.0.0.1:80"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d: want 200, got %d", i+1, rec.Code)
		}
	}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.2:80"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("client rate limit: want 429, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Client rate limit") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestMiddleware_SuccessAuthRecording(t *testing.T) {
	tr := NewFailedAttemptTracker()
	lim := New()
	lim.SetSuspiciousIPTracker(tr)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := MiddlewareWithClientLimiter(lim, nil, tr, []string{"/oauth/token"})(next)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=password&username=u&password=p&client_id=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.3.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("status = %d", rec.Code)
	}
	// Success should reset any prior failures
	if tr.IsSuspicious("192.168.3.1") {
		t.Error("successful auth should clear suspicious status")
	}
}

func TestMiddleware_NonLimitPath(t *testing.T) {
	lim := New()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(lim, []string{"/oauth/token"})(next)

	req := httptest.NewRequest("GET", "/health", nil)
	req.RemoteAddr = "10.0.0.1:80"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("non-limit path should pass: %d", rec.Code)
	}
}

func TestMiddleware_LoginAuthFailureRecording(t *testing.T) {
	os.Setenv("SUSPICIOUS_IP_FAILED_THRESHOLD", "1")
	defer os.Unsetenv("SUSPICIOUS_IP_FAILED_THRESHOLD")
	tr := NewFailedAttemptTracker()
	lim := New()
	lim.SetSuspiciousIPTracker(tr)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid credentials"))
	})
	h := MiddlewareWithClientLimiter(lim, nil, tr, []string{"/login"})(next)

	req := httptest.NewRequest("POST", "/login", strings.NewReader("username=u&password=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.4.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", rec.Code)
	}
	if !tr.IsSuspicious("192.168.4.1") {
		t.Error("failed login at /login should mark IP suspicious")
	}
}

func TestMiddleware_DeviceAuthorizeAuthFailure(t *testing.T) {
	os.Setenv("SUSPICIOUS_IP_FAILED_THRESHOLD", "1")
	defer os.Unsetenv("SUSPICIOUS_IP_FAILED_THRESHOLD")
	tr := NewFailedAttemptTracker()
	lim := New()
	lim.SetSuspiciousIPTracker(tr)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"Invalid credentials"}`))
	})
	h := MiddlewareWithClientLimiter(lim, nil, tr, []string{"/oauth/device/authorize"})(next)

	req := httptest.NewRequest("POST", "/oauth/device/authorize", strings.NewReader("user_code=xxxx"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.5.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !tr.IsSuspicious("192.168.5.1") {
		t.Error("device/authorize Invalid credentials should mark IP suspicious")
	}
}

func TestMiddleware_ClientIDFromJSON(t *testing.T) {
	os.Setenv("RATE_LIMIT_CLIENT_RPM", "2")
	defer os.Unsetenv("RATE_LIMIT_CLIENT_RPM")

	lim := New()
	cl := NewClientLimiter()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := MiddlewareWithClientLimiter(lim, cl, nil, []string{"/oauth/token"})(next)

	body := `{"grant_type":"password","client_id":"json-client","username":"u","password":"p"}`
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "10.0.0.1:80"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d: want 200, got %d", i+1, rec.Code)
		}
	}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.2:80"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("client rate limit (JSON): want 429, got %d", rec.Code)
	}
}
