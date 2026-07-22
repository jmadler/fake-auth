package botdetect

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestIsBot_EmptyUserAgent(t *testing.T) {
	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.Header.Del("User-Agent")
	ok, reason := IsBot(req)
	if !ok {
		t.Errorf("empty User-Agent should be bot, got ok=false")
	}
	if reason != "empty or missing User-Agent" {
		t.Errorf("reason = %q, want empty or missing User-Agent", reason)
	}
}

func TestIsBot_BotPattern(t *testing.T) {
	tests := []string{"Googlebot", "BingBot", "crawler", "spider", "scraper"}
	for _, ua := range tests {
		req := httptest.NewRequest("GET", "/oauth/token", nil)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")
		ok, reason := IsBot(req)
		if !ok {
			t.Errorf("User-Agent %q should be bot, got ok=false", ua)
		}
		if !strings.Contains(reason, "bot") && !strings.Contains(reason, "crawler") && !strings.Contains(reason, "spider") && !strings.Contains(reason, "scraper") {
			t.Errorf("reason = %q for UA %q", reason, ua)
		}
	}
}

func TestIsBot_MissingAccept(t *testing.T) {
	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Del("Accept")
	ok, reason := IsBot(req)
	if !ok {
		t.Errorf("missing Accept should be bot, got ok=false")
	}
	if reason != "missing Accept header" {
		t.Errorf("reason = %q, want missing Accept header", reason)
	}
}

func TestIsBot_Legitimate(t *testing.T) {
	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0")
	req.Header.Set("Accept", "application/json")
	ok, reason := IsBot(req)
	if ok {
		t.Errorf("legitimate browser should not be bot, got ok=true, reason=%q", reason)
	}
}

func TestMiddleware_BlockedWhenEnabled(t *testing.T) {
	os.Setenv("BOT_DETECTION_ENABLED", "true")
	defer os.Unsetenv("BOT_DETECTION_ENABLED")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when bot blocked")
	})
	h := Middleware(next)
	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.Header.Del("User-Agent")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "access_denied") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestMiddleware_PassthroughWhenDisabled(t *testing.T) {
	os.Unsetenv("BOT_DETECTION_ENABLED")
	handled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled = true
	})
	h := Middleware(next)
	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.Header.Del("User-Agent")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !handled {
		t.Error("handler should be called when bot detection disabled")
	}
}
