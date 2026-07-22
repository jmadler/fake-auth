package botdetect

import (
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/jmadler/auth2/internal/logging"
)

var (
	botPattern = regexp.MustCompile(`(?i)(bot|crawler|spider|scraper)`)
	// Suspicious header names that automated tools often send
	suspiciousHeaders = []string{
		"X-Scanner", "X-Security-Test", "Acunetix-",
		"scan", "Zap", "Nikto", "Nessus", "Sqlmap",
	}
)

// IsBot returns true if the request appears to come from a bot.
// Also returns a human-readable reason.
func IsBot(r *http.Request) (bool, string) {
	ua := r.Header.Get("User-Agent")
	if ua == "" || strings.TrimSpace(ua) == "" {
		return true, "empty or missing User-Agent"
	}
	if botPattern.MatchString(ua) {
		return true, "User-Agent contains bot/crawler/spider/scraper"
	}
	if r.Header.Get("Accept") == "" {
		return true, "missing Accept header"
	}
	// Check for suspicious scanner headers
	for _, h := range suspiciousHeaders {
		for k := range r.Header {
			if strings.Contains(strings.ToLower(k), strings.ToLower(h)) {
				return true, "suspicious header: " + k
			}
		}
	}
	return false, ""
}

// Enabled returns true if BOT_DETECTION_ENABLED is set to true.
func Enabled() bool {
	return strings.ToLower(os.Getenv("BOT_DETECTION_ENABLED")) == "true"
}

// Middleware runs before auth handlers. When enabled, blocks obvious bots with 403,
// logs others. When disabled, passes through.
// Should be placed before rate limit in the chain.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !Enabled() {
			next.ServeHTTP(w, r)
			return
		}
		isBot, reason := IsBot(r)
		if !isBot {
			next.ServeHTTP(w, r)
			return
		}
		// Block obvious bots (empty/missing UA, UA with bot patterns, missing Accept)
		if reason == "empty or missing User-Agent" ||
			reason == "User-Agent contains bot/crawler/spider/scraper" ||
			reason == "missing Accept header" {
			ctx := r.Context()
			logging.Warn(ctx, "bot blocked", "reason", reason, "path", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"access_denied","error_description":"Request blocked by bot detection"}`))
			return
		}
		// Log suspicious headers but allow (could be false positive)
		logging.Info(r.Context(), "suspicious request (allowed)", "reason", reason, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
