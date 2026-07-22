package password

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestIsBreached(t *testing.T) {
	// "password" is notoriously breached - SHA1 prefix 5BAA6, suffix 1E4C9B93F3F0682250B6CF8331B7EE68FD8
	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		if !strings.HasPrefix(r.URL.Path, "/range/") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3730471\n")
	}))
	defer server.Close()

	oldBase := hibpAPIBase
	hibpAPIBase = server.URL
	defer func() { hibpAPIBase = oldBase }()

	err := IsBreached("password")
	if !hit {
		t.Error("test server was not hit - may be using real API")
	}
	if err != ErrBreached {
		t.Errorf("IsBreached(password) = %v, want ErrBreached", err)
	}
}

func TestIsBreached_NotBreached(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// Return empty range - no hashes match
		io.WriteString(w, "000000000000000000000000000000000001:1\n")
	}))
	defer server.Close()

	oldBase := hibpAPIBase
	hibpAPIBase = server.URL
	defer func() { hibpAPIBase = oldBase }()

	os.Setenv("BREACHED_PASSWORD_CHECK", "true")
	defer os.Unsetenv("BREACHED_PASSWORD_CHECK")

	err := IsBreached("xK9#mP2$vL7qR4nZ")
	if err != nil {
		t.Errorf("IsBreached(strong) = %v, want nil", err)
	}
}

func TestIsBreachedCheckEnabled(t *testing.T) {
	os.Unsetenv("BREACHED_PASSWORD_CHECK")
	if IsBreachedCheckEnabled() {
		t.Error("expected disabled when unset")
	}
	os.Setenv("BREACHED_PASSWORD_CHECK", "true")
	defer os.Unsetenv("BREACHED_PASSWORD_CHECK")
	if !IsBreachedCheckEnabled() {
		t.Error("expected enabled")
	}
	os.Setenv("BREACHED_PASSWORD_CHECK", "TRUE")
	if !IsBreachedCheckEnabled() {
		t.Error("expected enabled for TRUE")
	}
}
