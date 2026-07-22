package acl

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestACL_New_EmptyRules(t *testing.T) {
	a := New(nil)
	if a != nil {
		t.Error("New(nil) should return nil")
	}
	a = New([]Rule{})
	if a != nil {
		t.Error("New([]Rule{}) should return nil")
	}
}

func TestACL_Allow_NoMatch(t *testing.T) {
	a := New([]Rule{
		{Action: "deny", Path: "/admin"},
	})
	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	if !a.Allow(req) {
		t.Error("request not matching any rule should be allowed (default allow)")
	}
}

func TestACL_Allow_PathMatch(t *testing.T) {
	a := New([]Rule{
		{Action: "deny", Path: "/oauth/*"},
	})
	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	if a.Allow(req) {
		t.Error("path /oauth/token should match /oauth/* and be denied")
	}
}

func TestACL_Allow_PathGlob(t *testing.T) {
	a := New([]Rule{
		{Action: "allow", Path: "/oauth/token"},
	})
	req := httptest.NewRequest("POST", "/oauth/token", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	if !a.Allow(req) {
		t.Error("path /oauth/token should be allowed")
	}
}

func TestACL_Allow_IPMatch(t *testing.T) {
	a := New([]Rule{
		{Action: "deny", IP: "127.0.0.1"},
	})
	req := httptest.NewRequest("GET", "/login", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	if a.Allow(req) {
		t.Error("127.0.0.1 should be denied")
	}
}

func TestACL_Allow_ClientIDMatch(t *testing.T) {
	a := New([]Rule{
		{Action: "deny", Path: "/oauth/token", ClientID: "bad-client"},
	})
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=password&client_id=bad-client&username=x&password=y"))
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if a.Allow(req) {
		t.Error("client_id=bad-client on /oauth/token should be denied")
	}
}

func TestACL_Middleware_NilACL(t *testing.T) {
	mw := Middleware(nil)
	handled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled = true
	})
	h := mw(next)
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !handled {
		t.Error("nil ACL should pass through to handler")
	}
}

func TestACL_Middleware_Deny(t *testing.T) {
	a := New([]Rule{
		{Action: "deny", Path: "/oauth/token"},
	})
	mw := Middleware(a)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when denied")
	})
	h := mw(next)
	req := httptest.NewRequest("POST", "/oauth/token", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "access_denied") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestACL_LoadFromEnv_Inline(t *testing.T) {
	os.Setenv("ACL_RULES", `[{"action":"deny","path":"/admin"}]`)
	defer os.Unsetenv("ACL_RULES")
	a := LoadFromEnv()
	if a == nil {
		t.Fatal("LoadFromEnv should return ACL")
	}
	req := httptest.NewRequest("GET", "/admin", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	if a.Allow(req) {
		t.Error("/admin should be denied")
	}
}

func TestACL_LoadFromEnv_InvalidJSON(t *testing.T) {
	os.Setenv("ACL_RULES", `[invalid`)
	defer os.Unsetenv("ACL_RULES")
	a := LoadFromEnv()
	if a != nil {
		t.Error("invalid JSON should return nil")
	}
}

func TestACL_Allow_CIDR(t *testing.T) {
	a := New([]Rule{
		{Action: "deny", IP: "192.168.1.0/24"},
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	if a.Allow(req) {
		t.Error("IP in 192.168.1.0/24 should be denied")
	}
	req.RemoteAddr = "192.168.2.1:12345"
	if !a.Allow(req) {
		t.Error("IP outside CIDR should be allowed")
	}
}

func TestACL_Allow_ClientIDFromQuery(t *testing.T) {
	a := New([]Rule{
		{Action: "deny", Path: "/authorize", ClientID: "blocked"},
	})
	req := httptest.NewRequest("GET", "/authorize?client_id=blocked&response_type=code", nil)
	req.RemoteAddr = "1.2.3.4:80"
	if a.Allow(req) {
		t.Error("client_id from query should match")
	}
}

func TestACL_Allow_ClientIDFromHeader(t *testing.T) {
	a := New([]Rule{
		{Action: "allow", Path: "/oauth/token", ClientID: "trusted"},
	})
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("X-Client-ID", "trusted")
	req.RemoteAddr = "1.2.3.4:80"
	if !a.Allow(req) {
		t.Error("X-Client-ID should match")
	}
}

func TestACL_Allow_ClientIDFromJSONBody(t *testing.T) {
	a := New([]Rule{
		{Action: "deny", Path: "/oauth/token", ClientID: "bad"},
	})
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(`{"grant_type":"password","client_id":"bad","username":"x","password":"y"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "1.2.3.4:80"
	if a.Allow(req) {
		t.Error("client_id from JSON body should match")
	}
}

func TestACL_Allow_PathPrefix(t *testing.T) {
	a := New([]Rule{
		{Action: "deny", Path: "/api/v2/*"},
	})
	req := httptest.NewRequest("GET", "/api/v2/users/123", nil)
	req.RemoteAddr = "1.2.3.4:80"
	if a.Allow(req) {
		t.Error("/api/v2/users/123 should match /api/v2/*")
	}
}

func TestACL_LoadFromEnv_File(t *testing.T) {
	f, err := os.CreateTemp("", "acl_rules_*.json")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.WriteString(`[{"action":"deny","path":"/secret"}]`); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	os.Setenv("ACL_RULES", "")
	os.Setenv("ACL_RULES_FILE", path)
	defer func() {
		os.Unsetenv("ACL_RULES")
		os.Unsetenv("ACL_RULES_FILE")
	}()
	a := LoadFromEnv()
	if a == nil {
		t.Fatal("LoadFromEnv with file should return ACL")
	}
	req := httptest.NewRequest("GET", "/secret", nil)
	req.RemoteAddr = "1.2.3.4:80"
	if a.Allow(req) {
		t.Error("/secret should be denied")
	}
}
