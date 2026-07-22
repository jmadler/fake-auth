package adminui

import (
	"embed"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
)

//go:embed static/*
var staticFS embed.FS

const adminKeyCookie = "auth2_admin_key"
const adminKeyCookiePath = "/"
const adminKeyCookieMaxAge = 86400 * 7 // 7 days

// Config holds admin UI configuration.
type Config struct {
	AdminAPIKey    string
	ProductionMode bool
}

// NewHandler returns an http.Handler that serves the admin UI.
// Protects /admin/* (except /admin/login) when AdminAPIKey is set or ProductionMode is true.
// When AdminAPIKey is empty and not ProductionMode, allows unauthenticated access for dev.
func NewHandler(cfg Config) http.Handler {
	content, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(content))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimSuffix(r.URL.Path, "/")
		if p == "" {
			p = "/"
		}
		if !strings.HasPrefix(p, "/admin") {
			http.NotFound(w, r)
			return
		}
		rel := strings.TrimPrefix(p, "/admin")
		if rel == "" {
			rel = "/"
		}
		trimmed := strings.TrimPrefix(strings.Trim(rel, "/"), "/")

		// POST /admin/login — validate key, set cookie, redirect
		if r.Method == http.MethodPost && (p == "/admin/login" || strings.HasSuffix(p, "/admin/login")) {
			_ = r.ParseForm()
			key := r.FormValue("key")
			requiresAuth := cfg.AdminAPIKey != "" || cfg.ProductionMode
			if !requiresAuth || (cfg.AdminAPIKey != "" && key == cfg.AdminAPIKey) {
				if requiresAuth {
					http.SetCookie(w, &http.Cookie{
						Name:     adminKeyCookie,
						Value:    key,
						Path:     adminKeyCookiePath,
						MaxAge:   adminKeyCookieMaxAge,
						HttpOnly: false, // JS needs to read it for API Bearer header
						SameSite: http.SameSiteLaxMode,
					})
				}
				http.Redirect(w, r, "/admin/", http.StatusFound)
				return
			}
			http.Redirect(w, r, "/admin/login?err=invalid", http.StatusFound)
			return
		}

		// GET /admin/logout — clear cookie, redirect to login
		if r.Method == http.MethodGet && (p == "/admin/logout" || strings.HasSuffix(p, "/admin/logout")) {
			http.SetCookie(w, &http.Cookie{
				Name:     adminKeyCookie,
				Value:    "",
				Path:     adminKeyCookiePath,
				MaxAge:   -1,
				SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}

		// GET /admin/login — serve login page (no auth required)
		if r.Method == http.MethodGet && (p == "/admin/login" || trimmed == "login" || trimmed == "login.html") {
			serveFile(w, r, content, fileServer, "login.html")
			return
		}

		// All other /admin/* require auth when AdminAPIKey is set or ProductionMode
		requiresAuth := cfg.AdminAPIKey != "" || cfg.ProductionMode
		if requiresAuth {
			cookie, err := r.Cookie(adminKeyCookie)
			if err != nil || cookie == nil || cookie.Value == "" {
				http.Redirect(w, r, "/admin/login", http.StatusFound)
				return
			}
			if cfg.AdminAPIKey != "" && cookie.Value != cfg.AdminAPIKey {
				http.Redirect(w, r, "/admin/login?err=invalid", http.StatusFound)
				return
			}
		}

		// Map request path to embedded file name
		var name string
		if trimmed == "" || trimmed == "index" {
			name = "index.html"
		} else {
			name = path.Base(trimmed)
			if name == "" || name == "." {
				name = "index.html"
			} else if !strings.Contains(name, ".") {
				name = name + ".html"
			}
		}
		if _, err := content.Open(name); err != nil {
			name = "index.html"
		}
		serveFile(w, r, content, fileServer, name)
	})
}

func serveFile(w http.ResponseWriter, r *http.Request, content fs.FS, fileServer http.Handler, name string) {
	r2 := r.Clone(r.Context())
	r2.URL = &url.URL{Path: "/" + name}
	fileServer.ServeHTTP(w, r2)
}
