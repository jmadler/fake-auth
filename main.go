package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jmadler/auth2/internal/acl"
	"github.com/jmadler/auth2/internal/adminauth"
	"github.com/jmadler/auth2/internal/adminui"
	"github.com/jmadler/auth2/internal/graphql"
	"github.com/jmadler/auth2/internal/audit"
	"github.com/jmadler/auth2/internal/botdetect"
	"github.com/jmadler/auth2/internal/clients"
	"github.com/jmadler/auth2/internal/cors"
	"github.com/jmadler/auth2/internal/grants"
	"github.com/jmadler/auth2/internal/handlers"
	"github.com/jmadler/auth2/internal/logging"
	"github.com/jmadler/auth2/internal/metrics"
	"github.com/jmadler/auth2/internal/ratelimit"
	"github.com/jmadler/auth2/internal/rules"
	"github.com/jmadler/auth2/internal/scim"
	"github.com/jmadler/auth2/internal/securityheaders"
	"github.com/jmadler/auth2/internal/sessions"
	"github.com/jmadler/auth2/internal/store"
	"github.com/jmadler/auth2/internal/token"
	"github.com/jmadler/auth2/internal/tracing"
	"github.com/jmadler/auth2/internal/webauthn"
	"golang.org/x/crypto/acme/autocert"
)

func parseIntEnv(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultVal
}

func main() {
	logging.Init()

	if err := tracing.Init(context.Background()); err != nil {
		logging.Warn(context.Background(), "tracing init failed (continuing without traces)", "error", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "9092"
	}
	dbDriver := strings.ToLower(os.Getenv("DB_DRIVER"))
	if dbDriver == "" {
		dbDriver = "sqlite"
	}
	dbDSN := os.Getenv("DB_DSN")
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./data/auth0.db"
	}
	issuerURL := os.Getenv("ISSUER_URL")
	if issuerURL == "" {
		issuerURL = "http://localhost:" + port
	}
	tlsCert := os.Getenv("TLS_CERT")
	tlsKey := os.Getenv("TLS_KEY")
	acmeEnabled := strings.ToLower(os.Getenv("TLS_ACME_ENABLED")) == "true"
	acmeDomain := os.Getenv("TLS_ACME_DOMAIN")
	acmeEmail := os.Getenv("TLS_ACME_EMAIL")
	acmeCacheDir := os.Getenv("TLS_ACME_CACHE_DIR")
	if acmeCacheDir == "" {
		acmeCacheDir = "./certs"
	}
	rulesDir := os.Getenv("RULES_DIR")
	grantStoreType := os.Getenv("GRANT_STORE")
	if grantStoreType == "" {
		grantStoreType = "memory"
	}
	sessionStoreType := os.Getenv("SESSION_STORE")
	if sessionStoreType == "" {
		sessionStoreType = "memory"
	}
	auditStoreType := strings.ToLower(os.Getenv("AUDIT_STORE"))
	if auditStoreType == "" {
		auditStoreType = "stdout"
	}
	redisURL := os.Getenv("REDIS_URL")

	var st store.Store
	switch dbDriver {
	case "postgres", "postgresql":
		if dbDSN == "" {
			logging.Error(context.Background(), "DB_DSN is required for postgres driver")
			os.Exit(1)
		}
		maxOpen := parseIntEnv("DB_MAX_OPEN", 25)
		maxIdle := parseIntEnv("DB_MAX_IDLE", 5)
		pg, err := store.NewPostgres(dbDSN, maxOpen, maxIdle)
		if err != nil {
			logging.Error(context.Background(), "postgres store failed", "error", err)
			os.Exit(1)
		}
		if err := store.MigratePostgres(pg.DB()); err != nil {
			pg.Close()
			logging.Error(context.Background(), "migrate failed", "error", err)
			os.Exit(1)
		}
		st = pg
	default:
		dsn := dbDSN
		if dsn == "" {
			dsn = dbPath
		}
		var err error
		st, err = store.NewSQLite(dsn)
		if err != nil {
			logging.Error(context.Background(), "store failed", "error", err)
			os.Exit(1)
		}
	}
	defer st.Close()

	issuer, err := token.NewIssuer(issuerURL + "/")
	if err != nil {
		logging.Error(context.Background(), "token issuer failed", "error", err)
		os.Exit(1)
	}

	var grantStore grants.GrantStore
	var sessionStore sessions.Store
	var grantRedis *grants.RedisStore
	var sessionRedis *sessions.RedisStore

	switch grantStoreType {
	case "redis":
		if redisURL == "" {
			logging.Error(context.Background(), "GRANT_STORE=redis requires REDIS_URL")
			os.Exit(1)
		}
		gs, err := grants.NewRedisStore(redisURL)
		if err != nil {
			logging.Error(context.Background(), "grants redis failed", "error", err)
			os.Exit(1)
		}
		grantStore = gs
		grantRedis = gs
		defer gs.Close()
	case "memory":
		fallthrough
	default:
		grantStore = grants.NewStore(5*time.Minute, 30*24*time.Hour)
	}

	switch sessionStoreType {
	case "redis":
		if redisURL == "" {
			logging.Error(context.Background(), "SESSION_STORE=redis requires REDIS_URL")
			os.Exit(1)
		}
		ss, err := sessions.NewRedisStore(redisURL, 7*24*time.Hour)
		if err != nil {
			logging.Error(context.Background(), "sessions redis failed", "error", err)
			os.Exit(1)
		}
		sessionStore = ss
		sessionRedis = ss
		defer ss.Close()
	case "memory":
		fallthrough
	default:
		sessionStore = sessions.NewStore(7 * 24 * time.Hour)
	}

	rulesRunner := rules.NewRunner(rulesDir)
	clientRegistry := clients.NewRegistry()
	if path := os.Getenv("CLIENT_REGISTRY_FILE"); path != "" {
		if err := clientRegistry.LoadFromFile(); err != nil {
			logging.Error(context.Background(), "CLIENT_REGISTRY_FILE load failed", "error", err)
			os.Exit(1)
		}
	} else if err := clientRegistry.LoadFromEnv(); err != nil {
		logging.Warn(context.Background(), "CLIENT_REGISTRY invalid JSON", "error", err)
	}
	clientRegistry.ValidateAndWarn()

	mfaEnabled := strings.ToLower(os.Getenv("MFA_ENABLED")) == "true"
	adaptiveMFAEnabled := strings.ToLower(os.Getenv("ADAPTIVE_MFA_ENABLED")) == "true"
	webauthnEnabled := strings.ToLower(os.Getenv("WEBAUTHN_ENABLED")) == "true"
	webauthnDisplayName := os.Getenv("WEBAUTHN_DISPLAY_NAME")
	adminCfg := adminauth.LoadFromEnv(issuer)
	h := &handlers.Handlers{
		Store:               st,
		Issuer:              issuer,
		IssuerURL:           issuerURL,
		GrantStore:          grantStore,
		SessionStore:        sessionStore,
		RulesRunner:         rulesRunner,
		ClientRegistry:      clientRegistry,
		AccessTokenLifetime: parseIntEnv("ACCESS_TOKEN_LIFETIME", 86400),
		IDTokenLifetime:     parseIntEnv("ID_TOKEN_LIFETIME", 86400),
		MFAEnabled:         mfaEnabled,
		AdaptiveMFAEnabled:  adaptiveMFAEnabled,
		AdminAPIKey:         adminCfg.AdminAPIKey,
	}
	if webauthnEnabled {
		waHandler, err := webauthn.New(webauthn.Config{
			Enabled:     true,
			DisplayName: webauthnDisplayName,
		}, st, issuerURL)
		if err != nil {
			logging.Error(context.Background(), "webauthn init failed", "error", err)
			os.Exit(1)
		}
		h.WebAuthnHandler = waHandler.Router(webauthn.RegisterDeps{
			SessionStore: sessionStore,
			GrantStore:  grantStore,
		})
		logging.Info(context.Background(), "WebAuthn passkeys enabled")
	}
	if grantRedis != nil {
		h.RedisClient = grantRedis.Client()
	} else if sessionRedis != nil {
		h.RedisClient = sessionRedis.Client()
	}
	if samlEntityID := os.Getenv("SAML_ENTITY_ID"); samlEntityID != "" || os.Getenv("SAML_CERT") != "" {
		h.SAMLConfig = &handlers.SAMLConfig{
			EntityID: samlEntityID,
			CertPEM:  os.Getenv("SAML_CERT"),
			KeyPEM:   os.Getenv("SAML_KEY"),
		}
		if h.SAMLConfig.EntityID == "" {
			h.SAMLConfig.EntityID = issuerURL
		}
	}

	switch auditStoreType {
	case "db":
		audit.SetStore(audit.NewDBStore(st))
	default:
		audit.SetStore(nil) // stdout (default)
	}

	auditWebhookURL := os.Getenv("AUDIT_WEBHOOK_URL")
	if auditWebhookURL != "" && (auditStoreType == "db" || auditStoreType == "stdout") {
		audit.SetWebhookURL(auditWebhookURL)
		logging.Info(context.Background(), "audit webhook enabled", "url", auditWebhookURL)
	}

	auditRetentionDays := parseIntEnv("AUDIT_RETENTION_DAYS", 90)
	if auditStoreType == "db" && auditRetentionDays > 0 {
		runAuditRetentionCleanup(st, auditRetentionDays)
	}

	productionMode := strings.ToLower(os.Getenv("PRODUCTION_MODE")) == "true" || strings.ToLower(os.Getenv("PRODUCTION")) == "true"
	useTLS := (tlsCert != "" && tlsKey != "") || (acmeEnabled && acmeDomain != "")
	if acmeEnabled && acmeDomain == "" {
		logging.Error(context.Background(), "TLS_ACME_ENABLED=true requires TLS_ACME_DOMAIN")
		os.Exit(1)
	}
	if acmeEnabled && tlsCert != "" && tlsKey != "" {
		logging.Warn(context.Background(), "ACME enabled; TLS_CERT/TLS_KEY ignored")
	}
	if productionMode && !useTLS {
		logging.Error(context.Background(), "TLS is required in production mode (set TLS_CERT/TLS_KEY or TLS_ACME_ENABLED with TLS_ACME_DOMAIN)")
		os.Exit(1)
	}
	aclMiddleware := acl.LoadFromEnv()
	rateLimiter := ratelimit.New()
	clientLimiter := ratelimit.NewClientLimiter()
	failedAttemptTracker := ratelimit.NewFailedAttemptTracker()
	rateLimiter.SetSuspiciousIPTracker(failedAttemptTracker)
	mux := http.NewServeMux()
	adminHandler := adminui.NewHandler(adminui.Config{
		AdminAPIKey:    adminCfg.AdminAPIKey,
		ProductionMode: adminCfg.ProductionMode,
	})
	mux.Handle("/admin", http.RedirectHandler("/admin/", http.StatusFound))
	mux.Handle("/admin/", adminHandler)
	if graphql.IsEnabled() {
		mux.Handle("/graphql", graphql.Handler(st))
		logging.Info(context.Background(), "GraphQL test API enabled", "path", "/graphql")
	}
	scimHandler := scim.AuthMiddleware(scim.NewHandler(st, issuerURL))
	mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", scimHandler))
	mux.Handle("/", h)
	chain := acl.Middleware(aclMiddleware)(
		tracing.Middleware(
			logging.Middleware(
				metrics.Middleware(
					securityheaders.Middleware(useTLS)(
						cors.Middleware(clientRegistry.AllowedOrigins)(
							adminauth.Middleware(adminCfg)(
								botdetect.Middleware(
									ratelimit.MiddlewareWithClientLimiter(rateLimiter, clientLimiter, failedAttemptTracker, ratelimit.TokenAuthPaths)(mux),
								),
							),
						),
					),
				),
			),
		),
	)

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           chain,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Update active sessions gauge when session store exposes count
	if sc, ok := sessionStore.(sessions.SessionCounter); ok {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				metrics.ActiveSessions.Set(float64(sc.Count()))
			}
		}()
	}

	go func() {
		logging.Info(context.Background(), "auth2 listening", "port", port, "issuer", issuerURL, "acme", acmeEnabled)
		var err error
		if acmeEnabled && acmeDomain != "" {
			m := &autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(acmeDomain),
				Cache:      autocert.DirCache(acmeCacheDir),
				Email:      acmeEmail,
			}
			// Optional: serve HTTP-01 challenges on port 80 for Let's Encrypt
			if acmeHTTPPort := os.Getenv("TLS_ACME_HTTP_PORT"); acmeHTTPPort != "" {
				challengeServer := &http.Server{
					Handler: m.HTTPHandler(nil),
					Addr:    ":" + acmeHTTPPort,
				}
				go func() {
					if err := challengeServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						logging.Warn(context.Background(), "ACME HTTP challenge server failed", "error", err)
					}
				}()
			}
			server.TLSConfig = m.TLSConfig()
			ln, lerr := net.Listen("tcp", ":"+port)
			if lerr != nil {
				logging.Error(context.Background(), "listen failed", "error", lerr)
				os.Exit(1)
			}
			tlsLn := tls.NewListener(ln, server.TLSConfig)
			err = server.Serve(tlsLn)
		} else if useTLS {
			err = server.ListenAndServeTLS(tlsCert, tlsKey)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logging.Error(context.Background(), "server failed", "error", err)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logging.Info(context.Background(), "shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := tracing.Shutdown(ctx); err != nil {
		logging.Warn(context.Background(), "tracing shutdown", "error", err)
	}
	if err := server.Shutdown(ctx); err != nil {
		logging.Warn(context.Background(), "shutdown", "error", err)
	}
	logging.Info(context.Background(), "shutdown complete")
}

// runAuditRetentionCleanup starts a background goroutine and runs cleanup on startup.
func runAuditRetentionCleanup(st store.Store, retentionDays int) {
	doCleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cutoff := time.Now().AddDate(0, 0, -retentionDays)
		n, err := st.DeleteOldAuditLogs(ctx, cutoff)
		if err != nil {
			logging.Warn(context.Background(), "audit retention cleanup failed", "error", err)
			return
		}
		if n > 0 {
			logging.Info(context.Background(), "audit retention cleanup", "deleted", n, "retention_days", retentionDays)
		}
	}
	doCleanup()
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			doCleanup()
		}
	}()
}
