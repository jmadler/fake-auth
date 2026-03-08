package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jmadler/fake-auth/internal/clients"
	"github.com/jmadler/fake-auth/internal/grants"
	"github.com/jmadler/fake-auth/internal/handlers"
	"github.com/jmadler/fake-auth/internal/rules"
	"github.com/jmadler/fake-auth/internal/sessions"
	"github.com/jmadler/fake-auth/internal/store"
	"github.com/jmadler/fake-auth/internal/token"
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
	port := os.Getenv("PORT")
	if port == "" {
		port = "9092"
	}
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
	rulesDir := os.Getenv("RULES_DIR")

	st, err := store.NewSQLite(dbPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	issuer, err := token.NewIssuer(issuerURL + "/")
	if err != nil {
		log.Fatalf("token: %v", err)
	}

	grantStore := grants.NewStore(5*time.Minute, 30*24*time.Hour)
	sessionStore := sessions.NewStore(7 * 24 * time.Hour) // 7 days
	rulesRunner := rules.NewRunner(rulesDir)
	clientRegistry := clients.NewRegistry()
	var extraAccessTokenClaims map[string]interface{}
	if v := os.Getenv("ACCESS_TOKEN_EXTRA_CLAIMS"); v != "" {
		if err := json.Unmarshal([]byte(v), &extraAccessTokenClaims); err != nil {
			log.Printf("warning: invalid ACCESS_TOKEN_EXTRA_CLAIMS JSON: %v", err)
		}
	}
	if err := clientRegistry.LoadFromEnv(); err != nil {
		log.Printf("warning: CLIENT_REGISTRY: %v", err)
	}

	h := &handlers.Handlers{
		Store:                  st,
		Issuer:                 issuer,
		IssuerURL:              issuerURL,
		GrantStore:             grantStore,
		SessionStore:           sessionStore,
		RulesRunner:            rulesRunner,
		ClientRegistry:         clientRegistry,
		AccessTokenLifetime:    parseIntEnv("ACCESS_TOKEN_LIFETIME", 86400),
		IDTokenLifetime:        parseIntEnv("ID_TOKEN_LIFETIME", 86400),
		ExtraAccessTokenClaims: extraAccessTokenClaims,
	}

	addr := ":" + port
	log.Printf("fake-auth listening on %s (issuer=%s)", addr, issuerURL)
	if tlsCert != "" && tlsKey != "" {
		log.Fatal(http.ListenAndServeTLS(addr, tlsCert, tlsKey, h))
	} else {
		log.Fatal(http.ListenAndServe(addr, h))
	}
}
