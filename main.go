package main

import (
	"log"
	"net/http"
	"os"

	"github.com/radimal/fake-auth0/internal/handlers"
	"github.com/radimal/fake-auth0/internal/store"
	"github.com/radimal/fake-auth0/internal/token"
)

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

	st, err := store.NewSQLite(dbPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	issuer, err := token.NewIssuer(issuerURL + "/")
	if err != nil {
		log.Fatalf("token: %v", err)
	}

	h := &handlers.Handlers{
		Store:     st,
		Issuer:    issuer,
		IssuerURL: issuerURL,
	}

	addr := ":" + port
	log.Printf("fake-auth0 listening on %s (issuer=%s)", addr, issuerURL)
	log.Fatal(http.ListenAndServe(addr, h))
}
