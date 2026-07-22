package migrations

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed *.sql
var migrationsFS embed.FS

// Run applies pending migration SQL files in order.
// It creates a schema_migrations table to track applied versions.
func Run(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir(".")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, name := range files {
		version := strings.TrimSuffix(name, ".sql")
		var applied string
		err := db.QueryRow(`SELECT version FROM schema_migrations WHERE version = $1`, version).Scan(&applied)
		if err == nil {
			continue // already applied
		}
		if err != sql.ErrNoRows {
			return fmt.Errorf("check migration %s: %w", version, err)
		}

		body, err := migrationsFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		_, err = db.Exec(string(body))
		if err != nil {
			return fmt.Errorf("apply migration %s: %w", version, err)
		}

		_, err = db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1)`, version)
		if err != nil {
			return fmt.Errorf("record migration %s: %w", version, err)
		}
	}
	return nil
}
