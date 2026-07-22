package store

import (
	"database/sql"

	"github.com/jmadler/auth2/migrations"
)

// MigratePostgres runs pending migrations via the migrations package.
func MigratePostgres(db *sql.DB) error {
	return migrations.Run(db)
}
