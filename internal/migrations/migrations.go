package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"
)

//go:embed sql/*.sql
var migrationFiles embed.FS

// Up applies all pending embedded migrations.
// The caller owns db and is responsible for closing it.
func Up(ctx context.Context, db *sql.DB) error {
	migrationFS, err := fs.Sub(migrationFiles, "sql")
	if err != nil {
		return fmt.Errorf("access embedded migrations: %w", err)
	}

	provider, err := goose.NewProvider(
		goose.DialectPostgres,
		db,
		migrationFS,
	)
	if err != nil {
		return fmt.Errorf("create migration provider: %w", err)
	}

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	return nil
}
