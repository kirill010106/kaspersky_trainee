package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/kirill010106/kaspersky_trainee/internal/config"
	"github.com/kirill010106/kaspersky_trainee/internal/migrations"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 || args[0] != "migrate" {
		return errors.New("usage: service migrate")
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	return runMigrate(ctx)
}

func runMigrate(ctx context.Context) error {
	cfg, err := config.LoadMigrate()
	if err != nil {
		return err
	}

	connConfig, err := pgx.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return errors.New("invalid DATABASE_URL")
	}

	db := stdlib.OpenDB(*connConfig)
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}

	return migrations.Up(ctx, db)
}
