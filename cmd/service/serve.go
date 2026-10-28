package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kirill010106/kaspersky_trainee/internal/config"
	"github.com/kirill010106/kaspersky_trainee/internal/httpapi"
	"github.com/kirill010106/kaspersky_trainee/internal/service"
	storagepostgres "github.com/kirill010106/kaspersky_trainee/internal/storage/postgres"
)

func runServe(ctx context.Context, stopSignals context.CancelFunc) error {
	cfg, err := config.LoadServe()
	if err != nil {
		return err
	}

	certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}

	poolConfig, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return errors.New("invalid DATABASE_URL")
	}
	poolConfig.MaxConns = cfg.DBMaxConns

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return fmt.Errorf("create PostgreSQL pool: %w", err)
	}
	defer pool.Close()

	repository, err := storagepostgres.New(pool, cfg.DBQueryTimeout)
	if err != nil {
		return err
	}

	readyCtx, cancelReady := context.WithTimeout(ctx, cfg.ReadinessTimeout)
	err = repository.CheckReady(readyCtx)
	cancelReady()
	if err != nil {
		return fmt.Errorf("check PostgreSQL schema: %w", err)
	}

	threatService := service.New(repository)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	handler, err := httpapi.NewRouter(threatService, httpapi.RouterOptions{
		Logger:                 logger,
		ReaderKey:              cfg.ReaderKey,
		WriterKey:              cfg.WriterKey,
		CheckReady:             repository.CheckReady,
		ReadinessTimeout:       cfg.ReadinessTimeout,
		APIRatePerMinute:       cfg.APIRatePerMinute,
		ReadinessRatePerMinute: cfg.ReadinessRatePerMinute,
	})
	if err != nil {
		return fmt.Errorf("create HTTP router: %w", err)
	}

	server := &http.Server{
		Addr:              cfg.HTTPSAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
		},
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTPS: %w", err)

	case <-ctx.Done():
		// Stop intercepting signals so another interrupt can terminate shutdown.
		stopSignals()
		// The signal context is canceled; Shutdown needs its own deadline.
		shutdownCtx, cancelShutdown := context.WithTimeout(
			context.Background(),
			cfg.ShutdownTimeout,
		)
		defer cancelShutdown()

		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return fmt.Errorf("shutdown HTTPS: %w", err)
		}

		if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTPS: %w", err)
		}
		return nil
	}
}
