//go:build integration

package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/kirill010106/kaspersky_trainee/internal/domain"
	"github.com/kirill010106/kaspersky_trainee/internal/migrations"
	"github.com/kirill010106/kaspersky_trainee/internal/service"
	storagepostgres "github.com/kirill010106/kaspersky_trainee/internal/storage/postgres"
)

func TestMigrations(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()

	container, err := postgres.Run(
		ctx,
		"postgres:16.15-alpine3.24",
		postgres.WithDatabase("safeboard_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		postgres.BasicWaitStrategies(),
	)

	if container != nil {
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(
				context.Background(),
				30*time.Second,
			)
			defer cleanupCancel()

			if err := container.Terminate(cleanupCtx); err != nil {
				t.Errorf("terminate PostgreSQL container: %v", err)
			}
		})
	}

	if err != nil {
		t.Fatalf("start PostgreSQL container: %v", err)
	}

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("get connection string: %v", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})

	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping database: %v", err)
	}

	if err := migrations.Up(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	const existingMD5 = "d41d8cd98f00b204e9800998ecf8427e"

	var createdAt, updatedAt time.Time

	err = db.QueryRowContext(
		ctx,
		`INSERT INTO threats (md5, name, type, severity)
		 VALUES ($1, $2, $3, $4)
		 RETURNING created_at, updated_at`,
		existingMD5,
		"Existing threat",
		"trojan",
		"high",
	).Scan(&createdAt, &updatedAt)
	if err != nil {
		t.Fatalf("insert existing threat: %v", err)
	}

	if createdAt.IsZero() || updatedAt.IsZero() {
		t.Fatal("database returned zero timestamps")
	}

	if !createdAt.Equal(updatedAt) {
		t.Fatalf(
			"timestamps on creation differ: created_at=%v updated_at=%v",
			createdAt,
			updatedAt,
		)
	}

	// Reapplying migrations should preserve the existing data.
	if err := migrations.Up(ctx, db); err != nil {
		t.Fatalf("apply migrations again: %v", err)
	}

	var storedCreatedAt time.Time

	err = db.QueryRowContext(
		ctx,
		`SELECT created_at FROM threats WHERE md5 = $1`,
		existingMD5,
	).Scan(&storedCreatedAt)
	if err != nil {
		t.Fatalf("read threat after repeated migration: %v", err)
	}

	if !storedCreatedAt.Equal(createdAt) {
		t.Fatal("created_at changed after repeated migration")
	}

	t.Run("HTTP slice", func(t *testing.T) {
		testHTTPSlice(t, ctx, dsn)
	})

	t.Run("repository create", func(t *testing.T) {
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("create pool: %v", err)
		}
		defer pool.Close()

		repository, err := storagepostgres.New(pool, 3*time.Second)
		if err != nil {
			t.Fatalf("create repository: %v", err)
		}

		const md5 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

		data := domain.ThreatData{
			Name:        "Test threat",
			Description: "Test description",
			Type:        domain.ThreatTypeTrojan,
			Severity:    domain.SeverityHigh,
		}

		threat, err := repository.Create(ctx, md5, data)
		if err != nil {
			t.Fatalf("create threat: %v", err)
		}

		if threat.MD5 != md5 ||
			threat.Name != data.Name ||
			threat.Description != data.Description ||
			threat.Type != data.Type ||
			threat.Severity != data.Severity {
			t.Fatalf("unexpected threat: %+v", threat)
		}

		if threat.CreatedAt.IsZero() || threat.UpdatedAt.IsZero() {
			t.Fatal("expected database-generated timestamps")
		}

		got, err := repository.Get(ctx, md5)
		if err != nil {
			t.Fatalf("get created threat: %v", err)
		}

		if got.MD5 != threat.MD5 ||
			got.Name != threat.Name ||
			got.Description != threat.Description ||
			got.Type != threat.Type ||
			got.Severity != threat.Severity ||
			!got.CreatedAt.Equal(threat.CreatedAt) ||
			!got.UpdatedAt.Equal(threat.UpdatedAt) {
			t.Fatalf("read threat = %+v; want %+v", got, threat)
		}

		const missingMD5 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

		_, err = repository.Get(ctx, missingMD5)
		if !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got: %v", err)
		}

		replacement := domain.ThreatData{
			Name:        "Updated threat",
			Description: "",
			Type:        domain.ThreatTypeWorm,
			Severity:    domain.SeverityCritical,
		}

		updated, err := repository.Replace(ctx, md5, replacement)
		if err != nil {
			t.Fatalf("replace threat: %v", err)
		}

		if updated.MD5 != md5 ||
			updated.Name != replacement.Name ||
			updated.Description != replacement.Description ||
			updated.Type != replacement.Type ||
			updated.Severity != replacement.Severity {
			t.Fatalf("unexpected updated threat: %+v", updated)
		}

		if !updated.CreatedAt.Equal(threat.CreatedAt) {
			t.Fatalf(
				"created_at changed: got %v, want %v",
				updated.CreatedAt,
				threat.CreatedAt,
			)
		}

		if updated.UpdatedAt.IsZero() {
			t.Fatal("expected updated_at from database")
		}

		stored, err := repository.Get(ctx, md5)
		if err != nil {
			t.Fatalf("get updated threat: %v", err)
		}

		if stored.Name != replacement.Name ||
			stored.Description != replacement.Description ||
			stored.Type != replacement.Type ||
			stored.Severity != replacement.Severity {
			t.Fatalf("replacement was not persisted: %+v", stored)
		}

		_, err = repository.Replace(ctx, missingMD5, replacement)
		if !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for replacement, got: %v", err)
		}

		_, err = repository.Get(ctx, missingMD5)
		if !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("replacement created a missing threat: %v", err)
		}

		_, err = repository.Create(ctx, md5, data)
		if !errors.Is(err, service.ErrAlreadyExists) {
			t.Fatalf("expected ErrAlreadyExists, got: %v", err)
		}
	})

	t.Run("repository timeout", func(t *testing.T) {
		config, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatalf("parse pool config: %v", err)
		}
		config.MaxConns = 1

		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatalf("create pool: %v", err)
		}
		defer pool.Close()

		connection, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire connection: %v", err)
		}
		defer connection.Release()

		repository, err := storagepostgres.New(pool, 100*time.Millisecond)
		if err != nil {
			t.Fatalf("create repository: %v", err)
		}

		_, err = repository.Get(ctx, existingMD5)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected repository timeout, got: %v", err)
		}
	})

	t.Run("duplicate md5", func(t *testing.T) {
		_, err := db.ExecContext(
			ctx,
			`INSERT INTO threats (md5, name, type, severity)
			 VALUES ($1, $2, $3, $4)`,
			existingMD5,
			"Duplicate",
			"trojan",
			"high",
		)

		assertPostgresError(t, err, "23505", "threats_pkey")
	})

	type threatInput struct {
		md5         string
		name        string
		description string
		threatType  string
		severity    string
	}

	tests := []struct {
		name           string
		change         func(*threatInput)
		wantConstraint string
	}{
		{
			name: "name at limit",
			change: func(v *threatInput) {
				v.name = strings.Repeat("я", 200)
			},
		},
		{
			name: "name exceeds limit",
			change: func(v *threatInput) {
				v.name = strings.Repeat("я", 201)
			},
			wantConstraint: "threats_name_length",
		},
		{
			name: "empty name",
			change: func(v *threatInput) {
				v.name = ""
			},
			wantConstraint: "threats_name_length",
		},
		{
			name: "description at limit",
			change: func(v *threatInput) {
				v.description = strings.Repeat("я", 4096)
			},
		},
		{
			name: "description exceeds limit",
			change: func(v *threatInput) {
				v.description = strings.Repeat("я", 4097)
			},
			wantConstraint: "threats_description_length",
		},
		{
			name: "invalid type",
			change: func(v *threatInput) {
				v.threatType = "virus"
			},
			wantConstraint: "threats_type_check",
		},
		{
			name: "invalid severity",
			change: func(v *threatInput) {
				v.severity = "unknown"
			},
			wantConstraint: "threats_severity_check",
		},
		{
			name: "non-hex md5",
			change: func(v *threatInput) {
				v.md5 = strings.Repeat("g", 32)
			},
			wantConstraint: "threats_md5_format",
		},
		{
			name: "uppercase md5",
			change: func(v *threatInput) {
				v.md5 = strings.ToUpper(existingMD5)
			},
			wantConstraint: "threats_md5_format",
		},
		{
			name: "md5 with trailing space",
			change: func(v *threatInput) {
				v.md5 = existingMD5 + " "
			},
			wantConstraint: "threats_md5_format",
		},
		{
			name: "md5 with leading ampersand",
			change: func(v *threatInput) {
				v.md5 = "&" + existingMD5
			},
			wantConstraint: "threats_md5_format",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := threatInput{
				md5:        fmt.Sprintf("%032x", i+1),
				name:       "Threat",
				threatType: "trojan",
				severity:   "high",
			}

			tt.change(&input)

			_, err := db.ExecContext(
				ctx,
				`INSERT INTO threats (md5, name, description, type, severity)
				 VALUES ($1, $2, $3, $4, $5)`,
				input.md5,
				input.name,
				input.description,
				input.threatType,
				input.severity,
			)

			if tt.wantConstraint == "" {
				if err != nil {
					t.Fatalf("insert valid threat: %v", err)
				}
				return
			}

			assertPostgresError(t, err, "23514", tt.wantConstraint)
		})
	}
}

func assertPostgresError(t *testing.T, err error, code, constraint string) {
	t.Helper()

	if err == nil {
		t.Fatal("expected PostgreSQL error, got nil")
	}

	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		t.Fatalf("expected PostgreSQL error, got %T: %v", err, err)
	}

	if pgErr.Code != code || pgErr.ConstraintName != constraint {
		t.Fatalf(
			"unexpected PostgreSQL error: code=%q constraint=%q; want code=%q constraint=%q",
			pgErr.Code,
			pgErr.ConstraintName,
			code,
			constraint,
		)
	}
}
