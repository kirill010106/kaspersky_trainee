package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kirill010106/kaspersky_trainee/internal/domain"
	"github.com/kirill010106/kaspersky_trainee/internal/service"
)

// Repository stores threats in PostgreSQL.
// The caller owns the pool and is responsible for closing it.
type Repository struct {
	pool *pgxpool.Pool
}

var _ service.Repository = (*Repository)(nil)

func New(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) Create(
	ctx context.Context,
	md5 string,
	data domain.ThreatData,
) (domain.Threat, error) {
	const query = `
		INSERT INTO threats (md5, name, description, type, severity)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING md5, name, description, type, severity, created_at, updated_at
	`

	var threat domain.Threat

	err := r.pool.QueryRow(
		ctx,
		query,
		md5,
		data.Name,
		data.Description,
		data.Type,
		data.Severity,
	).Scan(
		&threat.MD5,
		&threat.Name,
		&threat.Description,
		&threat.Type,
		&threat.Severity,
		&threat.CreatedAt,
		&threat.UpdatedAt,
	)
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok &&
			pgErr.Code == "23505" &&
			pgErr.ConstraintName == "threats_pkey" {
			return domain.Threat{}, fmt.Errorf(
				"create threat: %w",
				service.ErrAlreadyExists,
			)
		}

		return domain.Threat{}, fmt.Errorf("create threat: %w", err)
	}

	return threat, nil
}

func (r *Repository) Get(ctx context.Context, md5 string) (domain.Threat, error) {
	const query = `
		SELECT md5, name, description, type, severity, created_at, updated_at
		FROM threats
		WHERE md5 = $1
	`

	var threat domain.Threat

	err := r.pool.QueryRow(ctx, query, md5).Scan(
		&threat.MD5,
		&threat.Name,
		&threat.Description,
		&threat.Type,
		&threat.Severity,
		&threat.CreatedAt,
		&threat.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Threat{}, fmt.Errorf("get threat: %w", service.ErrNotFound)
		}

		return domain.Threat{}, fmt.Errorf("get threat: %w", err)
	}

	return threat, nil
}

func (r *Repository) Replace(
	ctx context.Context,
	md5 string,
	data domain.ThreatData,
) (domain.Threat, error) {
	const query = `
		UPDATE threats
		SET name = $2,
		    description = $3,
		    type = $4,
		    severity = $5,
		    updated_at = CURRENT_TIMESTAMP
		WHERE md5 = $1
		RETURNING md5, name, description, type, severity, created_at, updated_at
	`

	var threat domain.Threat

	err := r.pool.QueryRow(
		ctx,
		query,
		md5,
		data.Name,
		data.Description,
		data.Type,
		data.Severity,
	).Scan(
		&threat.MD5,
		&threat.Name,
		&threat.Description,
		&threat.Type,
		&threat.Severity,
		&threat.CreatedAt,
		&threat.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Threat{}, fmt.Errorf(
				"replace threat: %w",
				service.ErrNotFound,
			)
		}

		return domain.Threat{}, fmt.Errorf("replace threat: %w", err)
	}

	return threat, nil
}
