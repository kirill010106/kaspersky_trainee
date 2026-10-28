package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kirill010106/kaspersky_trainee/internal/domain"
	"github.com/kirill010106/kaspersky_trainee/internal/service"
)

// Repository stores threats in PostgreSQL.
// The caller owns the pool and is responsible for closing it.
type Repository struct {
	pool         *pgxpool.Pool
	queryTimeout time.Duration
}

var _ service.Repository = (*Repository)(nil)

// New creates a repository. queryTimeout bounds Get, Create, and Replace;
// CheckReady uses its caller's context.
func New(pool *pgxpool.Pool, queryTimeout time.Duration) (*Repository, error) {
	if pool == nil {
		return nil, errors.New("postgres pool is nil")
	}
	if queryTimeout <= 0 {
		return nil, fmt.Errorf("query timeout must be positive: %s", queryTimeout)
	}

	return &Repository{
		pool:         pool,
		queryTimeout: queryTimeout,
	}, nil
}

// CheckReady checks access to the expected threat columns without reading rows.
// It does not verify the goose migration version or schema constraints.
func (r *Repository) CheckReady(ctx context.Context) error {
	const query = `
		SELECT md5, name, description, type, severity, created_at, updated_at
		FROM threats
		LIMIT 0
	`

	if _, err := r.pool.Exec(ctx, query); err != nil {
		return fmt.Errorf("check threats schema: %w", err)
	}
	return nil
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

	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	err := r.pool.QueryRow(
		queryCtx,
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

	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	err := r.pool.QueryRow(queryCtx, query, md5).Scan(
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

	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	err := r.pool.QueryRow(
		queryCtx,
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
