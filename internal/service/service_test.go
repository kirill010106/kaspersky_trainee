package service_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kirill010106/kaspersky_trainee/internal/domain"
	"github.com/kirill010106/kaspersky_trainee/internal/service"
)

type fakeRepository struct {
	calls int
	op    string
	ctx   context.Context
	md5   string
	data  domain.ThreatData
	err   error
}

func (f *fakeRepository) record(
	ctx context.Context,
	op string,
	md5 string,
	data domain.ThreatData,
) (domain.Threat, error) {
	f.calls++
	f.op = op
	f.ctx = ctx
	f.md5 = md5
	f.data = data

	if f.err != nil {
		return domain.Threat{}, f.err
	}
	return domain.Threat{MD5: md5}, nil
}

func (f *fakeRepository) Get(
	ctx context.Context,
	md5 string,
) (domain.Threat, error) {
	return f.record(ctx, "get", md5, domain.ThreatData{})
}

func (f *fakeRepository) Create(
	ctx context.Context,
	md5 string,
	data domain.ThreatData,
) (domain.Threat, error) {
	return f.record(ctx, "create", md5, data)
}

func (f *fakeRepository) Replace(
	ctx context.Context,
	md5 string,
	data domain.ThreatData,
) (domain.Threat, error) {
	return f.record(ctx, "replace", md5, data)
}

func TestServiceNormalizesInputAndPreservesRepositoryErrors(t *testing.T) {
	const canonicalMD5 = "d41d8cd98f00b204e9800998ecf8427e"

	input := domain.ThreatData{
		Name:     "\u2003 Trojan \t",
		Type:     domain.ThreatTypeTrojan,
		Severity: domain.SeverityHigh,
	}
	wantData := input
	wantData.Name = "Trojan"

	tests := []struct {
		name     string
		run      func(context.Context, *service.Service) (domain.Threat, error)
		wantData domain.ThreatData
		repoErr  error
	}{
		{
			name: "get",
			run: func(ctx context.Context, svc *service.Service) (domain.Threat, error) {
				return svc.Get(ctx, strings.ToUpper(canonicalMD5))
			},
			repoErr: service.ErrNotFound,
		},
		{
			name: "create",
			run: func(ctx context.Context, svc *service.Service) (domain.Threat, error) {
				return svc.Create(ctx, strings.ToUpper(canonicalMD5), input)
			},
			wantData: wantData,
			repoErr:  service.ErrAlreadyExists,
		},
		{
			name: "replace",
			run: func(ctx context.Context, svc *service.Service) (domain.Threat, error) {
				return svc.Replace(ctx, strings.ToUpper(canonicalMD5), input)
			},
			wantData: wantData,
			repoErr:  service.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			repo := &fakeRepository{}
			svc := service.New(repo)

			got, err := tt.run(ctx, svc)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.MD5 != canonicalMD5 {
				t.Errorf("returned MD5 = %q, want %q", got.MD5, canonicalMD5)
			}
			if repo.calls != 1 || repo.op != tt.name {
				t.Fatalf("repository calls = %d, operation = %q",
					repo.calls, repo.op)
			}
			if repo.md5 != canonicalMD5 {
				t.Errorf("repository MD5 = %q, want %q", repo.md5, canonicalMD5)
			}
			if repo.data != tt.wantData {
				t.Errorf("repository data = %+v, want %+v", repo.data, tt.wantData)
			}

			repo.err = fmt.Errorf("repository: %w", tt.repoErr)
			_, err = tt.run(ctx, svc)
			if !errors.Is(err, tt.repoErr) {
				t.Errorf("error = %v, want wrapped %v", err, tt.repoErr)
			}

			if repo.ctx == nil {
				t.Fatal("repository did not receive a context")
			}
			cancel()
			if !errors.Is(repo.ctx.Err(), context.Canceled) {
				t.Errorf("repository context error = %v, want canceled", repo.ctx.Err())
			}
		})
	}
}

func TestServiceRejectsInvalidInputBeforeRepository(t *testing.T) {
	const md5 = "d41d8cd98f00b204e9800998ecf8427e"

	validData := domain.ThreatData{
		Name:     "Trojan",
		Type:     domain.ThreatTypeTrojan,
		Severity: domain.SeverityHigh,
	}
	invalidData := validData
	invalidData.Name = " \t"

	ctx := t.Context()

	tests := []struct {
		name      string
		run       func(*service.Service) (domain.Threat, error)
		wantField string
	}{
		{
			name: "get with invalid MD5",
			run: func(svc *service.Service) (domain.Threat, error) {
				return svc.Get(ctx, "invalid")
			},
			wantField: "md5",
		},
		{
			name: "create with invalid MD5",
			run: func(svc *service.Service) (domain.Threat, error) {
				return svc.Create(ctx, "invalid", validData)
			},
			wantField: "md5",
		},
		{
			name: "create with invalid data",
			run: func(svc *service.Service) (domain.Threat, error) {
				return svc.Create(ctx, md5, invalidData)
			},
			wantField: "name",
		},
		{
			name: "replace with invalid data",
			run: func(svc *service.Service) (domain.Threat, error) {
				return svc.Replace(ctx, md5, invalidData)
			},
			wantField: "name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeRepository{}
			got, err := tt.run(service.New(repo))

			validationErr, ok := errors.AsType[*domain.ValidationError](err)
			if !ok || validationErr.Field != tt.wantField {
				t.Fatalf("error = %v, want validation error for %q",
					err, tt.wantField)
			}
			if got != (domain.Threat{}) {
				t.Errorf("result = %+v, want zero value on error", got)
			}
			if repo.calls != 0 {
				t.Errorf("repository was called %d times, want 0", repo.calls)
			}
		})
	}
}
