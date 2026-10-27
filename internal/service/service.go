package service

import (
	"context"
	"errors"

	"github.com/kirill010106/kaspersky_trainee/internal/domain"
)

var (
	ErrNotFound      = errors.New("threat not found")
	ErrAlreadyExists = errors.New("threat already exists")
)

// Repository stores and retrieves threat records.
// Get and Replace return an error matching ErrNotFound for a missing record.
// Create returns an error matching ErrAlreadyExists for a duplicate MD5.
type Repository interface {
	Get(ctx context.Context, md5 string) (domain.Threat, error)
	Create(ctx context.Context, md5 string, data domain.ThreatData) (domain.Threat, error)
	Replace(ctx context.Context, md5 string, data domain.ThreatData) (domain.Threat, error)
}

type Service struct {
	repository Repository
}

func New(repository Repository) *Service {
	return &Service{
		repository: repository,
	}
}

func (s *Service) Get(ctx context.Context, md5 string) (domain.Threat, error) {
	normalizedMD5, err := domain.NormalizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}

	return s.repository.Get(ctx, normalizedMD5)
}

func (s *Service) Create(ctx context.Context, md5 string, data domain.ThreatData) (domain.Threat, error) {
	normalizedMD5, err := domain.NormalizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}

	normalizedData, err := data.NormalizeAndValidate()
	if err != nil {
		return domain.Threat{}, err
	}

	return s.repository.Create(ctx, normalizedMD5, normalizedData)
}

func (s *Service) Replace(ctx context.Context, md5 string, data domain.ThreatData) (domain.Threat, error) {
	normalizedMD5, err := domain.NormalizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}

	normalizedData, err := data.NormalizeAndValidate()
	if err != nil {
		return domain.Threat{}, err
	}
	return s.repository.Replace(ctx, normalizedMD5, normalizedData)
}
