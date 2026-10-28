package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ilyakaznacheev/cleanenv"
)

// MigrateConfig holds the database connection needed by the migrate command.
type MigrateConfig struct {
	DatabaseURL string `env:"DATABASE_URL" env-required:"true"`
}

// LoadMigrate reads and validates DATABASE_URL from the process environment.
// It does not load a .env file or require serve-only settings.
func LoadMigrate() (MigrateConfig, error) {
	var cfg MigrateConfig
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return MigrateConfig{}, fmt.Errorf("read migrate config: %w", err)
	}
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		return MigrateConfig{}, errors.New("DATABASE_URL must not be blank")
	}
	return cfg, nil
}
