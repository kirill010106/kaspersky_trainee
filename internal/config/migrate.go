package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ilyakaznacheev/cleanenv"
)

type MigrateConfig struct {
	DatabaseURL string `env:"DATABASE_URL" env-required:"true"`
}

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
