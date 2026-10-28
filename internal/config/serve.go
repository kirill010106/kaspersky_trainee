package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

// ServeConfig holds the environment settings required to run the HTTPS API.
type ServeConfig struct {
	DatabaseURL            string        `env:"DATABASE_URL" env-required:"true"`
	HTTPSAddr              string        `env:"HTTPS_ADDR" env-required:"true"`
	TLSCertFile            string        `env:"TLS_CERT_FILE" env-required:"true"`
	TLSKeyFile             string        `env:"TLS_KEY_FILE" env-required:"true"`
	ReaderKey              string        `env:"READER_KEY" env-required:"true"`
	WriterKey              string        `env:"WRITER_KEY" env-required:"true"`
	DBQueryTimeout         time.Duration `env:"DB_QUERY_TIMEOUT" env-default:"3s"`
	ReadinessTimeout       time.Duration `env:"READINESS_TIMEOUT" env-default:"1s"`
	ShutdownTimeout        time.Duration `env:"SHUTDOWN_TIMEOUT" env-default:"10s"`
	DBMaxConns             int32         `env:"DB_MAX_CONNS" env-default:"10"`
	ReadHeaderTimeout      time.Duration `env:"READ_HEADER_TIMEOUT" env-default:"3s"`
	ReadTimeout            time.Duration `env:"READ_TIMEOUT" env-default:"10s"`
	WriteTimeout           time.Duration `env:"WRITE_TIMEOUT" env-default:"15s"`
	IdleTimeout            time.Duration `env:"IDLE_TIMEOUT" env-default:"60s"`
	MaxHeaderBytes         int           `env:"MAX_HEADER_BYTES" env-default:"16384"`
	APIRatePerMinute       int           `env:"API_RATE_PER_MINUTE" env-default:"120"`
	ReadinessRatePerMinute int           `env:"READINESS_RATE_PER_MINUTE" env-default:"120"`
}

// LoadServe reads and validates server settings from the process environment.
// It does not load a .env file.
func LoadServe() (ServeConfig, error) {
	var cfg ServeConfig
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return ServeConfig{}, fmt.Errorf("read serve config: %w", err)
	}

	for _, field := range []struct {
		name  string
		value string
	}{
		{"DATABASE_URL", cfg.DatabaseURL},
		{"HTTPS_ADDR", cfg.HTTPSAddr},
		{"TLS_CERT_FILE", cfg.TLSCertFile},
		{"TLS_KEY_FILE", cfg.TLSKeyFile},
		{"READER_KEY", cfg.ReaderKey},
		{"WRITER_KEY", cfg.WriterKey},
	} {
		if strings.TrimSpace(field.value) == "" {
			return ServeConfig{}, fmt.Errorf("%s must not be blank", field.name)
		}
	}

	for _, setting := range []struct {
		name  string
		valid bool
	}{
		{"DB_QUERY_TIMEOUT", cfg.DBQueryTimeout > 0},
		{"READINESS_TIMEOUT", cfg.ReadinessTimeout > 0},
		{"SHUTDOWN_TIMEOUT", cfg.ShutdownTimeout > 0},
		{"DB_MAX_CONNS", cfg.DBMaxConns > 0},
		{"READ_HEADER_TIMEOUT", cfg.ReadHeaderTimeout > 0},
		{"READ_TIMEOUT", cfg.ReadTimeout > 0},
		{"WRITE_TIMEOUT", cfg.WriteTimeout > 0},
		{"IDLE_TIMEOUT", cfg.IdleTimeout > 0},
		{"MAX_HEADER_BYTES", cfg.MaxHeaderBytes > 0},
		{"API_RATE_PER_MINUTE", cfg.APIRatePerMinute > 0},
		{"READINESS_RATE_PER_MINUTE", cfg.ReadinessRatePerMinute > 0},
	} {
		if !setting.valid {
			return ServeConfig{}, fmt.Errorf("%s must be positive", setting.name)
		}
	}

	return cfg, nil
}
