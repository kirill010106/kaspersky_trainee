package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadServe(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost:5432/safeboard")
	t.Setenv("HTTPS_ADDR", "127.0.0.1:8443")
	t.Setenv("TLS_CERT_FILE", "cert.pem")
	t.Setenv("TLS_KEY_FILE", "key.pem")
	t.Setenv("READER_KEY", "reader-test-key")
	t.Setenv("WRITER_KEY", "writer-test-key")
	t.Setenv("DB_QUERY_TIMEOUT", "4s")
	t.Setenv("READINESS_TIMEOUT", "2s")
	t.Setenv("SHUTDOWN_TIMEOUT", "9s")
	t.Setenv("DB_MAX_CONNS", "7")
	t.Setenv("READ_HEADER_TIMEOUT", "4s")
	t.Setenv("READ_TIMEOUT", "11s")
	t.Setenv("WRITE_TIMEOUT", "16s")
	t.Setenv("IDLE_TIMEOUT", "65s")
	t.Setenv("MAX_HEADER_BYTES", "8192")
	t.Setenv("API_RATE_PER_MINUTE", "90")
	t.Setenv("READINESS_RATE_PER_MINUTE", "70")

	cfg, err := LoadServe()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPSAddr != "127.0.0.1:8443" ||
		cfg.ReaderKey != "reader-test-key" ||
		cfg.WriterKey != "writer-test-key" {
		t.Fatal("unexpected required serve settings")
	}

	t.Setenv("TLS_KEY_FILE", " \t ")
	if _, err := LoadServe(); err == nil {
		t.Fatal("expected error for blank TLS_KEY_FILE")
	}

	t.Setenv("TLS_KEY_FILE", "key.pem")
	t.Setenv("DB_MAX_CONNS", "0")
	if _, err := LoadServe(); err == nil {
		t.Fatal("expected error for non-positive DB_MAX_CONNS")
	}

	t.Setenv("DB_MAX_CONNS", "7")
	t.Setenv("API_RATE_PER_MINUTE", "0")
	if _, err := LoadServe(); err == nil {
		t.Fatal("expected error for non-positive API_RATE_PER_MINUTE")
	}

	t.Setenv("API_RATE_PER_MINUTE", "90")
	t.Setenv("DB_QUERY_TIMEOUT", "0s")
	if _, err := LoadServe(); err == nil {
		t.Fatal("expected error for non-positive DB_QUERY_TIMEOUT")
	}

	if cfg.DBQueryTimeout != 4*time.Second ||
		cfg.ReadinessTimeout != 2*time.Second ||
		cfg.ShutdownTimeout != 9*time.Second ||
		cfg.DBMaxConns != 7 {
		t.Fatal("unexpected numeric serve settings")
	}

	if cfg.ReadHeaderTimeout != 4*time.Second ||
		cfg.ReadTimeout != 11*time.Second ||
		cfg.WriteTimeout != 16*time.Second ||
		cfg.IdleTimeout != 65*time.Second ||
		cfg.MaxHeaderBytes != 8192 ||
		cfg.APIRatePerMinute != 90 ||
		cfg.ReadinessRatePerMinute != 70 {
		t.Fatal("unexpected HTTP serve settings")
	}
}

func TestLoadServeDefaults(t *testing.T) {
	for _, name := range []string{
		"DB_QUERY_TIMEOUT",
		"READINESS_TIMEOUT",
		"SHUTDOWN_TIMEOUT",
		"DB_MAX_CONNS",
		"READ_HEADER_TIMEOUT",
		"READ_TIMEOUT",
		"WRITE_TIMEOUT",
		"IDLE_TIMEOUT",
		"MAX_HEADER_BYTES",
		"API_RATE_PER_MINUTE",
		"READINESS_RATE_PER_MINUTE",
	} {
		// Setenv registers restoration; Unsetenv allows env-default to apply.
		t.Setenv(name, "temporary")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("DATABASE_URL", "postgres://localhost:5432/safeboard")
	t.Setenv("HTTPS_ADDR", "127.0.0.1:8443")
	t.Setenv("TLS_CERT_FILE", "cert.pem")
	t.Setenv("TLS_KEY_FILE", "key.pem")
	t.Setenv("READER_KEY", "reader-test-key")
	t.Setenv("WRITER_KEY", "writer-test-key")

	cfg, err := LoadServe()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBQueryTimeout != 3*time.Second ||
		cfg.ReadinessTimeout != time.Second ||
		cfg.ShutdownTimeout != 10*time.Second ||
		cfg.DBMaxConns != 10 ||
		cfg.ReadHeaderTimeout != 3*time.Second ||
		cfg.ReadTimeout != 10*time.Second ||
		cfg.WriteTimeout != 15*time.Second ||
		cfg.IdleTimeout != 60*time.Second ||
		cfg.MaxHeaderBytes != 16*1024 ||
		cfg.APIRatePerMinute != 120 ||
		cfg.ReadinessRatePerMinute != 120 {
		t.Fatal("unexpected serve defaults")
	}
}
