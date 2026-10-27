package config

import "testing"

func TestLoadMigrate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		const dsn = "postgres://localhost:5432/safeboard"
		t.Setenv("DATABASE_URL", dsn)

		cfg, err := LoadMigrate()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DatabaseURL != dsn {
			t.Fatalf("DatabaseURL = %q, want %q", cfg.DatabaseURL, dsn)
		}
	})

	for _, tc := range []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "whitespace", value: " \t "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DATABASE_URL", tc.value)
			if _, err := LoadMigrate(); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}
