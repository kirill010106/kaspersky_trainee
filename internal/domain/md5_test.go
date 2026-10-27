package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/kirill010106/kaspersky_trainee/internal/domain"
)

func TestNormalizeMD5(t *testing.T) {
	const canonical = "d41d8cd98f00b204e9800998ecf8427e"

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"lowercase", canonical, canonical, false},
		{"uppercase", strings.ToUpper(canonical), canonical, false},
		{"mixed case", "D41d8cd98f00b204e9800998ecf8427e", canonical, false},
		{"empty", "", "", true},
		{"too short", canonical[:31], "", true},
		{"too long", canonical + "0", "", true},
		{"non hexadecimal", "g" + canonical[1:], "", true},
		{"leading space", " " + canonical, "", true},
		{"trailing space", canonical + " ", "", true},
		{"non ASCII with 32 bytes", strings.Repeat("а", 16), "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := domain.NormalizeMD5(tt.input)

			if tt.wantErr {
				validationErr, ok := errors.AsType[*domain.ValidationError](err)
				if !ok {
					t.Fatalf("error = %v, want *domain.ValidationError", err)
				}
				if validationErr.Field != "md5" {
					t.Errorf("field = %q, want md5", validationErr.Field)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("NormalizeMD5() = %q, want %q", got, tt.want)
			}
		})
	}
}
