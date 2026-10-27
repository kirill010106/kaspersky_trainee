package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/kirill010106/kaspersky_trainee/internal/domain"
)

func TestThreatDataNormalizeAndValidate(t *testing.T) {
	tests := []struct {
		name        string
		inputName   string
		description string
		wantName    string
	}{
		{
			name:        "unicode whitespace",
			inputName:   "\u2003\tTrojan  Generic \u00a0",
			description: "\n details \t",
			wantName:    "Trojan  Generic",
		},
		{
			name:        "length boundaries after trim",
			inputName:   "\u2003" + strings.Repeat("я", 200) + "\u00a0",
			description: "\n" + strings.Repeat("🙂", 4094) + "\t",
			wantName:    strings.Repeat("я", 200),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := domain.ThreatData{
				Name:        tt.inputName,
				Description: tt.description,
				Type:        domain.ThreatTypeTrojan,
				Severity:    domain.SeverityHigh,
			}

			want := input
			want.Name = tt.wantName

			got, err := input.NormalizeAndValidate()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != want {
				t.Errorf("normalized data = %+v, want %+v", got, want)
			}
			if input.Name != tt.inputName {
				t.Error("normalization modified the original value")
			}
		})
	}
}

func TestThreatDataInvalidFields(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{"empty name", "name", ""},
		{"blank name", "name", "\u2003 \t"},
		{"long name", "name", strings.Repeat("я", 201)},
		{"invalid name utf8", "name", "Trojan\xff"},
		{"name with NUL", "name", "Trojan\x00Generic"},
		{"long description", "description", strings.Repeat("🙂", 4097)},
		{"invalid description utf8", "description", "\xff"},
		{"description with NUL", "description", "text\x00"},
		{"empty type", "type", ""},
		{"unknown type", "type", "virus"},
		{"type casing", "type", "Trojan"},
		{"empty severity", "severity", ""},
		{"unknown severity", "severity", "urgent"},
		{"severity casing", "severity", "HIGH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := domain.ThreatData{
				Name:     "Trojan",
				Type:     domain.ThreatTypeTrojan,
				Severity: domain.SeverityHigh,
			}

			switch tt.field {
			case "name":
				input.Name = tt.value
			case "description":
				input.Description = tt.value
			case "type":
				input.Type = domain.ThreatType(tt.value)
			case "severity":
				input.Severity = domain.Severity(tt.value)
			default:
				t.Fatalf("unknown test field %q", tt.field)
			}

			got, err := input.NormalizeAndValidate()

			validationErr, ok := errors.AsType[*domain.ValidationError](err)
			if !ok {
				t.Fatalf("error = %v, want *domain.ValidationError", err)
			}
			if validationErr.Field != tt.field {
				t.Errorf("field = %q, want %q", validationErr.Field, tt.field)
			}
			if got != (domain.ThreatData{}) {
				t.Errorf("result = %+v, want zero value on error", got)
			}
		})
	}
}

func TestThreatDataAllowedEnums(t *testing.T) {
	for _, kind := range []domain.ThreatType{
		"trojan", "ransomware", "spyware", "adware", "worm", "other",
	} {
		for _, severity := range []domain.Severity{
			"low", "medium", "high", "critical",
		} {
			input := domain.ThreatData{
				Name:     "Threat",
				Type:     kind,
				Severity: severity,
			}

			if _, err := input.NormalizeAndValidate(); err != nil {
				t.Errorf("type=%q severity=%q: %v", kind, severity, err)
			}
		}
	}
}
