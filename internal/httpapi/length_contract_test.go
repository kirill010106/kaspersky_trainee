package httpapi_test

import (
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/kirill010106/kaspersky_trainee/internal/domain"
)

func TestOpenAPIAndDomainLengthRules(t *testing.T) {
	loader := openapi3.NewLoader()

	spec, err := loader.LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI document: %v", err)
	}
	if err := spec.Validate(t.Context()); err != nil {
		t.Fatalf("validate OpenAPI document: %v", err)
	}

	descriptionTests := []struct {
		name      string
		length    int
		wantValid bool
	}{
		{"at limit", 4096, true},
		{"over limit", 4097, false},
	}

	for _, tt := range descriptionTests {
		t.Run("description/"+tt.name, func(t *testing.T) {
			description := strings.Repeat("в", tt.length)

			data := domain.ThreatData{
				Name:        "Threat",
				Description: description,
				Type:        domain.ThreatTypeTrojan,
				Severity:    domain.SeverityHigh,
			}

			_, domainErr := data.NormalizeAndValidate()
			if gotValid := domainErr == nil; gotValid != tt.wantValid {
				t.Errorf("domain valid = %v, want %v", gotValid, tt.wantValid)
			}

			for _, model := range []string{
				"ThreatCreateRequest",
				"ThreatUpdateRequest",
				"ThreatResponse",
			} {
				schema := fieldSchema(t, spec, model, "description")
				err := schema.VisitJSON(description)

				if gotValid := err == nil; gotValid != tt.wantValid {
					t.Errorf("%s description valid = %v, want %v",
						model, gotValid, tt.wantValid)
				}
			}
		})
	}

	nameTests := []struct {
		name         string
		value        string
		wantSchemaOK bool
		wantDomainOK bool
	}{
		{
			name:         "empty",
			value:        "",
			wantSchemaOK: false,
			wantDomainOK: false,
		},
		{
			name:         "whitespace only",
			value:        "   ",
			wantSchemaOK: true,
			wantDomainOK: false,
		},
		{
			name:         "over limit after trim",
			value:        strings.Repeat("я", 201),
			wantSchemaOK: true,
			wantDomainOK: false,
		},
		{
			name:         "at limit after trim",
			value:        strings.Repeat(" ", 220) + strings.Repeat("я", 200),
			wantSchemaOK: true,
			wantDomainOK: true,
		},
	}

	for _, tt := range nameTests {
		t.Run("name/"+tt.name, func(t *testing.T) {
			data := domain.ThreatData{
				Name:     tt.value,
				Type:     domain.ThreatTypeTrojan,
				Severity: domain.SeverityHigh,
			}

			_, domainErr := data.NormalizeAndValidate()
			if gotValid := domainErr == nil; gotValid != tt.wantDomainOK {
				t.Errorf("domain valid = %v, want %v", gotValid, tt.wantDomainOK)
			}

			for _, model := range []string{
				"ThreatCreateRequest",
				"ThreatUpdateRequest",
			} {
				schema := fieldSchema(t, spec, model, "name")
				err := schema.VisitJSON(tt.value)

				if gotValid := err == nil; gotValid != tt.wantSchemaOK {
					t.Errorf("%s name valid = %v, want %v",
						model, gotValid, tt.wantSchemaOK)
				}
			}
		})
	}

	responseName := fieldSchema(t, spec, "ThreatResponse", "name")

	for _, tt := range []struct {
		length    int
		wantValid bool
	}{
		{200, true},
		{201, false},
	} {
		err := responseName.VisitJSON(strings.Repeat("я", tt.length))
		if gotValid := err == nil; gotValid != tt.wantValid {
			t.Errorf("response name length %d: valid = %v, want %v",
				tt.length, gotValid, tt.wantValid)
		}
	}
}

func fieldSchema(
	t *testing.T,
	spec *openapi3.T,
	model string,
	field string,
) *openapi3.Schema {
	t.Helper()

	if spec.Components == nil {
		t.Fatal("OpenAPI components are missing")
	}

	modelRef := spec.Components.Schemas[model]
	if modelRef == nil || modelRef.Value == nil {
		t.Fatalf("OpenAPI schema %q is missing", model)
	}

	fieldRef := modelRef.Value.Properties[field]
	if fieldRef == nil || fieldRef.Value == nil {
		t.Fatalf("field %q is missing from OpenAPI schema %q", field, model)
	}

	return fieldRef.Value
}
