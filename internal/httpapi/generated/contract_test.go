package generated_test

import (
	"testing"

	"github.com/kirill010106/kaspersky_trainee/internal/httpapi/generated"
)

func TestOpenAPIDocument(t *testing.T) {
	spec, err := generated.GetSpec()
	if err != nil {
		t.Fatalf("load embedded OpenAPI document: %v", err)
	}

	if err := spec.Validate(t.Context()); err != nil {
		t.Fatalf("validate OpenAPI document: %v", err)
	}
}
