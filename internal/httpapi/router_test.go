package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kirill010106/kaspersky_trainee/internal/domain"
	"github.com/kirill010106/kaspersky_trainee/internal/service"
)

func TestRouterCreateThreat(t *testing.T) {
	const md5 = "d41d8cd98f00b204e9800998ecf8427e"

	calls := 0
	repository := &fakeRepository{
		create: func(
			_ context.Context,
			gotMD5 string,
			data domain.ThreatData,
		) (domain.Threat, error) {
			calls++

			now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
			return domain.Threat{
				MD5:         gotMD5,
				Name:        data.Name,
				Description: data.Description,
				Type:        data.Type,
				Severity:    data.Severity,
				CreatedAt:   now,
				UpdatedAt:   now,
			}, nil
		},
	}

	router, err := NewRouter(
		service.New(repository),
		"reader-test-key",
		"writer-test-key",
	)
	if err != nil {
		t.Fatalf("create router: %v", err)
	}

	validBody := `{"md5":"` + md5 + `","name":"Threat","type":"trojan","severity":"high"}`
	nullDescription := `{"md5":"` + md5 + `","name":"Threat","type":"trojan","severity":"high","description":null}`

	tests := []struct {
		name        string
		token       string
		contentType string
		body        string
		wantStatus  int
		wantCalls   int
	}{
		{
			name:        "missing key",
			contentType: "application/json",
			body:        validBody,
			wantStatus:  http.StatusUnauthorized,
		},
		{
			name:        "reader cannot create",
			token:       "reader-test-key",
			contentType: "application/json",
			body:        validBody,
			wantStatus:  http.StatusForbidden,
		},
		{
			name:        "writer creates threat",
			token:       "writer-test-key",
			contentType: "application/json",
			body:        validBody,
			wantStatus:  http.StatusCreated,
			wantCalls:   1,
		},
		{
			name:        "null description rejected by contract",
			token:       "writer-test-key",
			contentType: "application/json",
			body:        nullDescription,
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "unsupported content type",
			token:       "writer-test-key",
			contentType: "text/plain",
			body:        validBody,
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "body exceeds limit",
			token:       "writer-test-key",
			contentType: "application/json",
			body:        validBody + strings.Repeat(" ", maxRequestBody),
			wantStatus:  http.StatusRequestEntityTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls = 0

			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/info",
				strings.NewReader(tt.body),
			)
			request.Header.Set("Content-Type", tt.contentType)
			if tt.token != "" {
				request.Header.Set("Authorization", "Bearer "+tt.token)
			}

			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf(
					"status = %d, want %d; body = %s",
					response.Code,
					tt.wantStatus,
					response.Body.String(),
				)
			}

			if calls != tt.wantCalls {
				t.Fatalf("repository calls = %d, want %d", calls, tt.wantCalls)
			}
		})
	}
}
