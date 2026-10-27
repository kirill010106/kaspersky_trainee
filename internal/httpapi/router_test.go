package httpapi

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kirill010106/kaspersky_trainee/internal/domain"
	"github.com/kirill010106/kaspersky_trainee/internal/httpapi/generated"
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

func TestRouterResponseHeaders(t *testing.T) {
	router, err := NewRouter(
		service.New(&fakeRepository{}),
		"reader-test-key",
		"writer-test-key",
	)
	if err != nil {
		t.Fatalf("create router: %v", err)
	}

	for _, tt := range []struct {
		name       string
		path       string
		wantStatus int
	}{
		{"unauthorized", "/api/v1/info/d41d8cd98f00b204e9800998ecf8427e", http.StatusUnauthorized},
		{"unknown path", "/missing", http.StatusNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, tt.path, nil)
			request.Header.Set("X-Request-ID", "client-supplied")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}
			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
			if got := response.Header().Get("X-Request-ID"); got == "" || got == "client-supplied" {
				t.Errorf("server request ID = %q", got)
			}
		})
	}
}

func TestRouterNotFoundAndMethodNotAllowed(t *testing.T) {
	router, err := NewRouter(
		service.New(&fakeRepository{}),
		"reader-test-key",
		"writer-test-key",
	)
	if err != nil {
		t.Fatalf("create router: %v", err)
	}

	const md5 = "d41d8cd98f00b204e9800998ecf8427e"
	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantAllow  string
	}{
		{"unknown path", http.MethodGet, "/missing", http.StatusNotFound, ""},
		{"collection method", http.MethodGet, "/api/v1/info", http.StatusMethodNotAllowed, "POST"},
		{"item method", http.MethodPost, "/api/v1/info/" + md5, http.StatusMethodNotAllowed, "GET, PUT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(tt.method, tt.path, nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s",
					response.Code, tt.wantStatus, response.Body.String())
			}
			if got := response.Header().Get("Allow"); got != tt.wantAllow {
				t.Errorf("Allow = %q, want %q", got, tt.wantAllow)
			}
			if got := response.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}

			var body generated.ErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if body.Message == "" {
				t.Error("error message is empty")
			}
		})
	}
}
