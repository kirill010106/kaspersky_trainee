package httpapi

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kirill010106/kaspersky_trainee/internal/domain"
	"github.com/kirill010106/kaspersky_trainee/internal/httpapi/generated"
	"github.com/kirill010106/kaspersky_trainee/internal/service"
)

type fakeRepository struct {
	get    func(context.Context, string) (domain.Threat, error)
	create func(context.Context, string, domain.ThreatData) (domain.Threat, error)
}

func (r *fakeRepository) Get(ctx context.Context, md5 string) (domain.Threat, error) {
	if r.get == nil {
		return domain.Threat{}, errors.New("unexpected Get call")
	}
	return r.get(ctx, md5)
}

func (r *fakeRepository) Create(
	ctx context.Context,
	md5 string,
	data domain.ThreatData,
) (domain.Threat, error) {
	if r.create == nil {
		return domain.Threat{}, errors.New("unexpected Create call")
	}
	return r.create(ctx, md5, data)
}

func (r *fakeRepository) Replace(
	context.Context,
	string,
	domain.ThreatData,
) (domain.Threat, error) {
	return domain.Threat{}, errors.New("unexpected Replace call")
}

func TestGetThreat(t *testing.T) {
	const (
		lowercaseMD5 = "d41d8cd98f00b204e9800998ecf8427e"
		uppercaseMD5 = "D41D8CD98F00B204E9800998ECF8427E"
	)

	createdAt := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		md5        string
		get        func(context.Context, string) (domain.Threat, error)
		wantStatus int
	}{
		{
			name: "existing threat with uppercase MD5",
			md5:  uppercaseMD5,
			get: func(ctx context.Context, md5 string) (domain.Threat, error) {
				if md5 != lowercaseMD5 {
					t.Errorf("repository received MD5 %q, want %q", md5, lowercaseMD5)
				}

				if _, ok := ctx.Deadline(); !ok {
					t.Error("repository context has no deadline")
				}

				return domain.Threat{
					MD5:         md5,
					Name:        "Test threat",
					Description: "Description",
					Type:        domain.ThreatTypeTrojan,
					Severity:    domain.SeverityHigh,
					CreatedAt:   createdAt,
					UpdatedAt:   createdAt,
				}, nil
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "missing threat",
			md5:  lowercaseMD5,
			get: func(context.Context, string) (domain.Threat, error) {
				return domain.Threat{}, service.ErrNotFound
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "invalid MD5",
			md5:  "invalid",
			get: func(context.Context, string) (domain.Threat, error) {
				t.Error("repository must not be called for invalid MD5")
				return domain.Threat{}, nil
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "storage failure",
			md5:  lowercaseMD5,
			get: func(context.Context, string) (domain.Threat, error) {
				return domain.Threat{}, errors.New("internal database error")
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := &fakeRepository{get: tt.get}
			handler := &handlers{service: service.New(repository)}

			router := chi.NewRouter()
			router.Get("/api/v1/info/{md5}", handler.getThreat)

			request := httptest.NewRequest(
				http.MethodGet,
				"/api/v1/info/"+tt.md5,
				nil,
			)
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

			if got := response.Header().Get("Content-Type"); got != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json", got)
			}

			if tt.wantStatus == http.StatusOK {
				var body generated.ThreatResponse
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatalf("decode response: %v", err)
				}

				if body.Md5 != lowercaseMD5 ||
					body.Name != "Test threat" ||
					!body.CreatedAt.Equal(createdAt) {
					t.Fatalf("unexpected response: %+v", body)
				}
			} else {
				var body generated.ErrorResponse
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatalf("decode error response: %v", err)
				}

				if body.Message == "" {
					t.Fatal("error response has an empty message")
				}

				if body.Message == "internal database error" {
					t.Fatal("response exposed an internal error")
				}
			}
		})
	}
}

func TestCreateThreat(t *testing.T) {
	const (
		lowercaseMD5 = "d41d8cd98f00b204e9800998ecf8427e"
		uppercaseMD5 = "D41D8CD98F00B204E9800998ECF8427E"
	)

	createdAt := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

	repository := &fakeRepository{
		create: func(
			ctx context.Context,
			md5 string,
			data domain.ThreatData,
		) (domain.Threat, error) {
			if md5 != lowercaseMD5 {
				t.Errorf("repository received MD5 %q, want %q", md5, lowercaseMD5)
			}

			if data.Name != "Test threat" ||
				data.Description != "" ||
				data.Type != domain.ThreatTypeTrojan ||
				data.Severity != domain.SeverityHigh {
				t.Errorf("repository received unexpected data: %+v", data)
			}

			if _, ok := ctx.Deadline(); !ok {
				t.Error("repository context has no deadline")
			}

			return domain.Threat{
				MD5:         md5,
				Name:        data.Name,
				Description: data.Description,
				Type:        data.Type,
				Severity:    data.Severity,
				CreatedAt:   createdAt,
				UpdatedAt:   createdAt,
			}, nil
		},
	}

	handler := &handlers{service: service.New(repository)}
	router := chi.NewRouter()
	router.Post("/api/v1/info", handler.createThreat)

	body := `{
		"md5": "` + uppercaseMD5 + `",
		"name": " Test threat ",
		"type": "trojan",
		"severity": "high"
	}`

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/info",
		strings.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf(
			"status = %d, want %d; body = %s",
			response.Code,
			http.StatusCreated,
			response.Body.String(),
		)
	}

	wantLocation := "/api/v1/info/" + lowercaseMD5
	if got := response.Header().Get("Location"); got != wantLocation {
		t.Fatalf("Location = %q, want %q", got, wantLocation)
	}

	var result generated.ThreatResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if result.Md5 != lowercaseMD5 ||
		result.Name != "Test threat" ||
		result.Description != "" ||
		!result.CreatedAt.Equal(createdAt) {
		t.Fatalf("unexpected response: %+v", result)
	}
}
