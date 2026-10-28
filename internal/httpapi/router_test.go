package httpapi

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
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

func testRouterOptions() RouterOptions {
	return RouterOptions{
		ReaderKey:              "reader-test-key",
		WriterKey:              "writer-test-key",
		CheckReady:             func(context.Context) error { return nil },
		ReadinessTimeout:       time.Second,
		APIRatePerMinute:       120,
		ReadinessRatePerMinute: 120,
	}
}

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
		testRouterOptions(),
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
		testRouterOptions(),
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
		testRouterOptions(),
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

func TestRouterLiveness(t *testing.T) {
	router, err := NewRouter(
		service.New(&fakeRepository{}),
		testRouterOptions(),
	)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/livez", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if response.Body.Len() != 0 {
		t.Fatalf("expected empty body, got %q", response.Body.String())
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing X-Request-ID")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing Cache-Control: no-store")
	}
}

func TestRouterReadiness(t *testing.T) {
	checkErr := errors.New("private database failure")
	checks := 0
	options := testRouterOptions()
	options.CheckReady = func(ctx context.Context) error {
		checks++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("readiness check has no deadline")
		}
		return checkErr
	}

	router, err := NewRouter(service.New(&fakeRepository{}), options)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var failure generated.ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil {
		t.Fatalf("decode readiness error: %v", err)
	}
	if failure.Message != "service unavailable" ||
		strings.Contains(response.Body.String(), checkErr.Error()) {
		t.Fatalf("unsafe readiness error response: %q", response.Body.String())
	}

	checkErr = nil
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if response.Body.Len() != 0 {
		t.Fatalf("expected empty readiness body, got %q", response.Body.String())
	}
	if checks != 2 {
		t.Fatalf("readiness checks = %d, want 2", checks)
	}
}

func TestRouterRateLimits(t *testing.T) {
	options := testRouterOptions()
	options.APIRatePerMinute = 2
	options.ReadinessRatePerMinute = 1

	checks := 0
	options.CheckReady = func(context.Context) error {
		checks++
		return nil
	}

	router, err := NewRouter(service.New(&fakeRepository{}), options)
	if err != nil {
		t.Fatal(err)
	}

	send := func(method, path, remote, forwarded string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, nil)
		request.RemoteAddr = remote
		if forwarded != "" {
			request.Header.Set("X-Forwarded-For", forwarded)
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	assertLimited := func(response *httptest.ResponseRecorder) {
		t.Helper()
		if response.Code != http.StatusTooManyRequests {
			t.Fatalf("limited status = %d, want 429", response.Code)
		}
		if response.Header().Get("Retry-After") == "" {
			t.Fatal("429 has no Retry-After")
		}
		if response.Header().Get("Content-Type") != "application/json" {
			t.Fatal("429 has no application/json Content-Type")
		}
		var body generated.ErrorResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode 429 response: %v", err)
		}
		if body.Message != "too many requests" {
			t.Fatalf("429 message = %q", body.Message)
		}
	}

	const apiPath = "/api/v1/info/d41d8cd98f00b204e9800998ecf8427e"

	if got := send(http.MethodGet, apiPath, "192.0.2.1:10001", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("first API status = %d, want 401", got)
	}
	if got := send(http.MethodPost, "/api/v1/info", "192.0.2.1:10002", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("second API status = %d, want 401", got)
	}

	limitedAPI := send(http.MethodPut, apiPath, "192.0.2.1:10003", "203.0.113.99")
	assertLimited(limitedAPI)

	if got := send(http.MethodGet, "/readyz", "192.0.2.1:10004", "").Code; got != http.StatusOK {
		t.Fatalf("first readyz status = %d, want 200", got)
	}
	limitedReady := send(http.MethodGet, "/readyz", "192.0.2.1:10005", "")
	assertLimited(limitedReady)
	if checks != 1 {
		t.Fatalf("readiness checks = %d, want 1", checks)
	}

	for range 3 {
		if got := send(http.MethodGet, "/livez", "192.0.2.1:10006", "").Code; got != http.StatusOK {
			t.Fatalf("livez status = %d, want 200", got)
		}
	}
	if got := send(http.MethodGet, "/readyz", "192.0.2.2:10007", "").Code; got != http.StatusOK {
		t.Fatalf("other IP readyz status = %d, want 200", got)
	}

	if got := send(http.MethodGet, "/api/v1/unknown", "192.0.2.3:10001", "").Code; got != http.StatusNotFound {
		t.Fatalf("unknown API path status = %d, want 404", got)
	}
	if got := send(http.MethodDelete, apiPath, "192.0.2.3:10002", "").Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("wrong API method status = %d, want 405", got)
	}
	assertLimited(send(http.MethodGet, apiPath, "192.0.2.3:10003", ""))
}

func TestRouterInternalErrorDiagnostics(t *testing.T) {
	const privateDetail = "postgres://private-dsn-secret"

	tests := []struct {
		name      string
		cause     error
		wantClass string
	}{
		{"timeout", fmt.Errorf("%s: %w", privateDetail, context.DeadlineExceeded), "timeout"},
		{"other error", errors.New(privateDetail), "internal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			options := testRouterOptions()
			options.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
			repository := &fakeRepository{
				get: func(context.Context, string) (domain.Threat, error) {
					return domain.Threat{}, tt.cause
				},
			}
			router, err := NewRouter(service.New(repository), options)
			if err != nil {
				t.Fatal(err)
			}

			request := httptest.NewRequest(http.MethodGet,
				"/api/v1/info/d41d8cd98f00b204e9800998ecf8427e", nil)
			request.Header.Set("Authorization", "Bearer "+options.ReaderKey)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", response.Code)
			}
			requestID := response.Header().Get("X-Request-ID")
			if requestID == "" {
				t.Fatal("missing request ID")
			}
			if strings.Contains(response.Body.String(), privateDetail) || strings.Contains(logs.String(), privateDetail) {
				t.Fatal("private error detail leaked to response or logs")
			}

			found := false
			for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
				var event map[string]any
				if err := json.Unmarshal([]byte(line), &event); err != nil {
					t.Fatalf("decode log: %v", err)
				}
				if event["msg"] != "request failed" {
					continue
				}
				found = true
				if event["request_id"] != requestID || event["error_class"] != tt.wantClass {
					t.Fatalf("diagnostic event = %v", event)
				}
			}
			if !found {
				t.Fatal("missing diagnostic event")
			}
		})
	}
}

func TestRecoverPanic(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	router := chi.NewRouter()
	router.Use(responseHeaders, accessLog(logger), recoverPanic(logger))
	router.Get("/panic", func(http.ResponseWriter, *http.Request) {
		panic("private panic value")
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/panic", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", response.Code)
	}
	if !strings.Contains(response.Body.String(), `"message":"internal server error"`) {
		t.Fatalf("unexpected response: %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "private panic value") ||
		strings.Contains(logs.String(), "private panic value") {
		t.Fatal("panic value leaked")
	}

	requestID := response.Header().Get("X-Request-ID")
	if requestID == "" || !strings.Contains(logs.String(), requestID) {
		t.Fatal("request ID missing from response or logs")
	}
	if !strings.Contains(logs.String(), `"status":500`) {
		t.Fatalf("access log does not contain status 500: %s", logs.String())
	}
}

func TestRecoverPanicAfterHeaders(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	router := chi.NewRouter()
	router.Use(responseHeaders, accessLog(logger), recoverPanic(logger))
	router.Get("/panic-after-headers", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		panic("private panic value")
	})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/panic-after-headers", nil)

	func() {
		defer func() {
			if value := recover(); value != http.ErrAbortHandler {
				t.Fatalf("panic = %v, want http.ErrAbortHandler", value)
			}
		}()
		router.ServeHTTP(response, request)
	}()

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", response.Code)
	}
	if response.Body.Len() != 0 {
		t.Fatalf("unexpected response body: %s", response.Body.String())
	}
	if strings.Contains(logs.String(), "private panic value") {
		t.Fatal("panic value leaked into logs")
	}
	if !strings.Contains(logs.String(), `"status":202`) ||
		!strings.Contains(logs.String(), `"completed":false`) {
		t.Fatalf("aborted request missing from access log: %s", logs.String())
	}
}
