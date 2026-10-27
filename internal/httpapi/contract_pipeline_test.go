package httpapi_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-chi/chi/v5"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"

	"github.com/kirill010106/kaspersky_trainee/internal/httpapi/generated"
)

func TestRequestContractPipeline(t *testing.T) {
	spec, err := generated.GetSpec()
	if err != nil {
		t.Fatalf("load OpenAPI document: %v", err)
	}

	const bodyLimit = 32 * 1024

	limitBody := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)
			next.ServeHTTP(w, r)
		})
	}

	validate := nethttpmiddleware.OapiRequestValidatorWithOptions(
		spec,
		&nethttpmiddleware.Options{
			Options: openapi3filter.Options{
				SkipSettingDefaults: true,
				// Authentication is outside this compatibility test.
				AuthenticationFunc: func(
					context.Context,
					*openapi3filter.AuthenticationInput,
				) error {
					return nil
				},
			},
			ErrorHandlerWithOpts: func(
				_ context.Context,
				validationErr error,
				w http.ResponseWriter,
				_ *http.Request,
				opts nethttpmiddleware.ErrorHandlerOpts,
			) {
				status := opts.StatusCode
				if _, ok := errors.AsType[*http.MaxBytesError](validationErr); ok {
					status = http.StatusRequestEntityTooLarge
				}
				http.Error(w, "invalid request", status)
			},
		},
	)

	const fields = `"name":"Trojan","type":"trojan","severity":"high"`
	const valid = `{` + fields + `}`

	atLimit := valid + strings.Repeat(" ", bodyLimit-len(valid))

	tests := []struct {
		name          string
		body          string
		wantStatus    int
		unknownLength bool
	}{
		{
			name:       "valid request",
			body:       valid,
			wantStatus: http.StatusOK,
		},
		{
			name:       "empty description",
			body:       `{` + fields + `,"description":""}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing required fields",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "null object",
			body:       `null`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "null description",
			body:       `{` + fields + `,"description":null}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid enum",
			body:       `{"name":"Trojan","type":"unknown","severity":"high"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unknown field",
			body:       `{` + fields + `,"extra":true}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "duplicate field",
			body:       `{` + fields + `,"name":"Other"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid utf8",
			body:       "{\"name\":\"\xff\",\"type\":\"trojan\",\"severity\":\"high\"}",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "second json value",
			body:       valid + ` {}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "exact body limit",
			body:       atLimit,
			wantStatus: http.StatusOK,
		},
		{
			name:          "body limit without content length",
			body:          atLimit + " ",
			wantStatus:    http.StatusRequestEntityTooLarge,
			unknownLength: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := chi.NewRouter()

			router.With(limitBody, validate).Put(
				"/api/v1/info/{md5}",
				func(w http.ResponseWriter, r *http.Request) {
					data, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, "cannot read body", http.StatusBadRequest)
						return
					}

					if string(data) != tt.body {
						t.Error("validator changed the original request body")
					}

					var request generated.ThreatUpdateRequest
					if err := json.Unmarshal(
						data,
						&request,
						json.RejectUnknownMembers(true),
					); err != nil {
						http.Error(w, "invalid JSON", http.StatusBadRequest)
						return
					}

					w.WriteHeader(http.StatusOK)
				},
			)

			request := httptest.NewRequest(
				http.MethodPut,
				"/api/v1/info/d41d8cd98f00b204e9800998ecf8427e",
				strings.NewReader(tt.body),
			)
			request.Header.Set("Content-Type", "application/json")
			if tt.unknownLength {
				request.ContentLength = -1
			}

			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body = %q",
					response.Code, tt.wantStatus, response.Body.String())
			}
		})
	}
}
