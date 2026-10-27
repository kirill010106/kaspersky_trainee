package httpapi

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-chi/chi/v5"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"

	"github.com/kirill010106/kaspersky_trainee/internal/httpapi/generated"
	"github.com/kirill010106/kaspersky_trainee/internal/service"
)

// NewRouter creates the HTTP router for the threat service.
func NewRouter(
	threatService *service.Service,
	readerKey string,
	writerKey string,
) (http.Handler, error) {
	if threatService == nil {
		return nil, errors.New("threat service must not be nil")
	}

	auth, err := newAuthenticator(readerKey, writerKey)
	if err != nil {
		return nil, fmt.Errorf("configure authentication: %w", err)
	}

	spec, err := generated.GetSpec()
	if err != nil {
		return nil, fmt.Errorf("load OpenAPI specification: %w", err)
	}

	validate := nethttpmiddleware.OapiRequestValidatorWithOptions(
		spec,
		&nethttpmiddleware.Options{
			Options: openapi3filter.Options{
				SkipSettingDefaults: true,
				AuthenticationFunc: func(
					ctx context.Context,
					_ *openapi3filter.AuthenticationInput,
				) error {
					role, ok := ctx.Value(roleContextKey{}).(accessRole)
					if !ok || (role != roleReader && role != roleWriter) {
						return errors.New("authenticated role is missing")
					}

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

				writeJSON(w, status, generated.ErrorResponse{
					Message: "invalid request",
				})
			},
		},
	)

	handler := &handlers{service: threatService}

	router := chi.NewRouter()

	router.With(
		auth.authenticate,
		validate,
	).Get("/api/v1/info/{md5}", handler.getThreat)

	router.With(
		auth.authenticate,
		requireWriter,
		limitRequestBody,
		requireJSON,
		validate,
	).Post("/api/v1/info", handler.createThreat)

	return router, nil
}

func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		next.ServeHTTP(w, r)
	})
}

func requireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentEncoding := r.Header.Get("Content-Encoding")
		if contentEncoding != "" && !strings.EqualFold(contentEncoding, "identity") {
			writeJSON(w, http.StatusUnsupportedMediaType, generated.ErrorResponse{
				Message: "unsupported content encoding",
			})
			return
		}

		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			writeJSON(w, http.StatusUnsupportedMediaType, generated.ErrorResponse{
				Message: "unsupported content type",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
