package httpapi

import (
	"context"
	"crypto/rand"
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

type requestIDContextKey struct{}

func responseHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := rand.Text()
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("Cache-Control", "no-store")

		ctx := context.WithValue(r.Context(), requestIDContextKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

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

	router.Use(responseHeaders)

	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, generated.ErrorResponse{
			Message: "not found",
		})
	})

	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.RawPath
		if path == "" {
			path = r.URL.Path
		}

		var allowed []string
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut} {
			if router.Match(chi.NewRouteContext(), method, path) {
				allowed = append(allowed, method)
			}
		}

		if len(allowed) == 0 {
			writeJSON(w, http.StatusNotFound, generated.ErrorResponse{
				Message: "not found",
			})
			return
		}

		w.Header().Set("Allow", strings.Join(allowed, ", "))
		writeJSON(w, http.StatusMethodNotAllowed, generated.ErrorResponse{
			Message: "method not allowed",
		})
	})

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

	router.With(
		auth.authenticate,
		requireWriter,
		limitRequestBody,
		requireJSON,
		validate,
	).Put("/api/v1/info/{md5}", handler.updateThreat)

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
