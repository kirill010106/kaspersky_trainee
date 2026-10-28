package httpapi

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

func accessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			completed := false

			defer func() {
				status := ww.Status()
				if status == 0 {
					status = http.StatusOK
				}

				route := ""
				if routeContext := chi.RouteContext(r.Context()); routeContext != nil {
					route = routeContext.RoutePattern()
				}

				requestID, _ := r.Context().Value(requestIDContextKey{}).(string)
				logger.InfoContext(r.Context(), "http request",
					"request_id", requestID,
					"method", r.Method,
					"route", route,
					"status", status,
					"duration_ms", time.Since(start).Milliseconds(),
					"completed", completed,
				)
			}()

			next.ServeHTTP(ww, r)
			completed = true
		})
	}
}
