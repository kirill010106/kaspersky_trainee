package httpapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/kirill010106/kaspersky_trainee/internal/httpapi/generated"
)

func recoverPanic(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)

			defer func() {
				value := recover()
				if value == nil {
					return
				}

				if err, ok := value.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(value)
				}

				requestID, _ := r.Context().Value(requestIDContextKey{}).(string)
				logger.ErrorContext(r.Context(), "http handler panic",
					"request_id", requestID,
					"panic_type", fmt.Sprintf("%T", value),
				)

				if ww.Status() != 0 {
					panic(http.ErrAbortHandler)
				}

				writeJSON(ww, http.StatusInternalServerError, generated.ErrorResponse{
					Message: "internal server error",
				})
			}()

			next.ServeHTTP(ww, r)
		})
	}
}
