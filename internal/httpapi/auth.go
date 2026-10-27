package httpapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/kirill010106/kaspersky_trainee/internal/httpapi/generated"
)

type accessRole uint8

const (
	roleReader accessRole = iota + 1
	roleWriter
)

type roleContextKey struct{}

type authenticator struct {
	readerKey string
	writerKey string
}

func newAuthenticator(readerKey, writerKey string) (*authenticator, error) {
	if readerKey == "" || writerKey == "" {
		return nil, errors.New("reader and writer keys must not be empty")
	}

	if readerKey == writerKey {
		return nil, errors.New("reader and writer keys must be different")
	}

	return &authenticator{
		readerKey: readerKey,
		writerKey: writerKey,
	}, nil
}

func (a *authenticator) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeUnauthorized(w)
			return
		}

		token := parts[1]

		readerMatch := subtle.ConstantTimeCompare(
			[]byte(token),
			[]byte(a.readerKey),
		)
		writerMatch := subtle.ConstantTimeCompare(
			[]byte(token),
			[]byte(a.writerKey),
		)

		var role accessRole
		switch {
		case writerMatch == 1:
			role = roleWriter
		case readerMatch == 1:
			role = roleReader
		default:
			writeUnauthorized(w)
			return
		}

		ctx := context.WithValue(r.Context(), roleContextKey{}, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requireWriter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role, ok := r.Context().Value(roleContextKey{}).(accessRole)
		if !ok {
			writeUnauthorized(w)
			return
		}

		if role != roleWriter {
			writeJSON(w, http.StatusForbidden, generated.ErrorResponse{
				Message: "forbidden",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(w, http.StatusUnauthorized, generated.ErrorResponse{
		Message: "unauthorized",
	})
}
