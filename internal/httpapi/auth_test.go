package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticateAndRequireWriter(t *testing.T) {
	auth, err := newAuthenticator("reader-test-key", "writer-test-key")
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	tests := []struct {
		name          string
		authorization string
		write         bool
		wantStatus    int
	}{
		{
			name:       "missing key",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:          "invalid key",
			authorization: "Bearer invalid",
			wantStatus:    http.StatusUnauthorized,
		},
		{
			name:          "reader can read",
			authorization: "Bearer reader-test-key",
			wantStatus:    http.StatusNoContent,
		},
		{
			name:          "writer can read",
			authorization: "Bearer writer-test-key",
			wantStatus:    http.StatusNoContent,
		},
		{
			name:          "reader cannot write",
			authorization: "Bearer reader-test-key",
			write:         true,
			wantStatus:    http.StatusForbidden,
		},
		{
			name:          "writer can write",
			authorization: "Bearer writer-test-key",
			write:         true,
			wantStatus:    http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var handler http.Handler = okHandler
			if tt.write {
				handler = requireWriter(handler)
			}
			handler = auth.authenticate(handler)

			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.authorization != "" {
				request.Header.Set("Authorization", tt.authorization)
			}

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf(
					"status = %d, want %d; body = %s",
					response.Code,
					tt.wantStatus,
					response.Body.String(),
				)
			}

			if tt.wantStatus == http.StatusUnauthorized &&
				response.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Error("expected Bearer authentication challenge")
			}
		})
	}
}

func TestNewAuthenticatorRejectsInvalidKeys(t *testing.T) {
	tests := []struct {
		name   string
		reader string
		writer string
	}{
		{name: "empty reader", writer: "writer"},
		{name: "empty writer", reader: "reader"},
		{name: "same keys", reader: "same", writer: "same"},
		{name: "space in reader", reader: "reader key", writer: "writer"},
		{name: "Unicode space in writer", reader: "reader", writer: "writer\u00a0key"},
		{name: "control in reader", reader: "reader\x00key", writer: "writer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newAuthenticator(tt.reader, tt.writer)
			if err == nil {
				t.Fatal("expected an error for invalid keys")
			}
		})
	}
}
