//go:build integration

package integration_test

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kirill010106/kaspersky_trainee/internal/httpapi"
	"github.com/kirill010106/kaspersky_trainee/internal/httpapi/generated"
	"github.com/kirill010106/kaspersky_trainee/internal/service"
	storagepostgres "github.com/kirill010106/kaspersky_trainee/internal/storage/postgres"
)

func testHTTPSlice(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	defer pool.Close()

	repository := storagepostgres.New(pool)
	threatService := service.New(repository)

	const (
		readerKey = "reader-test-key"
		writerKey = "writer-test-key"
	)

	router, err := httpapi.NewRouter(threatService, readerKey, writerKey)
	if err != nil {
		t.Fatalf("create router: %v", err)
	}

	server := httptest.NewServer(router)
	defer server.Close()

	client := server.Client()

	request := func(method, path, key, body string) (int, http.Header, []byte) {
		t.Helper()

		req, err := http.NewRequestWithContext(
			ctx,
			method,
			server.URL+path,
			strings.NewReader(body),
		)
		if err != nil {
			t.Fatalf("create request: %v", err)
		}

		req.Header.Set("Authorization", "Bearer "+key)
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("perform request: %v", err)
		}
		defer resp.Body.Close()

		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}

		return resp.StatusCode, resp.Header, responseBody
	}

	const (
		inputMD5 = "ABCDEF0123456789ABCDEF0123456789"
		md5      = "abcdef0123456789abcdef0123456789"
	)

	body := `{
		"md5": "` + inputMD5 + `",
		"name": " Test threat ",
		"description": "Integration test",
		"type": "trojan",
		"severity": "high"
	}`

	status, headers, responseBody := request(
		http.MethodPost,
		"/api/v1/info",
		writerKey,
		body,
	)
	if status != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201; body = %s", status, responseBody)
	}

	wantLocation := "/api/v1/info/" + md5
	if location := headers.Get("Location"); location != wantLocation {
		t.Fatalf("Location = %q, want %q", location, wantLocation)
	}

	var created generated.ThreatResponse
	if err := json.Unmarshal(responseBody, &created); err != nil {
		t.Fatalf("decode POST response: %v", err)
	}

	if created.Md5 != md5 ||
		created.Name != "Test threat" ||
		created.Description != "Integration test" ||
		created.Type != generated.Trojan ||
		created.Severity != generated.High ||
		created.CreatedAt.IsZero() ||
		created.UpdatedAt.IsZero() {
		t.Fatalf("unexpected POST response: %+v", created)
	}

	status, _, responseBody = request(
		http.MethodGet,
		"/api/v1/info/"+inputMD5,
		readerKey,
		"",
	)
	if status != http.StatusOK {
		t.Fatalf("GET status = %d, want 200; body = %s", status, responseBody)
	}

	var fetched generated.ThreatResponse
	if err := json.Unmarshal(responseBody, &fetched); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}

	if fetched.Md5 != created.Md5 ||
		fetched.Name != created.Name ||
		fetched.Description != created.Description ||
		fetched.Type != created.Type ||
		fetched.Severity != created.Severity ||
		!fetched.CreatedAt.Equal(created.CreatedAt) ||
		!fetched.UpdatedAt.Equal(created.UpdatedAt) {
		t.Fatalf("GET response = %+v, want %+v", fetched, created)
	}

	status, _, responseBody = request(
		http.MethodPost,
		"/api/v1/info",
		writerKey,
		body,
	)
	if status != http.StatusConflict {
		t.Fatalf("duplicate POST status = %d, want 409; body = %s", status, responseBody)
	}

	const missingMD5 = "cccccccccccccccccccccccccccccccc"

	status, _, responseBody = request(
		http.MethodGet,
		"/api/v1/info/"+missingMD5,
		readerKey,
		"",
	)
	if status != http.StatusNotFound {
		t.Fatalf("missing GET status = %d, want 404; body = %s", status, responseBody)
	}
}
