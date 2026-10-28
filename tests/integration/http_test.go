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
	"time"

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

	repository, err := storagepostgres.New(pool, 3*time.Second)
	if err != nil {
		t.Fatalf("create repository: %v", err)
	}
	threatService := service.New(repository)

	const (
		readerKey = "reader-test-key"
		writerKey = "writer-test-key"
	)

	router, err := httpapi.NewRouter(threatService, httpapi.RouterOptions{
		ReaderKey:              readerKey,
		WriterKey:              writerKey,
		CheckReady:             repository.CheckReady,
		ReadinessTimeout:       time.Second,
		APIRatePerMinute:       120,
		ReadinessRatePerMinute: 120,
	})
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

		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		if method == http.MethodPost || method == http.MethodPut {
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

	readyStatus, _, readyBody := request(http.MethodGet, "/readyz", "", "")
	if readyStatus != http.StatusOK || len(readyBody) != 0 {
		t.Fatalf("readyz status = %d, body = %q; want 200 and empty body", readyStatus, readyBody)
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
	replacement := `{
		"name": " Updated threat ",
		"type": "worm",
		"severity": "critical"
	}`

	status, _, responseBody = request(
		http.MethodPut,
		"/api/v1/info/"+inputMD5,
		readerKey,
		replacement,
	)
	if status != http.StatusForbidden {
		t.Fatalf("reader PUT status = %d, want 403; body = %s", status, responseBody)
	}

	status, _, responseBody = request(
		http.MethodPut,
		"/api/v1/info/"+inputMD5,
		writerKey,
		replacement,
	)
	if status != http.StatusOK {
		t.Fatalf("writer PUT status = %d, want 200; body = %s", status, responseBody)
	}

	var updated generated.ThreatResponse
	if err := json.Unmarshal(responseBody, &updated); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}

	if updated.Md5 != md5 ||
		updated.Name != "Updated threat" ||
		updated.Description != "" ||
		updated.Type != generated.Worm ||
		updated.Severity != generated.Critical ||
		!updated.CreatedAt.Equal(created.CreatedAt) ||
		updated.UpdatedAt.IsZero() {
		t.Fatalf("unexpected PUT response: %+v", updated)
	}

	status, _, responseBody = request(
		http.MethodGet,
		"/api/v1/info/"+md5,
		readerKey,
		"",
	)
	if status != http.StatusOK {
		t.Fatalf("GET after PUT status = %d, want 200; body = %s", status, responseBody)
	}

	var afterUpdate generated.ThreatResponse
	if err := json.Unmarshal(responseBody, &afterUpdate); err != nil {
		t.Fatalf("decode GET after PUT: %v", err)
	}

	if afterUpdate.Md5 != updated.Md5 ||
		afterUpdate.Name != updated.Name ||
		afterUpdate.Description != updated.Description ||
		afterUpdate.Type != updated.Type ||
		afterUpdate.Severity != updated.Severity ||
		!afterUpdate.CreatedAt.Equal(updated.CreatedAt) ||
		!afterUpdate.UpdatedAt.Equal(updated.UpdatedAt) {
		t.Fatalf("GET after PUT = %+v, want %+v", afterUpdate, updated)
	}

	status, _, responseBody = request(
		http.MethodPut,
		"/api/v1/info/"+missingMD5,
		writerKey,
		replacement,
	)
	if status != http.StatusNotFound {
		t.Fatalf("missing PUT status = %d, want 404; body = %s", status, responseBody)
	}

	bodyWithMD5 := `{
		"md5": "` + md5 + `",
		"name": "Another threat",
		"type": "trojan",
		"severity": "low"
	}`

	status, _, responseBody = request(
		http.MethodPut,
		"/api/v1/info/"+md5,
		writerKey,
		bodyWithMD5,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("PUT with MD5 in body status = %d, want 400; body = %s", status, responseBody)
	}

	t.Run("concurrent POST same MD5", func(t *testing.T) {
		md5 := strings.Repeat("e", 32)
		body := `{"md5":"` + md5 + `","name":"Concurrent threat","type":"trojan","severity":"high"}`

		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		ready := make(chan struct{}, 2)
		start := make(chan struct{})
		results := make(chan int, 2)

		for range 2 {
			go func() {
				req := httptest.NewRequest(
					http.MethodPost,
					"/api/v1/info",
					strings.NewReader(body),
				).WithContext(requestCtx)
				req.Header.Set("Authorization", "Bearer "+writerKey)
				req.Header.Set("Content-Type", "application/json")

				response := httptest.NewRecorder()
				ready <- struct{}{}
				<-start

				router.ServeHTTP(response, req)
				results <- response.Code
			}()
		}

		<-ready
		<-ready
		close(start)

		statuses := make([]int, 0, 2)
		for range 2 {
			select {
			case status := <-results:
				statuses = append(statuses, status)
			case <-requestCtx.Done():
				t.Fatalf("concurrent POST timed out: %v", requestCtx.Err())
			}
		}

		if !((statuses[0] == http.StatusCreated && statuses[1] == http.StatusConflict) ||
			(statuses[0] == http.StatusConflict && statuses[1] == http.StatusCreated)) {
			t.Fatalf("statuses = %v, want one 201 and one 409", statuses)
		}

		var count int
		if err := pool.QueryRow(ctx,
			"SELECT count(*) FROM threats WHERE md5 = $1", md5,
		).Scan(&count); err != nil {
			t.Fatalf("count stored threats: %v", err)
		}
		if count != 1 {
			t.Fatalf("stored threats = %d, want 1", count)
		}

		pool.Close()

		status, _, responseBody = request(http.MethodGet, "/readyz", "", "")
		if status != http.StatusServiceUnavailable {
			t.Fatalf("readyz with closed pool: status = %d, want 503; body = %s",
				status, responseBody)
		}
		if strings.Contains(string(responseBody), "closed pool") {
			t.Fatalf("readyz exposed storage error: %s", responseBody)
		}

		status, _, responseBody = request(
			http.MethodGet,
			"/api/v1/info/"+md5,
			readerKey,
			"",
		)
		if status != http.StatusInternalServerError {
			t.Fatalf("GET with closed pool: status = %d, want 500; body = %s",
				status, responseBody)
		}
		if strings.Contains(string(responseBody), "closed pool") {
			t.Fatalf("GET exposed storage error: %s", responseBody)
		}
	})
}
