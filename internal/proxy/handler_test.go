package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sismedika/otlp-proxy/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestProxyMissingTenantKey(t *testing.T) {
	// Create a dummy backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)

	handler, err := NewHandler(backend.URL, "test-ingest-key", st, 4194304)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1/traces", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestProxyInvalidTenantKey(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)

	handler, err := NewHandler(backend.URL, "test-ingest-key", st, 4194304)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1/traces", nil)
	req.Header.Set("X-Tenant-Key", "deadbeef")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestProxyValidTenantForward(t *testing.T) {
	var receivedAuth string
	var receivedPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "test-app", "")

	handler, err := NewHandler(backend.URL, "test-ingest-key", st, 4194304)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1/traces", nil)
	req.Header.Set("X-Tenant-Key", tenant.APIKey)
	req.Header.Set("Content-Length", "42")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if receivedAuth != "Bearer test-ingest-key" {
		t.Fatalf("expected auth header, got %q", receivedAuth)
	}
	if receivedPath != "/v1/traces" {
		t.Fatalf("expected path /v1/traces, got %q", receivedPath)
	}
}

func TestProxyUnknownPath(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)

	handler, err := NewHandler(backend.URL, "test-ingest-key", st, 4194304)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1/unknown", nil)
	req.Header.Set("X-Tenant-Key", "some-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestProxyValidForwardOptionalAuth(t *testing.T) {
	var receivedAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "no-auth-app", "")

	handler, err := NewHandler(backend.URL, "", st, 4194304)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1/traces", nil)
	req.Header.Set("X-Tenant-Key", tenant.APIKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if receivedAuth != "" {
		t.Fatalf("expected no auth header with empty key, got %q", receivedAuth)
	}
}

func TestNewHandlerInvalidURL(t *testing.T) {
	st := testStore(t)
	_, err := NewHandler("://invalid", "key", st, 4194304)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}

	parseErr, ok := err.(*url.Error)
	if !ok {
		t.Fatalf("expected *url.Error, got %T", err)
	}
	if parseErr.Op != "parse" {
		t.Fatalf("expected parse error, got %q", parseErr.Op)
	}
}

func TestMaxBodyExceeded(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "max-body-test", "")

	handler, err := NewHandler(backend.URL, "test-key", st, 100)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	// 101 bytes exceeds the 100 byte limit
	body := strings.Repeat("x", 101)
	req := httptest.NewRequest("POST", "/v1/traces", strings.NewReader(body))
	req.Header.Set("X-Tenant-Key", tenant.APIKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rec.Code)
	}
}

func TestMaxBodyUnder(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "max-body-ok", "")

	handler, err := NewHandler(backend.URL, "test-key", st, 100)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	// 100 bytes = exactly at limit
	body := strings.Repeat("x", 100)
	req := httptest.NewRequest("POST", "/v1/traces", strings.NewReader(body))
	req.Header.Set("X-Tenant-Key", tenant.APIKey)
	req.Header.Set("Content-Length", "100")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestProxyNearPathRejected(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	handler, err := NewHandler(backend.URL, "test-key", st, 4194304)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	for _, path := range []string{"/v1/tracesXYZ", "/v1/metrics/", "/v1/logsx"} {
		req := httptest.NewRequest("POST", path, nil)
		req.Header.Set("X-Tenant-Key", "ing_1_000000000000000000000000000000000000000000000000")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for %s, got %d", path, rec.Code)
		}
	}
}

func TestProxyStripsTenantKeyHeader(t *testing.T) {
	var forwardedHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedHeader = r.Header.Get("X-Tenant-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "strip-test", "")

	handler, err := NewHandler(backend.URL, "test-ingest-key", st, 4194304)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1/traces", nil)
	req.Header.Set("X-Tenant-Key", tenant.APIKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if forwardedHeader != "" {
		t.Fatalf("expected X-Tenant-Key to be stripped, got %q", forwardedHeader)
	}
}

func TestProxyHealthz(t *testing.T) {
	st := testStore(t)
	handler, err := NewHandler("http://localhost:1", "key", st, 4194304)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("expected ok status, got %q", rec.Body.String())
	}
}

func TestProxyHealthzDBDown(t *testing.T) {
	st := testStore(t)
	// Close the DB to simulate failure
	st.Close()

	handler, err := NewHandler("http://localhost:1", "key", st, 4194304)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}
