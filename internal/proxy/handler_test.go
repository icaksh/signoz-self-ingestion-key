package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	tracecollector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/sismedika/otlp-proxy/internal/ratelimit"
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

func jsonTraceBody() string { return `{"resourceSpans":[]}` }

func TestProxyMissingTenantKey(t *testing.T) {
	// Create a dummy backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)

	handler, err := NewHandler(backend.URL, "test-ingest-key", st, 4194304, ratelimit.NewLimiter(st))
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

	handler, err := NewHandler(backend.URL, "test-ingest-key", st, 4194304, ratelimit.NewLimiter(st))
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
	tenant, _ := st.CreateTenant(t.Context(), "test-app", "", nil)

	handler, err := NewHandler(backend.URL, "test-ingest-key", st, 4194304, ratelimit.NewLimiter(st))
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

	st.FlushCounters()
	requests, _, _, err := st.CounterTotals(t.Context(), tenant.ID)
	if err != nil {
		t.Fatalf("counter totals: %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected 1 request recorded, got %d", requests)
	}
}

func TestProxyUnknownPath(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)

	handler, err := NewHandler(backend.URL, "test-ingest-key", st, 4194304, ratelimit.NewLimiter(st))
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
	tenant, _ := st.CreateTenant(t.Context(), "no-auth-app", "", nil)

	handler, err := NewHandler(backend.URL, "", st, 4194304, ratelimit.NewLimiter(st))
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

	st.FlushCounters()
	requests, _, _, err := st.CounterTotals(t.Context(), tenant.ID)
	if err != nil {
		t.Fatalf("counter totals: %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected 1 request recorded, got %d", requests)
	}
}

func TestNewHandlerInvalidURL(t *testing.T) {
	st := testStore(t)
	_, err := NewHandler("://invalid", "key", st, 4194304, ratelimit.NewLimiter(st))
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
	tenant, _ := st.CreateTenant(t.Context(), "max-body-test", "", nil)

	handler, err := NewHandler(backend.URL, "test-key", st, 100, ratelimit.NewLimiter(st))
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
	tenant, _ := st.CreateTenant(t.Context(), "max-body-ok", "", nil)

	handler, err := NewHandler(backend.URL, "test-key", st, 100, ratelimit.NewLimiter(st))
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
	handler, err := NewHandler(backend.URL, "test-key", st, 4194304, ratelimit.NewLimiter(st))
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
	tenant, _ := st.CreateTenant(t.Context(), "strip-test", "", nil)

	handler, err := NewHandler(backend.URL, "test-ingest-key", st, 4194304, ratelimit.NewLimiter(st))
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
	handler, err := NewHandler("http://localhost:1", "key", st, 4194304, ratelimit.NewLimiter(st))
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

	handler, err := NewHandler("http://localhost:1", "key", st, 4194304, ratelimit.NewLimiter(st))
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

func TestProxyUpstream503(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "upstream-503", "", nil)

	handler, err := NewHandler(backend.URL, "test-key", st, 4194304, ratelimit.NewLimiter(st))
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1/traces", strings.NewReader(jsonTraceBody()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Key", tenant.APIKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}

	st.FlushCounters()
	requests, _, errors, err := st.CounterTotals(t.Context(), tenant.ID)
	if err != nil {
		t.Fatalf("counter totals: %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected 1 request recorded, got %d", requests)
	}
	if errors != 1 {
		t.Fatalf("expected 1 error recorded, got %d", errors)
	}
}

func TestProxyChunkedBodyCounting(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "chunked-test", "", nil)

	handler, err := NewHandler(backend.URL, "test-key", st, 4194304, ratelimit.NewLimiter(st))
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	bodyContent := jsonTraceBody()
	req := httptest.NewRequest("POST", "/v1/traces", strings.NewReader(bodyContent))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Key", tenant.APIKey)
	req.ContentLength = -1 // no Content-Length → chunked
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	st.FlushCounters()
	requests, bytes, _, err := st.CounterTotals(t.Context(), tenant.ID)
	if err != nil {
		t.Fatalf("counter totals: %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected 1 request, got %d", requests)
	}
	if bytes != int64(len(bodyContent)) {
		t.Fatalf("expected %d bytes accounted, got %d", len(bodyContent), bytes)
	}
}

func TestProxySpoofedContentLength(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "spoof-test", "", nil)

	handler, err := NewHandler(backend.URL, "test-key", st, 4194304, ratelimit.NewLimiter(st))
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	realBody := jsonTraceBody()
	req := httptest.NewRequest("POST", "/v1/traces", strings.NewReader(realBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Key", tenant.APIKey)
	req.Header.Set("Content-Length", "999999") // spoofed!
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	st.FlushCounters()
	_, bytes, _, err := st.CounterTotals(t.Context(), tenant.ID)
	if err != nil {
		t.Fatalf("counter totals: %v", err)
	}
	if bytes != int64(len(realBody)) {
		t.Fatalf("expected %d bytes accounted (real body size), got %d (spoofed Content-Length was 999999)", len(realBody), bytes)
	}
}

func TestProxyHealthzDroppedCounter(t *testing.T) {
	st := testStore(t)
	handler, err := NewHandler("http://localhost:1", "key", st, 4194304, ratelimit.NewLimiter(st))
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"dropped":0`) {
		t.Fatalf("expected dropped counter in healthz, got %q", rec.Body.String())
	}
}

func TestProxyRateLimit429(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	rps10 := int64(10)
	tenant, _ := st.CreateTenant(t.Context(), "rl-test", "", &store.RateLimitParams{RateLimitRPS: &rps10})

	lim := ratelimit.NewLimiter(st)
	lim.Start()
	defer lim.Stop()

	handler, err := NewHandler(backend.URL, "", st, 4194304, lim)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("POST", "/v1/traces", strings.NewReader(jsonTraceBody()))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-Key", tenant.APIKey)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest("POST", "/v1/traces", strings.NewReader(jsonTraceBody()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Key", tenant.APIKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("expected Retry-After: 1 header, got %q", rec.Header().Get("Retry-After"))
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}
	if body["error"] != "rate limit exceeded" {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
	if body["reason"] != "rps" {
		t.Fatalf("expected reason=rps, got %q", body["reason"])
	}
}

func TestProxyNoRateLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "no-rl", "", nil)

	lim := ratelimit.NewLimiter(st)
	lim.Start()
	defer lim.Stop()

	handler, err := NewHandler(backend.URL, "", st, 4194304, lim)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("POST", "/v1/traces", strings.NewReader(jsonTraceBody()))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-Key", tenant.APIKey)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 (unlimited), got %d", i+1, rec.Code)
		}
	}
}

func TestProxyStripClientTenantID(t *testing.T) {
	var forwardedBody []byte
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "strip-test", "", nil)

	handler, err := NewHandler(backend.URL, "test-key", st, 4194304, ratelimit.NewLimiter(st))
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := &tracecollector.ExportTraceServiceRequest{
		ResourceSpans: []*tracev1.ResourceSpans{{
			Resource: &resourcev1.Resource{
				Attributes: []*commonv1.KeyValue{
					stringAttr("tenant.id", "victim"),
					stringAttr("service.name", "myapp"),
				},
			},
		}},
	}
	body, _ := proto.Marshal(req)

	httpReq := httptest.NewRequest("POST", "/v1/traces", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("X-Tenant-Key", tenant.APIKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httpReq)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var result tracecollector.ExportTraceServiceRequest
	if err := proto.Unmarshal(forwardedBody, &result); err != nil {
		t.Fatalf("unmarshal forwarded: %v", err)
	}
	attrs := result.ResourceSpans[0].Resource.Attributes
	var foundTenantID string
	for _, kv := range attrs {
		if kv.Key == "tenant.id" {
			foundTenantID = kv.Value.GetStringValue()
		}
	}
	if foundTenantID == "victim" {
		t.Fatal("tenant.id=victim was NOT stripped!")
	}
	if foundTenantID != strconv.FormatInt(tenant.ID, 10) {
		t.Fatalf("expected tenant.id=%d, got %s", tenant.ID, foundTenantID)
	}
}

func TestProxyMalformedProto400(t *testing.T) {
	backendHit := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "malformed-test", "", nil)

	handler, err := NewHandler(backend.URL, "test-key", st, 4194304, ratelimit.NewLimiter(st))
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1/traces", strings.NewReader("absolute garbage!!!"))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Tenant-Key", tenant.APIKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed body, got %d: %s", rec.Code, rec.Body.String())
	}
	if backendHit {
		t.Fatal("backend was hit despite malformed body — body was forwarded!")
	}
}

func TestProxyGzipRoundTrip(t *testing.T) {
	var forwardedBody []byte
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "gzip-test", "", nil)

	handler, err := NewHandler(backend.URL, "test-key", st, 4194304, ratelimit.NewLimiter(st))
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := &tracecollector.ExportTraceServiceRequest{
		ResourceSpans: []*tracev1.ResourceSpans{{
			Resource: &resourcev1.Resource{
				Attributes: []*commonv1.KeyValue{stringAttr("service.name", "gzip-app")},
			},
		}},
	}
	rawBody, _ := proto.Marshal(req)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write(rawBody)
	gw.Close()

	httpReq := httptest.NewRequest("POST", "/v1/traces", bytes.NewReader(buf.Bytes()))
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("Content-Encoding", "gzip")
	httpReq.Header.Set("X-Tenant-Key", tenant.APIKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httpReq)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Decompress and verify stamped
	gr, err := gzip.NewReader(bytes.NewReader(forwardedBody))
	if err != nil {
		t.Fatalf("forwarded body not gzip: %v", err)
	}
	defer gr.Close()
	decompressed, _ := io.ReadAll(gr)

	var result tracecollector.ExportTraceServiceRequest
	if err := proto.Unmarshal(decompressed, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	found := false
	for _, kv := range result.ResourceSpans[0].Resource.Attributes {
		if kv.Key == "tenant.id" && kv.Value.GetStringValue() == strconv.FormatInt(tenant.ID, 10) {
			found = true
		}
	}
	if !found {
		t.Fatal("tenant.id missing in gzip round-tripped body")
	}
}

func TestProxyOriginalByteAccounting(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "byte-accounting", "", nil)

	handler, err := NewHandler(backend.URL, "test-key", st, 4194304, ratelimit.NewLimiter(st))
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := &tracecollector.ExportTraceServiceRequest{
		ResourceSpans: []*tracev1.ResourceSpans{{
			Resource: &resourcev1.Resource{
				Attributes: []*commonv1.KeyValue{stringAttr("a", "b")},
			},
		}},
	}
	body, _ := proto.Marshal(req)
	originalSize := len(body)

	httpReq := httptest.NewRequest("POST", "/v1/traces", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("X-Tenant-Key", tenant.APIKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httpReq)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	st.FlushCounters()
	_, accountedBytes, _, err := st.CounterTotals(t.Context(), tenant.ID)
	if err != nil {
		t.Fatalf("counter totals: %v", err)
	}
	if accountedBytes != int64(originalSize) {
		t.Fatalf("expected accounted bytes=%d (original size), got %d (stamped size may differ)", originalSize, accountedBytes)
	}
}

func TestProxyJSONContentType(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "json-test", "", nil)

	handler, err := NewHandler(backend.URL, "test-key", st, 4194304, ratelimit.NewLimiter(st))
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1/traces", strings.NewReader(`{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"app"}}]}}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Key", tenant.APIKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProxyContentTypeWithCharset(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st := testStore(t)
	tenant, _ := st.CreateTenant(t.Context(), "charset-test", "", nil)

	handler, err := NewHandler(backend.URL, "test-key", st, 4194304, ratelimit.NewLimiter(st))
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1/traces", strings.NewReader(`{"resourceSpans":[]}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-Tenant-Key", tenant.APIKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
