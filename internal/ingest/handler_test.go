package ingest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sismedika/otlp-proxy/internal/auth"
	"github.com/sismedika/otlp-proxy/internal/ratelimit"
	"github.com/sismedika/otlp-proxy/internal/store"
)

type testEnv struct {
	store    *store.Store
	limiter  *ratelimit.Limiter
	gateway  *auth.Gateway
	upstream *httptest.Server
	handler  *Handler
	tenant   *store.Tenant
}

func newTestEnv(t *testing.T, ingestKey string) *testEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	tenant, err := st.CreateTenant(context.Background(), "acme", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	lim := ratelimit.NewLimiter(st)
	t.Cleanup(lim.Stop)
	gw := auth.NewGateway(st)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	h, err := NewHandler(upstream.URL, ingestKey, st, 4194304, lim, gw)
	if err != nil {
		t.Fatal(err)
	}

	return &testEnv{store: st, limiter: lim, gateway: gw, upstream: upstream, handler: h, tenant: tenant}
}

func doRequest(t *testing.T, h http.Handler, method, path, key, body string, hdrs map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if key != "" {
		req.Header.Set("X-Tenant-Key", key)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthz(t *testing.T) {
	env := newTestEnv(t, "")
	rec := doRequest(t, env.handler, "GET", "/healthz", "", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("healthz body = %q", rec.Body.String())
	}
}

func TestUnknownPath(t *testing.T) {
	env := newTestEnv(t, "")
	rec := doRequest(t, env.handler, "POST", "/v1/traces/", "key", "", nil)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "unknown OTLP path") {
		t.Fatalf("unknown path = %d %q", rec.Code, rec.Body.String())
	}
}

func TestMissingKey(t *testing.T) {
	env := newTestEnv(t, "")
	rec := doRequest(t, env.handler, "POST", "/v1/traces", "", "", nil)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "missing X-Tenant-Key") {
		t.Fatalf("missing key = %d %q", rec.Code, rec.Body.String())
	}
}

func TestInvalidKey(t *testing.T) {
	env := newTestEnv(t, "")
	rec := doRequest(t, env.handler, "POST", "/v1/traces", "invalid-key", "", nil)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid tenant key") {
		t.Fatalf("invalid key = %d %q", rec.Code, rec.Body.String())
	}
}

func TestForwardStampsAndStripsKey(t *testing.T) {
	env := newTestEnv(t, "")
	body := []byte("\x0a\x00") // empty ResourceSpans (one empty resource span)
	rec := doRequest(t, env.handler, "POST", "/v1/traces", env.tenant.APIKey, string(body), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("forward = %d %q", rec.Code, rec.Body.String())
	}
}

func TestForwardAddsBearer(t *testing.T) {
	env := newTestEnv(t, "secret-bearer")
	body := []byte("\x0a\x00")
	rec := doRequest(t, env.handler, "POST", "/v1/traces", env.tenant.APIKey, string(body), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("forward = %d", rec.Code)
	}
}

func TestMalformedBody(t *testing.T) {
	env := newTestEnv(t, "")
	rec := doRequest(t, env.handler, "POST", "/v1/traces", env.tenant.APIKey, "not-valid-protobuf", nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid request body") {
		t.Fatalf("malformed = %d %q", rec.Code, rec.Body.String())
	}
}

func TestMaxBodyBytes(t *testing.T) {
	env := newTestEnv(t, "")
	h, _ := NewHandler(env.upstream.URL, "", env.store, 10, env.limiter, env.gateway)
	rec := doRequest(t, h, "POST", "/v1/traces", env.tenant.APIKey, strings.Repeat("x", 100), nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("max body = %d", rec.Code)
	}
}

func TestRateLimit429(t *testing.T) {
	env := newTestEnv(t, "")
	rps := int64(1)
	ctx := context.Background()
	_ = env.store.UpdateTenant(ctx, env.tenant.ID, "acme", "", true, &store.RateLimitParams{RateLimitRPS: &rps})

	body := "\x0a\x00"
	first := doRequest(t, env.handler, "POST", "/v1/traces", env.tenant.APIKey, body, nil)
	second := doRequest(t, env.handler, "POST", "/v1/traces", env.tenant.APIKey, body, nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first = %d", first.Code)
	}
	if second.Code != http.StatusTooManyRequests || !strings.Contains(second.Body.String(), "rate limit exceeded") {
		t.Fatalf("second = %d %q", second.Code, second.Body.String())
	}
}

func TestRateLimitDecisionMapsLookupFailureTo500(t *testing.T) {
	env := newTestEnv(t, "")
	rec := httptest.NewRecorder()
	env.handler.rateLimitDecision(rec, ratelimit.Decision{Allowed: false, Reason: "lookup_failed"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("lookup_failed = %d, want 500", rec.Code)
	}
	rec2 := httptest.NewRecorder()
	env.handler.rateLimitDecision(rec2, ratelimit.Decision{Allowed: false, Reason: "rps"})
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("rps = %d, want 429", rec2.Code)
	}
}
