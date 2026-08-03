package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/sismedika/otlp-proxy/internal/store"
)

type Handler struct {
	proxy        *httputil.ReverseProxy
	store        *store.Store
	maxBodyBytes int64
}

// countingReadCloser wraps an io.ReadCloser and counts the bytes actually read.
type countingReadCloser struct {
	io.ReadCloser
	n int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n += int64(n)
	return n, err
}

// statusRecorder captures the real upstream status code via ModifyResponse.
type statusRecorder struct {
	code int
}

type ctxKeyStatus struct{}

func NewHandler(signozEndpoint, signozIngestKey string, st *store.Store, maxBodyBytes int64) (*Handler, error) {
	target, err := url.Parse(signozEndpoint)
	if err != nil {
		return nil, err
	}

	h := &Handler{
		store:        st,
		maxBodyBytes: maxBodyBytes,
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			req.Header.Del("X-Tenant-Key")
			if signozIngestKey != "" {
				req.Header.Set("Authorization", "Bearer "+signozIngestKey)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if sr, ok := resp.Request.Context().Value(ctxKeyStatus{}).(*statusRecorder); ok {
				sr.code = resp.StatusCode
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				http.Error(w, `{"error":"request body too large"}`, http.StatusRequestEntityTooLarge)
				return
			}
			log.Printf("[proxy] backend error: %v", err)
			http.Error(w, `{"error":"backend unreachable"}`, http.StatusBadGateway)
		},
	}

	h.proxy = proxy
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Health check — no auth
	if r.Method == "GET" && r.URL.Path == "/healthz" {
		if err := h.store.Ping(r.Context()); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"unhealthy"}`))
			return
		}
		dropped := h.store.DroppedSamples()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","dropped":%d}`, dropped)
		return
	}

	path := r.URL.Path

	var signalType string
	switch path {
	case "/v1/traces":
		signalType = "traces"
	case "/v1/metrics":
		signalType = "metrics"
	case "/v1/logs":
		signalType = "logs"
	default:
		http.Error(w, `{"error":"unknown OTLP path"}`, http.StatusNotFound)
		return
	}

	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	}

	tenantKey := r.Header.Get("X-Tenant-Key")
	if tenantKey == "" {
		http.Error(w, `{"error":"missing X-Tenant-Key header"}`, http.StatusUnauthorized)
		return
	}

	tenant, err := h.store.LookupTenantByKey(r.Context(), tenantKey)
	if err != nil {
		log.Printf("[proxy] tenant lookup error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if tenant == nil {
		clientIP := r.RemoteAddr
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			clientIP = fwd
		}
		masked := tenantKey
		if len(masked) > 4 {
			masked = masked[:4] + "..."
		}
		log.Printf("[proxy] 401 %s key=%s path=%s", clientIP, masked, path)
		http.Error(w, `{"error":"invalid tenant key"}`, http.StatusUnauthorized)
		return
	}

	// Wrap body for accurate byte counting
	var cr *countingReadCloser
	if r.Body != nil {
		cr = &countingReadCloser{ReadCloser: r.Body}
		r.Body = cr
	}

	// Inject status recorder into context for ModifyResponse. Default 502 —
	// the ErrorHandler path never calls ModifyResponse, so a transport error
	// keeps this default.
	sr := &statusRecorder{code: http.StatusBadGateway}
	ctx := context.WithValue(r.Context(), ctxKeyStatus{}, sr)
	r = r.WithContext(ctx)

	h.proxy.ServeHTTP(w, r)

	// Read actual values after proxy completes
	actualBytes := int64(0)
	if cr != nil {
		actualBytes = cr.n
	}

	h.store.RecordUsage(tenant.ID, signalType, sr.code, actualBytes)
}
