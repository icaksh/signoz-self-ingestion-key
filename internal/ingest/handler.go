// Package ingest implements the OTLP proxy hot path: authentication, rate
// limiting, server-side tenant stamping, and forwarding to the upstream
// collector.
package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/sismedika/otlp-proxy/internal/auth"
	"github.com/sismedika/otlp-proxy/internal/ratelimit"
	"github.com/sismedika/otlp-proxy/internal/store"
)

// Handler is the :4318 OTLP ingestion handler.
type Handler struct {
	proxy        *httputil.ReverseProxy
	store        *store.Store
	gateway      *auth.Gateway
	limiter      *ratelimit.Limiter
	maxBodyBytes int64
}

// statusRecorder captures the real upstream status code via ModifyResponse.
type statusRecorder struct {
	code int
}

type ctxKeyStatus struct{}

// NewHandler builds the ingestion handler with a shared reverse proxy.
func NewHandler(signozEndpoint, signozIngestKey string, st *store.Store, maxBodyBytes int64, lim *ratelimit.Limiter, gw *auth.Gateway) (*Handler, error) {
	target, err := url.Parse(signozEndpoint)
	if err != nil {
		return nil, err
	}

	h := &Handler{
		store:        st,
		gateway:      gw,
		limiter:      lim,
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
			log.Printf("[ingest] backend error: %v", err)
			http.Error(w, `{"error":"backend unreachable"}`, http.StatusBadGateway)
		},
	}

	h.proxy = proxy
	return h, nil
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (h *Handler) writeRateLimit(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprintf(w, `{"error":"rate limit exceeded","reason":"%s"}`, reason)
}

// ServeHTTP implements the ingestion endpoint contract.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && r.URL.Path == "/healthz" {
		h.healthz(w, r)
		return
	}

	var signalType string
	switch r.URL.Path {
	case "/v1/traces":
		signalType = "traces"
	case "/v1/metrics":
		signalType = "metrics"
	case "/v1/logs":
		signalType = "logs"
	default:
		h.writeJSON(w, http.StatusNotFound, `{"error":"unknown OTLP path"}`)
		return
	}

	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	}

	tenantKey := r.Header.Get("X-Tenant-Key")
	if tenantKey == "" {
		h.writeJSON(w, http.StatusUnauthorized, `{"error":"missing X-Tenant-Key header"}`)
		return
	}

	tenant, err := h.gateway.ResolveTenant(r.Context(), auth.NewAPIKeyCredential(tenantKey))
	if err != nil {
		log.Printf("[ingest] tenant lookup error: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, `{"error":"internal error"}`)
		return
	}
	if tenant == nil {
		h.log401(r, tenantKey)
		h.writeJSON(w, http.StatusUnauthorized, `{"error":"invalid tenant key"}`)
		return
	}

	// RPS pre-check — reject before consuming the body.
	if dec := h.limiter.AllowRPS(r.Context(), tenant.ID); !dec.Allowed {
		h.rateLimitDecision(w, dec)
		return
	}

	var originalBytes []byte
	if r.Body != nil {
		originalBytes, err = io.ReadAll(r.Body)
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			h.writeJSON(w, http.StatusRequestEntityTooLarge, `{"error":"request body too large"}`)
			return
		}
		if err != nil {
			log.Printf("[ingest] body read error: %v", err)
			h.writeJSON(w, http.StatusInternalServerError, `{"error":"internal error"}`)
			return
		}
	}
	r.Body.Close()
	originalByteCount := int64(len(originalBytes))

	// Byte-aware check (burst bytes + daily quota).
	if dec := h.limiter.AllowBytes(r.Context(), tenant.ID, originalByteCount); !dec.Allowed {
		h.rateLimitDecision(w, dec)
		return
	}

	// Stamp server-side tenant identity onto the OTLP payload.
	contentType := r.Header.Get("Content-Type")
	contentEncoding := r.Header.Get("Content-Encoding")
	tenantIDStr := strconv.FormatInt(tenant.ID, 10)

	newBody, err := stampTenantIdentity(originalBytes, contentType, contentEncoding, signalType, tenantIDStr, tenant.Name)
	if err != nil {
		if isMalformedBody(err) {
			h.writeJSON(w, http.StatusBadRequest, `{"error":"invalid request body"}`)
		} else {
			log.Printf("[ingest] otlp processing error: %v", err)
			h.writeJSON(w, http.StatusInternalServerError, `{"error":"internal error"}`)
		}
		return
	}

	r.Body = io.NopCloser(bytes.NewReader(newBody))
	r.ContentLength = int64(len(newBody))
	if !strings.EqualFold(contentEncoding, "gzip") {
		r.Header.Del("Content-Encoding")
	}

	sr := &statusRecorder{code: http.StatusBadGateway}
	ctx := context.WithValue(r.Context(), ctxKeyStatus{}, sr)
	r = r.WithContext(ctx)

	h.proxy.ServeHTTP(w, r)

	// Account ORIGINAL client bytes, not the re-encoded/stamped size.
	h.store.RecordUsage(tenant.ID, signalType, sr.code, originalByteCount)
}

// rateLimitDecision maps a limiter decision to the correct HTTP status. A
// store lookup failure is a server error (500), not a client rate limit (429)
// — fixing the legacy misclassification.
func (h *Handler) rateLimitDecision(w http.ResponseWriter, dec ratelimit.Decision) {
	if dec.Reason == "lookup_failed" {
		h.writeJSON(w, http.StatusInternalServerError, `{"error":"internal error"}`)
		return
	}
	h.writeRateLimit(w, dec.Reason)
}

func (h *Handler) log401(r *http.Request, tenantKey string) {
	clientIP := clientIP(r)
	masked := tenantKey
	if len(masked) > 4 {
		masked = masked[:4] + "..."
	}
	log.Printf("[ingest] 401 %s key=%s path=%s", clientIP, masked, r.URL.Path)
}

// clientIP derives the client IP for logging, honoring only explicitly trusted
// forwarded headers.
func clientIP(r *http.Request) string {
	return r.RemoteAddr
}

func (h *Handler) healthz(w http.ResponseWriter, r *http.Request) {
	dropped := h.store.DroppedSamples()
	qf := h.limiter.QuotaFailures()
	if err := h.store.Ping(r.Context()); err != nil {
		h.writeJSON(w, http.StatusServiceUnavailable,
			fmt.Sprintf(`{"status":"unhealthy","dropped":%d,"quota_failures":%d}`, dropped, qf))
		return
	}
	h.writeJSON(w, http.StatusOK,
		fmt.Sprintf(`{"status":"ok","dropped":%d,"quota_failures":%d}`, dropped, qf))
}
