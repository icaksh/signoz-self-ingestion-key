package proxy

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/sismedika/otlp-proxy/internal/store"
)

type Handler struct {
	proxy        *httputil.ReverseProxy
	store        *store.Store
	maxBodyBytes int64
}

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
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		if err := h.store.Ping(r.Context()); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"unhealthy","error":"db ping failed"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
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

	byteCount := int64(0)
	if cl := r.Header.Get("Content-Length"); cl != "" {
		byteCount, _ = strconv.ParseInt(cl, 10, 64)
	}

	h.proxy.ServeHTTP(w, r)

	go func() {
		h.store.LogUsage(context.Background(), tenant.ID, signalType, byteCount, 200)
	}()
}
