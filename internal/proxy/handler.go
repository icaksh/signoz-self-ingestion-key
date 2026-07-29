package proxy

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/sismedika/otlp-proxy/internal/store"
)

type Handler struct {
	proxy     *httputil.ReverseProxy
	store     *store.Store
}

func NewHandler(signozEndpoint, signozIngestKey string, st *store.Store) (*Handler, error) {
	target, err := url.Parse(signozEndpoint)
	if err != nil {
		return nil, err
	}

	h := &Handler{
		store: st,
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			if signozIngestKey != "" {
				req.Header.Set("Authorization", "Bearer "+signozIngestKey)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[proxy] backend error: %v", err)
			http.Error(w, `{"error":"backend unreachable"}`, http.StatusBadGateway)
		},
	}

	h.proxy = proxy
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	var signalType string
	switch {
	case strings.HasPrefix(path, "/v1/traces"):
		signalType = "traces"
	case strings.HasPrefix(path, "/v1/metrics"):
		signalType = "metrics"
	case strings.HasPrefix(path, "/v1/logs"):
		signalType = "logs"
	default:
		http.Error(w, `{"error":"unknown OTLP path"}`, http.StatusNotFound)
		return
	}

	tenantKey := r.Header.Get("X-Tenant-Key")
	if tenantKey == "" {
		http.Error(w, `{"error":"missing X-Tenant-Key header"}`, http.StatusUnauthorized)
		return
	}

	tenant, err := h.store.LookupTenant(r.Context(), tenantKey)
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

	r = r.WithContext(context.WithValue(r.Context(), ctxKeyTenantID{}, tenant.ID))
	r = r.WithContext(context.WithValue(r.Context(), ctxKeySignalType{}, signalType))
	r = r.WithContext(context.WithValue(r.Context(), ctxKeyByteCount{}, byteCount))

	h.proxy.ServeHTTP(w, r)

	go func() {
		h.store.LogUsage(context.Background(), tenant.ID, signalType, byteCount, 200)
	}()
}

type ctxKeyTenantID struct{}
type ctxKeySignalType struct{}
type ctxKeyByteCount struct{}
