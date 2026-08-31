// Package web implements the admin HTTP server: routes, auth/CSRF/security
// middleware, PRG handlers, and server-rendered templates + static assets.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/sismedika/otlp-proxy/internal/auth"
	"github.com/sismedika/otlp-proxy/internal/pki"
	"github.com/sismedika/otlp-proxy/internal/ratelimit"
	"github.com/sismedika/otlp-proxy/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// View is the top-level template data shared across pages.
type View struct {
	Title         string
	Section       string
	ExpiringCerts int
	CSRF          string
	Flash         *FlashData

	// tenants index
	Tenants     []store.Tenant
	ExpiringMap map[int64]int

	// tenant form
	Editing bool
	Tenant  *store.Tenant

	// users
	Users []store.User

	// usage
	TenantID   int64
	QuotaUsed  int64
	QuotaTotal int64

	// certs
	Certificates   []store.Certificate
	CAEnabled      bool
	ExpiryWarnDays int
}

// Config carries the admin server dependencies.
type Config struct {
	Store             *store.Store
	Addr              string
	SigningKey        []byte
	CookieSecure      bool
	TrustProxyHeaders bool
	CAClient          *pki.Client
	DownloadManager   *pki.DownloadManager
	CAExternalHost    string
	CASyslogPort      int
	CertLifetime      time.Duration
	Limiter           *ratelimit.Limiter
}

// Server owns the admin dependencies and serves the admin mux.
type Server struct {
	store             *store.Store
	tmpl              *template.Template
	session           *auth.SessionManager
	csrf              *auth.CSRF
	flash             *FlashManager
	loginLimiter      *auth.LoginLimiter
	limiter           *ratelimit.Limiter
	caClient          *pki.Client
	downloadMgr       *pki.DownloadManager
	caExternalHost    string
	caSyslogPort      int
	certLifetime      time.Duration
	trustProxyHeaders bool
}

// New builds the admin *http.Server.
func New(cfg Config) *http.Server {
	st := cfg.Store
	funcMap := template.FuncMap{
		"maskKey":           maskKey,
		"megaBytes":         megaBytes,
		"percentOf":         percentOf,
		"formatTime":        formatTime,
		"expired":           expired,
		"expiringSoon":      expiringSoon,
		"daysUntil":         daysUntil,
		"fingerprintFormat": fingerprintFormat,
		"fingerprintShort":  fingerprintShort,
	}

	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html"))

	s := &Server{
		store:             st,
		tmpl:              tmpl,
		session:           auth.NewSessionManager(cfg.SigningKey, cfg.CookieSecure, st),
		csrf:              auth.NewCSRF(cfg.SigningKey),
		flash:             NewFlashManager(cfg.SigningKey, cfg.CookieSecure),
		loginLimiter:      auth.NewLoginLimiter(),
		limiter:           cfg.Limiter,
		caClient:          cfg.CAClient,
		downloadMgr:       cfg.DownloadManager,
		caExternalHost:    cfg.CAExternalHost,
		caSyslogPort:      cfg.CASyslogPort,
		certLifetime:      cfg.CertLifetime,
		trustProxyHeaders: cfg.TrustProxyHeaders,
	}
	if s.certLifetime == 0 {
		s.certLifetime = 2160 * time.Hour
	}

	mux := http.NewServeMux()

	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("static embed: %v", err)
	}
	staticHandler := http.FileServer(http.FS(staticSub))
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler))

	// public
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginAction)
	mux.HandleFunc("GET /setup", s.setupPage)
	mux.HandleFunc("POST /setup", s.setupAction)
	mux.HandleFunc("GET /api/certificates/{token}/download", s.downloadByToken)

	// protected GETs
	mux.HandleFunc("GET /{$}", s.requireAuth(s.index))
	mux.HandleFunc("GET /tenants/new", s.requireAuth(s.tenantNew))
	mux.HandleFunc("GET /tenants/{id}/edit", s.requireAuth(s.tenantEdit))
	mux.HandleFunc("GET /tenants/{id}/usage", s.requireAuth(s.usagePage))
	mux.HandleFunc("GET /tenants/{id}/usage/data", s.requireAuth(s.usageData))
	mux.HandleFunc("GET /tenants/{id}/certificates", s.requireAuth(s.certsPage))
	mux.HandleFunc("GET /tenants/{id}/certificates/new", s.requireAuth(s.certIssueForm))
	mux.HandleFunc("GET /users", s.requireAuth(s.usersPage))

	// protected mutations (CSRF enforced; plain HTML forms => POST)
	mux.HandleFunc("POST /tenants", s.requireAuth(s.requireCSRF(s.tenantCreate)))
	mux.HandleFunc("POST /tenants/{id}", s.requireAuth(s.requireCSRF(s.tenantUpdate)))
	mux.HandleFunc("POST /tenants/{id}/delete", s.requireAuth(s.requireCSRF(s.tenantDelete)))
	mux.HandleFunc("POST /tenants/{id}/regenerate", s.requireAuth(s.requireCSRF(s.tenantRegenerate)))
	mux.HandleFunc("POST /tenants/{id}/certificates", s.requireAuth(s.requireCSRF(s.certIssue)))
	mux.HandleFunc("POST /tenants/{id}/certificates/keygen", s.requireAuth(s.requireCSRF(s.certIssueKeygen)))
	mux.HandleFunc("POST /tenants/{id}/certificates/{certId}/renew", s.requireAuth(s.requireCSRF(s.certRenew)))
	mux.HandleFunc("POST /tenants/{id}/certificates/{certId}/revoke", s.requireAuth(s.requireCSRF(s.certRevoke)))
	mux.HandleFunc("POST /users", s.requireAuth(s.requireCSRF(s.userCreate)))
	mux.HandleFunc("POST /users/{id}/delete", s.requireAuth(s.requireCSRF(s.userDelete)))
	mux.HandleFunc("POST /logout", s.requireAuth(s.requireCSRF(s.logout)))

	return &http.Server{
		Addr:    cfg.Addr,
		Handler: securityHeaders(loggingMiddleware(mux)),
	}
}

// securityHeaders adds baseline security headers to every admin response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[web] %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	qf := int64(0)
	if s.limiter != nil {
		qf = s.limiter.QuotaFailures()
	}
	if err := s.store.Ping(r.Context()); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"status":"unhealthy","quota_failures":%d}`, qf)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","quota_failures":%d}`, qf)
}

// render executes the named template.
func (s *Server) render(w http.ResponseWriter, name string, v View) {
	if err := s.tmpl.ExecuteTemplate(w, name, v); err != nil {
		log.Printf("[web] template error: %v", err)
	}
}

// baseView builds the shared View scaffolding for an authenticated page.
func (s *Server) baseView(r *http.Request, title string) View {
	expiring, _ := s.store.ListExpiringCertificates(r.Context(), 168) // 7 days
	csrfSecret := s.currentCSRFSecret(r)
	section := "tenants"
	if strings.HasPrefix(r.URL.Path, "/users") {
		section = "users"
	}
	return View{
		Title:          title,
		Section:        section,
		ExpiringCerts:  len(expiring),
		CSRF:           s.csrf.Token(csrfSecret),
		ExpiryWarnDays: 14,
	}
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	v := s.baseView(r, title)
	v.Flash = nil
	_ = s.tmpl.ExecuteTemplate(w, "error_page", map[string]any{
		"StatusCode": status,
		"Title":      title,
		"Detail":     detail,
		"View":       v,
	})
}

// --- template helpers ---

func maskKey(k string) string {
	if len(k) <= 8 {
		return strings.Repeat("*", len(k))
	}
	return k[:4] + "..." + k[len(k)-4:]
}

func megaBytes(v any) float64 {
	switch n := v.(type) {
	case int64:
		return float64(n) / 1048576
	case *int64:
		if n != nil {
			return float64(*n) / 1048576
		}
	}
	return 0
}

func percentOf(used, quota int64) int {
	if quota <= 0 {
		return 0
	}
	pct := int(used * 100 / quota)
	if pct > 100 {
		pct = 100
	}
	if pct < 0 {
		pct = 0
	}
	return pct
}

func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

func expired(t time.Time) bool {
	return time.Now().After(t)
}

func expiringSoon(t time.Time, warnDays int) bool {
	return !time.Now().After(t) && time.Now().Add(time.Duration(warnDays)*24*time.Hour).After(t)
}

func daysUntil(t time.Time) int {
	return int(time.Until(t).Hours() / 24)
}

func fingerprintFormat(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return s
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func fingerprintShort(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 12 {
		return s
	}
	return s[:8] + "\u2026"
}
