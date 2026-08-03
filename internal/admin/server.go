package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/sismedika/otlp-proxy/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

type Server struct {
	store        *store.Store
	tmpl         *template.Template
	h            *Handlers
	signingKey   []byte
	cookieSecure bool
	loginLimiter *LoginLimiter
}

func NewServer(st *store.Store, addr string, signingKey []byte, cookieSecure bool) *http.Server {
	funcMap := template.FuncMap{
		"maskKey":   maskKey,
		"megaBytes": megaBytes,
		"percent":   percentOf,
	}

	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html"))

	h := NewHandlers(st, tmpl)
	s := &Server{store: st, tmpl: tmpl, h: h, signingKey: signingKey, cookieSecure: cookieSecure, loginLimiter: NewLoginLimiter()}

	mux := http.NewServeMux()

	// public
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginAction)
	mux.HandleFunc("GET /setup", s.setupPage)
	mux.HandleFunc("POST /setup", s.setupAction)

	// protected
	mux.HandleFunc("GET /{$}", s.requireAuth(h.Index))
	mux.HandleFunc("GET /tenants/new", s.requireAuth(h.NewForm))
	mux.HandleFunc("POST /tenants", s.requireAuth(h.Create))
	mux.HandleFunc("GET /tenants/{id}/edit", s.requireAuth(h.EditForm))
	mux.HandleFunc("PUT /tenants/{id}", s.requireAuth(h.Update))
	mux.HandleFunc("DELETE /tenants/{id}", s.requireAuth(h.Delete))
	mux.HandleFunc("POST /tenants/{id}/regenerate", s.requireAuth(h.RegenerateKey))
	mux.HandleFunc("GET /tenants/{id}/usage", s.requireAuth(h.UsagePage))
	mux.HandleFunc("GET /tenants/{id}/usage/data", s.requireAuth(h.UsageData))
	mux.HandleFunc("GET /tenants/{id}/quota", s.requireAuth(h.QuotaFragment))
	mux.HandleFunc("GET /tenants/cancel", s.requireAuth(h.CancelForm))
	mux.HandleFunc("GET /users", s.requireAuth(h.UsersPage))
	mux.HandleFunc("POST /users", s.requireAuth(h.CreateUser))
	mux.HandleFunc("DELETE /users/{id}", s.requireAuth(h.DeleteUser))
	mux.HandleFunc("POST /logout", s.requireAuth(h.Logout))

	return &http.Server{
		Addr:    addr,
		Handler: loggingMiddleware(mux),
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[admin] %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// megaBytes converts bytes to a human-friendly MB value (1 MB = 1048576 B).
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

// percentOf returns the percentage of used/quota, clamped to [0, 100].
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

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"unhealthy"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// --- auth ---

func (s *Server) makeToken(userID int64, username string) string {
	payload, _ := json.Marshal(map[string]any{"id": userID, "u": username, "exp": time.Now().Add(24 * time.Hour).Unix()})
	mac := hmac.New(sha256.New, s.signingKey)
	mac.Write(payload)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (s *Server) verifyToken(cookie string) (int64, string, bool) {
	parts := strings.SplitN(cookie, ".", 2)
	if len(parts) != 2 {
		return 0, "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, "", false
	}
	mac := hmac.New(sha256.New, s.signingKey)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return 0, "", false
	}
	var data struct {
		ID  int64  `json:"id"`
		U   string `json:"u"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return 0, "", false
	}
	if time.Now().Unix() > data.Exp {
		return 0, "", false
	}
	return data.ID, data.U, true
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if _, _, ok := s.verifyToken(cookie.Value); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	count, _ := s.store.UserCount(r.Context())
	if count == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if err := s.tmpl.ExecuteTemplate(w, "login", nil); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

// dummyHash is a valid bcrypt hash used to make login timing constant even
// when the username does not exist.
var dummyHash = []byte("$2a$10$tSjm/ToHuip7KGgiUuwwBOfyw1q1bdg.hpm2ziKRNY0Zj4MaBbBR6")

func (s *Server) loginAction(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	clientIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		clientIP = strings.SplitN(fwd, ",", 2)[0]
	}

	ipKey := "ip:" + clientIP
	userKey := "user:" + username

	if !s.loginLimiter.Allow(ipKey) || !s.loginLimiter.Allow(userKey) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":"too many attempts"}`))
		return
	}

	id, hash, err := s.store.GetUserByUsername(r.Context(), username)
	if err != nil || id == 0 {
		// Constant-time: always run a bcrypt comparison against a dummy hash
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid credentials"}`))
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid credentials"}`))
		return
	}
	token := s.makeToken(id, username)
	http.SetCookie(w, &http.Cookie{
		Name: "session", Value: token, Path: "/",
		HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteStrictMode,
		MaxAge: 86400,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	count, _ := s.store.UserCount(r.Context())
	if count > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := s.tmpl.ExecuteTemplate(w, "setup", nil); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

func (s *Server) setupAction(w http.ResponseWriter, r *http.Request) {
	count, _ := s.store.UserCount(r.Context())
	if count > 0 {
		http.Error(w, "already setup", http.StatusForbidden)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}
	if len(password) < 12 {
		http.Error(w, "password must be at least 12 characters", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("[admin] bcrypt error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.CreateUser(r.Context(), username, string(hash)); err != nil {
		http.Error(w, "create user failed", http.StatusInternalServerError)
		return
	}
	id, _, _ := s.store.GetUserByUsername(r.Context(), username)
	token := s.makeToken(id, username)
	http.SetCookie(w, &http.Cookie{
		Name: "session", Value: token, Path: "/",
		HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteStrictMode,
		MaxAge: 86400,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
