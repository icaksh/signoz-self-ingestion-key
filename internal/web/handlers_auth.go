package web

import (
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// dummyHash is a valid bcrypt hash used to make login timing constant even
// when the username does not exist.
var dummyHash = []byte("$2a$10$tSjm/ToHuip7KGgiUuwwBOfyw1q1bdg.hpm2ziKRNY0Zj4MaBbBR6")

// clientIP derives the client IP for login throttling, honoring forwarded
// headers only when explicitly trusted.
func (s *Server) clientIP(r *http.Request) string {
	if s.trustProxyHeaders {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			return strings.SplitN(fwd, ",", 2)[0]
		}
		if real := r.Header.Get("X-Real-IP"); real != "" {
			return real
		}
	}
	return r.RemoteAddr
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	count, _ := s.store.UserCount(r.Context())
	if count == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, "login", s.baseView(r, "Sign in"))
}

func (s *Server) loginAction(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	clientIP := s.clientIP(r)
	ipKey := "ip:" + clientIP
	userKey := "user:" + username

	if !s.loginLimiter.Allow(ipKey) || !s.loginLimiter.Allow(userKey) {
		writeJSONError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}

	id, hash, err := s.store.GetUserByUsername(r.Context(), username)
	if err != nil || id == 0 {
		// Constant-time: always run bcrypt against a dummy hash.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	s.establishSession(w, id, username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// establishSession sets the session cookie and a fresh CSRF secret cookie.
func (s *Server) establishSession(w http.ResponseWriter, userID int64, username string) {
	token := s.session.Sign(userID, username)
	s.session.SetCookie(w, token)
	s.csrf.SetCookie(w, s.csrf.NewSecret(), s.session.CookieSecure())
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	count, _ := s.store.UserCount(r.Context())
	if count > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, "setup", s.baseView(r, "Set up"))
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
		log.Printf("[web] bcrypt error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.CreateUser(r.Context(), username, string(hash)); err != nil {
		http.Error(w, "create user failed", http.StatusInternalServerError)
		return
	}
	id, _, _ := s.store.GetUserByUsername(r.Context(), username)
	s.establishSession(w, id, username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.session.ClearCookie(w)
	s.csrf.ClearCookie(w, s.session.CookieSecure())
	s.flash.Clear(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(`{"error":"` + msg + `"}`))
}
