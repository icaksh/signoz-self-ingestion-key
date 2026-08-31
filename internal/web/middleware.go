package web

import (
	"net/http"
)

// currentCSRFSecret returns the raw CSRF secret cookie value.
func (s *Server) currentCSRFSecret(r *http.Request) string {
	cookie, err := r.Cookie("csrf")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// requireAuth redirects unauthenticated requests to /login.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if _, _, ok := s.session.Verify(r.Context(), cookie.Value); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// requireCSRF enforces the synchronizer token on state-changing routes.
func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret := s.currentCSRFSecret(r)
		token := r.FormValue("_csrf")
		if secret == "" || token == "" || !s.csrf.Verify(secret, token) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
