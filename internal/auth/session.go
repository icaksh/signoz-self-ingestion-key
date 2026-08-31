package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/sismedika/otlp-proxy/internal/store"
)

// sessionTTL is the session lifetime.
const sessionTTL = 24 * time.Hour

// SessionManager signs and verifies admin session cookies. In addition to the
// HMAC signature and expiry, it re-validates that the user still exists so
// deleting a user revokes their session.
type SessionManager struct {
	signingKey   []byte
	cookieSecure bool
	store        *store.Store
}

func NewSessionManager(signingKey []byte, cookieSecure bool, st *store.Store) *SessionManager {
	return &SessionManager{signingKey: signingKey, cookieSecure: cookieSecure, store: st}
}

// CookieSecure reports the configured Secure flag for session cookies.
func (m *SessionManager) CookieSecure() bool { return m.cookieSecure }

type sessionClaims struct {
	ID  int64  `json:"id"`
	U   string `json:"u"`
	Exp int64  `json:"exp"`
}

// Sign builds a signed session token for the user.
func (m *SessionManager) Sign(userID int64, username string) string {
	payload, _ := json.Marshal(sessionClaims{
		ID:  userID,
		U:   username,
		Exp: time.Now().Add(sessionTTL).Unix(),
	})
	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write(payload)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// Verify checks the token signature and expiry, then re-validates that the
// user still exists in the store. Returns (userID, username, true) on success.
func (m *SessionManager) Verify(ctx context.Context, token string) (int64, string, bool) {
	parts := strings.SplitN(token, ".", 2)
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
	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return 0, "", false
	}
	var claims sessionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, "", false
	}
	if time.Now().Unix() > claims.Exp {
		return 0, "", false
	}
	// Re-validate the user still exists (revokes sessions of deleted users).
	if _, found, err := m.store.GetUserByID(ctx, claims.ID); err != nil || !found {
		return 0, "", false
	}
	return claims.ID, claims.U, true
}

// SetCookie writes the session cookie with the full security attribute set.
func (m *SessionManager) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

// ClearCookie removes the session cookie with the exact same attribute
// parity (Secure + SameSite) as the set cookie, fixing the legacy logout bug.
func (m *SessionManager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
