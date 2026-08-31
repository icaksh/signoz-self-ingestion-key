package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
)

// CSRF implements a synchronizer token bound to the session. A random secret
// is delivered as a SameSite=Strict cookie; each protected form carries the
// HMAC(signingKey, "csrf:"+secret) as a hidden field. On submit the handler
// recomputes the HMAC and compares constant-time, so a cross-site form cannot
// forge the token even though the cookie is SameSite=Strict.
type CSRF struct {
	signingKey []byte
}

func NewCSRF(signingKey []byte) *CSRF {
	return &CSRF{signingKey: signingKey}
}

const csrfCookieName = "csrf"

// NewSecret returns a fresh 32-byte random hex secret.
func (c *CSRF) NewSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Token derives the CSRF token (HMAC) for a secret.
func (c *CSRF) Token(secret string) string {
	mac := hmac.New(sha256.New, c.signingKey)
	mac.Write([]byte("csrf:" + secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify compares a submitted token against the expected token for a secret.
func (c *CSRF) Verify(secret, token string) bool {
	expected := c.Token(secret)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1
}

// SetCookie writes the CSRF secret cookie with SameSite=Strict. It is not
// HttpOnly so the token can be derived server-side only (the raw secret is
// never rendered into pages; only the HMAC token is).
func (c *CSRF) SetCookie(w http.ResponseWriter, secret string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    secret,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

// ClearCookie removes the CSRF cookie.
func (c *CSRF) ClearCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
