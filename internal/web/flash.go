package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// FlashData is the one-time message carried across a Post/Redirect/Get cycle.
type FlashData struct {
	Kind    string `json:"kind"`    // "apikey", "download", "message"
	Key     string `json:"key"`     // full API key (apikey)
	Tenant  string `json:"tenant"`  // tenant name (apikey)
	URL     string `json:"url"`     // download URL (download)
	Message string `json:"message"` // generic notice (message)
}

const flashCookieName = "flash"

// FlashManager signs and verifies one-time flash cookies used for PRG reveals
// (API key shown once, single-use download links).
type FlashManager struct {
	key    []byte
	secure bool
}

func NewFlashManager(signingKey []byte, secure bool) *FlashManager {
	return &FlashManager{key: signingKey, secure: secure}
}

func (f *FlashManager) sign(payload []byte) string {
	mac := hmac.New(sha256.New, f.key)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Set stores a flash for one following GET.
func (f *FlashManager) Set(w http.ResponseWriter, data FlashData) {
	payload, _ := json.Marshal(data)
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    f.sign(payload),
		Path:     "/",
		HttpOnly: true,
		Secure:   f.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300,
	})
}

// Get reads and verifies a flash cookie. The caller must also call Clear to
// remove it from the client.
func (f *FlashManager) Get(r *http.Request) (*FlashData, bool) {
	cookie, err := r.Cookie(flashCookieName)
	if err != nil {
		return nil, false
	}
	parts := splitDot(cookie.Value)
	if len(parts) != 2 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, f.key)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return nil, false
	}
	var data FlashData
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, false
	}
	return &data, true
}

// Clear removes the flash cookie.
func (f *FlashManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   f.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}

func splitDot(s string) []string {
	return strings.SplitN(s, ".", 2)
}
