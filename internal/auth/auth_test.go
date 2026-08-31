package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sismedika/otlp-proxy/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func signingKey() []byte {
	return []byte(strings.Repeat("ab", 32))
}

func TestSessionSignVerifyAndUserDeleted(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	// Create a user.
	if err := st.CreateUser(ctx, "alice", "hash"); err != nil {
		t.Fatal(err)
	}
	id, _, _ := st.GetUserByUsername(ctx, "alice")

	m := NewSessionManager(signingKey(), true, st)
	token := m.Sign(id, "alice")

	uid, username, ok := m.Verify(ctx, token)
	if !ok || uid != id || username != "alice" {
		t.Fatalf("Verify = %d/%q/%v", uid, username, ok)
	}

	// Deleting the user must revoke the session (security fix).
	if err := st.DeleteUser(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := m.Verify(ctx, token); ok {
		t.Fatalf("session still valid after user deletion")
	}
}

func TestSessionTamperRejected(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	m := NewSessionManager(signingKey(), true, st)

	token := m.Sign(1, "alice")
	if _, _, ok := m.Verify(ctx, token+"x"); ok {
		t.Fatalf("tampered token accepted")
	}
	// Wrong key rejects.
	m2 := NewSessionManager([]byte(strings.Repeat("cd", 32)), true, st)
	if _, _, ok := m2.Verify(ctx, token); ok {
		t.Fatalf("wrong-key token accepted")
	}
}

func TestCSRFVerify(t *testing.T) {
	c := NewCSRF(signingKey())
	secret := c.NewSecret()
	token := c.Token(secret)
	if !c.Verify(secret, token) {
		t.Fatalf("valid CSRF token rejected")
	}
	if c.Verify(secret, "deadbeef") {
		t.Fatalf("invalid CSRF token accepted")
	}
	if c.Verify("other-secret", token) {
		t.Fatalf("token accepted for wrong secret")
	}
}

func TestLoginLimiterWindow(t *testing.T) {
	l := NewLoginLimiter()
	for i := 0; i < 5; i++ {
		if !l.Allow("ip:1.2.3.4") {
			t.Fatalf("attempt %d should be allowed", i)
		}
	}
	if l.Allow("ip:1.2.3.4") {
		t.Fatalf("6th attempt should be limited")
	}
	// A different key is independent.
	if !l.Allow("ip:5.6.7.8") {
		t.Fatalf("different IP should be allowed")
	}
}

func TestGatewayResolve(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	tenant, err := st.CreateTenant(ctx, "gw", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(st)

	got, err := g.ResolveTenant(ctx, NewAPIKeyCredential(tenant.APIKey))
	if err != nil || got == nil || got.ID != tenant.ID {
		t.Fatalf("API key resolve = %+v, %v", got, err)
	}

	// Unknown fingerprint resolves nil.
	if got, _ := g.ResolveTenant(ctx, NewCertCredential("deadbeef")); got != nil {
		t.Fatalf("unknown fingerprint resolved tenant")
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	st := newTestStore(t)
	m := NewSessionManager(signingKey(), true, st)

	rec := httptest.NewRecorder()
	m.SetCookie(rec, "tok")
	resp := rec.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie")
	}
	c := cookies[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie attrs = HttpOnly:%v Secure:%v SameSite:%v", c.HttpOnly, c.Secure, c.SameSite)
	}

	// ClearCookie must preserve Secure + SameSite (legacy bug fix).
	rec2 := httptest.NewRecorder()
	m.ClearCookie(rec2)
	resp2 := rec2.Result()
	c2 := resp2.Cookies()[0]
	if !c2.Secure || c2.SameSite != http.SameSiteStrictMode {
		t.Errorf("clear cookie attrs = Secure:%v SameSite:%v", c2.Secure, c2.SameSite)
	}
	if c2.MaxAge != -1 {
		t.Errorf("clear cookie MaxAge = %d, want -1", c2.MaxAge)
	}
}
