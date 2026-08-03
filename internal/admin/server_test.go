package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/sismedika/otlp-proxy/internal/store"
)

func testAdminServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if err := st.CreateUser(t.Context(), "admin", string(hash)); err != nil {
		t.Fatalf("create user: %v", err)
	}

	srv := NewServer(st, "127.0.0.1:0", []byte("0123456789abcdef0123456789abcdef"), false, nil, nil, "", 6514, 2160*time.Hour)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	return ts, st
}

func postForm(t *testing.T, url, body string) *http.Response {
	t.Helper()
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Post(url, "application/x-www-form-urlencoded", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return resp
}

func TestLoginRateLimit(t *testing.T) {
	ts, _ := testAdminServer(t)

	// 5 failed attempts → 401 each
	for i := 0; i < 5; i++ {
		resp := postForm(t, ts.URL+"/login", "username=admin&password=wrong-password")
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d (%s)", i+1, resp.StatusCode, body)
		}
	}

	// 6th attempt → 429
	resp := postForm(t, ts.URL+"/login", "username=admin&password=wrong-password")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "too many attempts") {
		t.Fatalf("expected rate limit message, got %s", body)
	}
}

func TestLoginSuccessAfterFailures(t *testing.T) {
	ts, _ := testAdminServer(t)

	// 3 failures then a correct password → 303 redirect (success)
	for i := 0; i < 3; i++ {
		resp := postForm(t, ts.URL+"/login", "username=admin&password=wrong-password")
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
	}

	resp := postForm(t, ts.URL+"/login", "username=admin&password=correct-password-123")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 on success, got %d", resp.StatusCode)
	}
}

func TestLoginUnknownVsWrongPassword(t *testing.T) {
	ts, _ := testAdminServer(t)

	unknown := postForm(t, ts.URL+"/login", "username=nobody&password=whatever")
	unknownBody, _ := io.ReadAll(unknown.Body)
	unknown.Body.Close()

	wrong := postForm(t, ts.URL+"/login", "username=admin&password=wrong-password")
	wrongBody, _ := io.ReadAll(wrong.Body)
	wrong.Body.Close()

	if unknown.StatusCode != wrong.StatusCode {
		t.Fatalf("status mismatch: unknown=%d wrong=%d", unknown.StatusCode, wrong.StatusCode)
	}
	if unknown.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", unknown.StatusCode)
	}
	if string(unknownBody) != string(wrongBody) {
		t.Fatalf("response bodies must be identical:\nunknown: %q\nwrong:   %q", unknownBody, wrongBody)
	}
}

func TestLoginLimiterWindowReset(t *testing.T) {
	l := NewLoginLimiter()

	for i := 0; i < 5; i++ {
		if !l.Allow("user:admin") {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if l.Allow("user:admin") {
		t.Fatal("6th attempt should be blocked")
	}

	// Force the window to expire
	l.mu.Lock()
	if e, ok := l.entries["user:admin"]; ok {
		e.resetAt = time.Now().Add(-time.Minute)
	}
	l.mu.Unlock()

	if !l.Allow("user:admin") {
		t.Fatal("expected allowed after window reset")
	}
}

func TestAdminHealthz(t *testing.T) {
	ts, _ := testAdminServer(t)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("expected ok status, got %s", body)
	}
}

func TestSetupRequiresLongPassword(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv := NewServer(st, "127.0.0.1:0", []byte("0123456789abcdef0123456789abcdef"), false, nil, nil, "", 6514, 2160*time.Hour)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	// Short password rejected
	resp := postForm(t, ts.URL+"/setup", "username=admin&password=short")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for short password, got %d (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "at least 12 characters") {
		t.Fatalf("expected min-length message, got %s", body)
	}

	// Long password accepted
	resp = postForm(t, ts.URL+"/setup", "username=admin&password=a-very-long-password-123")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 on setup success, got %d", resp.StatusCode)
	}
}
