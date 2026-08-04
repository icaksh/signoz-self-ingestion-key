package admin

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// uiLogin logs in with the pre-created admin user and returns an
// authenticated HTTP client.
func uiLogin(t *testing.T, ts *httptest.Server) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// Login with the known password (testAdminServer creates user "admin" with
	// password "correct-password-123")
	resp, err := client.Post(ts.URL+"/login", "application/x-www-form-urlencoded",
		strings.NewReader("username=admin&password=correct-password-123"))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login failed: expected 303, got %d", resp.StatusCode)
	}
	return client
}

func TestDestructiveActionsIncludeIdentifier(t *testing.T) {
	ts, st := testAdminServer(t)
	client := uiLogin(t, ts)

	tenant, err := st.CreateTenant(t.Context(), "prod-app", "test tenant", nil)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	resp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("get index: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	html := string(body)
	if !strings.Contains(html, "data-confirm-name=\"tenant "+tenant.Name+"\"") {
		t.Fatal("missing data-confirm-name for tenant delete button")
	}
	if !strings.Contains(html, "data-confirm-name=\"API key for "+tenant.Name+"\"") {
		t.Fatal("missing data-confirm-name for API key revoke button")
	}
}

func TestKeyRevealHasDismissButton(t *testing.T) {
	ts, _ := testAdminServer(t)
	client := uiLogin(t, ts)

	resp, err := client.Post(ts.URL+"/tenants", "application/x-www-form-urlencoded",
		strings.NewReader("name=test-app&description=test"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	if !strings.Contains(html, "This key is shown once") {
		t.Fatal("key reveal missing 'shown once' warning")
	}
	if !strings.Contains(html, "I have saved this key") {
		t.Fatal("key reveal missing dismiss button")
	}
	if !strings.Contains(html, "Copy to clipboard") {
		t.Fatal("key reveal missing copy button")
	}
}

func TestKeyRevealRenderedOnce(t *testing.T) {
	ts, _ := testAdminServer(t)
	client := uiLogin(t, ts)

	resp, err := client.Post(ts.URL+"/tenants", "application/x-www-form-urlencoded",
		strings.NewReader("name=key-test&description=test"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	createBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	createHTML := string(createBody)

	// The create response must contain the key reveal section with a full key
	if !strings.Contains(createHTML, "key-reveal") {
		t.Fatal("create response does not contain key-reveal section")
	}
	if !strings.Contains(createHTML, "This key is shown once") {
		t.Fatal("create response does not contain 'shown once' text")
	}

	// Now GET the index — the key reveal should NOT be in the table rows
	resp, err = client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("get index: %v", err)
	}
	indexBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	indexHTML := string(indexBody)

	// The index should NOT have the key-reveal banner (only in create/regenerate response)
	if strings.Contains(indexHTML, "class=\"key-reveal-row\"") {
		t.Fatal("index page contains key-reveal-row — key should only be revealed once")
	}
}

func TestEmptyStateNoTenants(t *testing.T) {
	ts, _ := testAdminServer(t)
	client := uiLogin(t, ts)

	resp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("get index: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	if !strings.Contains(html, "No tenants configured") {
		t.Fatal("expected empty state message when no tenants exist")
	}
}

func TestEmptyStateNoCertificates(t *testing.T) {
	ts, st := testAdminServer(t)
	client := uiLogin(t, ts)

	tenant, err := st.CreateTenant(t.Context(), "cert-empty", "no certs yet", nil)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	resp, err := client.Get(ts.URL + "/tenants/" + strconv.FormatInt(tenant.ID, 10) + "/certificates")
	if err != nil {
		t.Fatalf("get certs: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	if !strings.Contains(html, "No certificates issued") {
		t.Fatal("expected empty state message when no certificates exist")
	}
}

func TestErrorPageLayout(t *testing.T) {
	ts, _ := testAdminServer(t)
	client := uiLogin(t, ts)

	resp, err := client.Get(ts.URL + "/tenants/99999/usage")
	if err != nil {
		t.Fatalf("get non-existent tenant: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}

	html := string(body)
	if !strings.HasPrefix(strings.TrimSpace(html), "<!DOCTYPE html>") {
		t.Fatal("error page is not HTML")
	}
	if !strings.Contains(html, "OTLP Proxy") {
		t.Fatal("error page does not include nav shell")
	}
	if !strings.Contains(html, "Return to dashboard") {
		t.Fatal("error page missing return link")
	}
}

func TestNoExternalCDNRequests(t *testing.T) {
	ts, _ := testAdminServer(t)
	client := uiLogin(t, ts)

	resp, err := client.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	if strings.Contains(html, "https://cdn.") {
		t.Fatal("page contains CDN reference (https://cdn.*)")
	}
	if strings.Contains(html, "https://unpkg.com") {
		t.Fatal("page contains unpkg.com CDN reference")
	}
	if strings.Contains(html, "https://cdn.jsdelivr.net") {
		t.Fatal("page contains jsdelivr CDN reference")
	}
	if !strings.Contains(html, "/static/app.css") {
		t.Fatal("page missing local /static/app.css reference")
	}
	if !strings.Contains(html, "/static/htmx.min.js") {
		t.Fatal("page missing local /static/htmx.min.js reference")
	}

	// Verify static files are actually served
	for _, path := range []string{"/static/app.css", "/static/htmx.min.js", "/static/chart.umd.min.js"} {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("static file %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("static file %s returned %d, expected 200", path, resp.StatusCode)
		}
	}

	// Verify CSS MIME type
	resp, err = client.Get(ts.URL + "/static/app.css")
	if err != nil {
		t.Fatalf("css: %v", err)
	}
	ct := resp.Header.Get("Content-Type")
	resp.Body.Close()
	if !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("app.css Content-Type: %q, expected text/css", ct)
	}
}

func TestConfirmOverlayRendered(t *testing.T) {
	ts, _ := testAdminServer(t)
	client := uiLogin(t, ts)

	resp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("get index: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	if !strings.Contains(html, "confirm-overlay") {
		t.Fatal("page missing confirm-overlay element")
	}
	if !strings.Contains(html, "confirm-yes") {
		t.Fatal("confirm overlay missing confirm-yes button")
	}
	if !strings.Contains(html, "confirm-no") {
		t.Fatal("confirm overlay missing confirm-no button")
	}
}

func TestFingerprintTemplateHelpers(t *testing.T) {
	// Test the fingerprintFormat helper
	tests := []struct {
		input    string
		expected string
	}{
		{"abcdabcdabcdabcd", "abcd abcd abcd abcd"},
		{"aabbccdd", "aabb ccdd"},
		{"abc", "abc"},
		{"", ""},
	}
	for _, tt := range tests {
		result := fingerprintFormat(tt.input)
		if result != tt.expected {
			t.Errorf("fingerprintFormat(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}

	// Test the fingerprintShort helper
	if s := fingerprintShort("abcdefabcdefabcdef"); s != "abcdefab…" {
		t.Errorf("fingerprintShort(long) = %q, want 'abcdefab…'", s)
	}
	if s := fingerprintShort("short"); s != "short" {
		t.Errorf("fingerprintShort(short) = %q, want 'short'", s)
	}
}
