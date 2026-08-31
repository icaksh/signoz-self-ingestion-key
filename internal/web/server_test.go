package web_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/sismedika/otlp-proxy/internal/auth"
	"github.com/sismedika/otlp-proxy/internal/store"
	"github.com/sismedika/otlp-proxy/internal/web"
)

func signingKey() []byte {
	return []byte(strings.Repeat("ab", 32))
}

func newTestServer(t *testing.T) (*store.Store, *http.Server) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	srv := web.New(web.Config{
		Store:        st,
		Addr:         "127.0.0.1:0",
		SigningKey:   signingKey(),
		CookieSecure: false,
	})
	return st, srv
}

func serve(t *testing.T, srv *http.Server, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	return rec
}

func createUser(t *testing.T, st *store.Store, username, password string) int64 {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(t.Context(), username, string(hash)); err != nil {
		t.Fatal(err)
	}
	id, _, _ := st.GetUserByUsername(t.Context(), username)
	return id
}

// authCookies returns a valid session token + CSRF secret/token for a user.
func authCookies(t *testing.T, st *store.Store, userID int64, username string) (session string, csrfSecret string, csrfToken string) {
	t.Helper()
	sm := auth.NewSessionManager(signingKey(), false, st)
	session = sm.Sign(userID, username)
	c := auth.NewCSRF(signingKey())
	csrfSecret = c.NewSecret()
	csrfToken = c.Token(csrfSecret)
	return
}

func addCookies(req *http.Request, session, csrfSecret string) {
	req.AddCookie(&http.Cookie{Name: "session", Value: session, Path: "/"})
	req.AddCookie(&http.Cookie{Name: "csrf", Value: csrfSecret, Path: "/"})
}

func TestSetupFlow(t *testing.T) {
	st, srv := newTestServer(t)

	// No users: GET /setup returns the setup form.
	rec := serve(t, srv, httptest.NewRequest("GET", "/setup", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Set up your admin account") {
		t.Fatalf("setup page = %d", rec.Code)
	}

	// Short password rejected.
	form := url.Values{"username": {"root"}, "password": {"short"}}
	rec = serve(t, srv, httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode())))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short password = %d, want 400", rec.Code)
	}

	// Valid setup redirects to / and creates the user.
	form = url.Values{"username": {"root"}, "password": {"long-password-123"}}
	req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = serve(t, srv, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("setup redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if n, _ := st.UserCount(t.Context()); n != 1 {
		t.Fatalf("user count = %d, want 1", n)
	}

	// Now GET /setup redirects to /login.
	rec = serve(t, srv, httptest.NewRequest("GET", "/setup", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("setup after users = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestLoginLogoutFlow(t *testing.T) {
	st, srv := newTestServer(t)
	createUser(t, st, "alice", "correct-horse-1")

	// Wrong password → 401.
	form := url.Values{"username": {"alice"}, "password": {"wrong-wrong-wrong"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := serve(t, srv, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login = %d", rec.Code)
	}

	// Correct password → 303 to /, sets session + csrf cookies.
	form = url.Values{"username": {"alice"}, "password": {"correct-horse-1"}}
	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = serve(t, srv, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("good login = %d", rec.Code)
	}
	var hasSession, hasCSRF bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" {
			hasSession = true
		}
		if c.Name == "csrf" {
			hasCSRF = true
		}
	}
	if !hasSession || !hasCSRF {
		t.Fatalf("cookies set: session=%v csrf=%v", hasSession, hasCSRF)
	}
}

func TestLoginThrottle(t *testing.T) {
	st, srv := newTestServer(t)
	createUser(t, st, "alice", "correct-horse-1")

	for i := 0; i < 5; i++ {
		form := url.Values{"username": {"alice"}, "password": {"bad-password-1"}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := serve(t, srv, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d", i, rec.Code)
		}
	}
	// 6th attempt throttled.
	form := url.Values{"username": {"alice"}, "password": {"bad-password-1"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := serve(t, srv, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt = %d, want 429", rec.Code)
	}
}

func TestAuthRedirect(t *testing.T) {
	_, srv := newTestServer(t)
	rec := serve(t, srv, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("protected redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestCSRFEnforced(t *testing.T) {
	st, srv := newTestServer(t)
	id := createUser(t, st, "alice", "correct-horse-1")

	session, csrfSecret, csrfToken := authCookies(t, st, id, "alice")

	// Without CSRF token → 403.
	form := url.Values{"name": {"acme"}}
	req := httptest.NewRequest("POST", "/tenants", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addCookies(req, session, csrfSecret)
	rec := serve(t, srv, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no csrf = %d, want 403", rec.Code)
	}

	// With valid CSRF → redirect (tenant created).
	form.Set("_csrf", csrfToken)
	req = httptest.NewRequest("POST", "/tenants", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addCookies(req, session, csrfSecret)
	rec = serve(t, srv, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("with csrf = %d, want 303", rec.Code)
	}
}

func TestKeyRevealedOnce(t *testing.T) {
	st, srv := newTestServer(t)
	id := createUser(t, st, "alice", "correct-horse-1")
	session, csrfSecret, csrfToken := authCookies(t, st, id, "alice")

	// Create a tenant → redirect to /.
	form := url.Values{"name": {"acme"}, "_csrf": {csrfToken}}
	req := httptest.NewRequest("POST", "/tenants", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addCookies(req, session, csrfSecret)
	rec := serve(t, srv, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create = %d", rec.Code)
	}

	// Carry the flash cookie set by the POST response forward to the GET.
	var flashCookie string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "flash" {
			flashCookie = c.Value
		}
	}
	if flashCookie == "" {
		t.Fatalf("flash cookie not set on tenant create")
	}

	// First GET / shows the full key.
	req = httptest.NewRequest("GET", "/", nil)
	addCookies(req, session, csrfSecret)
	req.AddCookie(&http.Cookie{Name: "flash", Value: flashCookie, Path: "/"})
	rec = serve(t, srv, req)
	body := rec.Body.String()
	if !strings.Contains(body, "shown once") || !strings.Contains(body, "key-reveal-code") {
		t.Fatalf("key reveal missing from first render")
	}

	// Second GET / must not re-display the reveal (flash consumed). The 12-char
	// prefix still appears in the tenant list, but the one-time banner is gone.
	req = httptest.NewRequest("GET", "/", nil)
	addCookies(req, session, csrfSecret)
	rec = serve(t, srv, req)
	if strings.Contains(rec.Body.String(), "shown once") || strings.Contains(rec.Body.String(), "key-reveal-code") {
		t.Fatalf("full key re-displayed on second render")
	}
}

func TestSecurityHeaders(t *testing.T) {
	_, srv := newTestServer(t)
	rec := serve(t, srv, httptest.NewRequest("GET", "/login", nil))
	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("missing security header %s", h)
		}
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", rec.Header().Get("X-Frame-Options"))
	}
}

func TestConfirmDialogContract(t *testing.T) {
	st, srv := newTestServer(t)
	id := createUser(t, st, "alice", "correct-horse-1")
	session, csrfSecret, _ := authCookies(t, st, id, "alice")

	// Create a tenant so the index renders the regenerate + delete forms.
	form := url.Values{"name": {"acme"}, "_csrf": {auth.NewCSRF(signingKey()).Token(csrfSecret)}}
	req := httptest.NewRequest("POST", "/tenants", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addCookies(req, session, csrfSecret)
	serve(t, srv, req)

	req = httptest.NewRequest("GET", "/", nil)
	addCookies(req, session, csrfSecret)
	rec := serve(t, srv, req)
	body := rec.Body.String()

	// The native dialog is still rendered with its accessibility contract.
	for _, want := range []string{
		`id="confirm-dialog"`,
		`role="alertdialog"`,
		`aria-modal="true"`,
		`aria-labelledby="confirm-title"`,
		`aria-describedby="confirm-message"`,
		`value="confirm"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("confirm dialog missing %q", want)
		}
	}

	// The submit button default label must be generic, never hardcoded Delete.
	if !strings.Contains(body, `value="confirm">Confirm</button>`) {
		t.Errorf("confirm submit button default label is not the generic Confirm")
	}

	// Confirmation forms must provide explicit action metadata.
	for _, want := range []string{
		`data-confirm-title="Regenerate API key?"`,
		`data-confirm-action="Regenerate Key"`,
		`data-confirm-variant="destructive"`,
		`data-confirm-title="Delete tenant?"`,
		`data-confirm-action="Delete"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("confirmation form missing %q", want)
		}
	}

	// Regenerate must not be associated with a Delete action.
	if i := strings.Index(body, "regenerate"); i >= 0 {
		regenerateForm := body[i:]
		if j := strings.Index(regenerateForm, "</form>"); j >= 0 {
			regenerateForm = regenerateForm[:j]
		}
		if strings.Contains(regenerateForm, `data-confirm-action="Delete"`) {
			t.Errorf("regenerate form carries a Delete action")
		}
	}
}

func TestErrorPageRenders(t *testing.T) {
	st, srv := newTestServer(t)
	id := createUser(t, st, "alice", "correct-horse-1")
	session, csrfSecret, _ := authCookies(t, st, id, "alice")

	req := httptest.NewRequest("GET", "/tenants/999/usage", nil)
	addCookies(req, session, csrfSecret)
	rec := serve(t, srv, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing tenant usage = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Tenant Not Found") {
		t.Fatalf("error page body missing title")
	}
}

func TestUsagePageCSPCompliant(t *testing.T) {
	st, srv := newTestServer(t)
	id := createUser(t, st, "alice", "correct-horse-1")
	quota := int64(1048576)
	tenant, err := st.CreateTenant(t.Context(), "acme", "", &store.RateLimitParams{DailyByteQuota: &quota})
	if err != nil {
		t.Fatal(err)
	}
	session, csrfSecret, _ := authCookies(t, st, id, "alice")

	req := httptest.NewRequest("GET", "/tenants/"+strconv.FormatInt(tenant.ID, 10)+"/usage", nil)
	addCookies(req, session, csrfSecret)
	rec := serve(t, srv, req)
	body := rec.Body.String()

	// No inline scripts or inline styles — the CSP (script-src 'self';
	// style-src 'self') must not block the page.
	if strings.Contains(body, "<script>") || strings.Contains(body, "style=\"") {
		t.Fatalf("usage page contains inline script/style, blocked by CSP")
	}
	if !strings.Contains(body, `data-tenant-id="`) || !strings.Contains(body, "<progress") {
		t.Fatalf("usage page missing data-tenant-id marker or <progress> element")
	}
}

func TestSidebarShell(t *testing.T) {
	st, srv := newTestServer(t)
	id := createUser(t, st, "alice", "correct-horse-1")
	if _, err := st.CreateTenant(t.Context(), "acme", "", nil); err != nil {
		t.Fatal(err)
	}
	session, csrfSecret, _ := authCookies(t, st, id, "alice")

	// Authenticated page renders the sidebar shell, not the old top navbar.
	req := httptest.NewRequest("GET", "/", nil)
	addCookies(req, session, csrfSecret)
	rec := serve(t, srv, req)
	body := rec.Body.String()
	if !strings.Contains(body, `id="sidebar"`) {
		t.Fatalf("authenticated page missing sidebar")
	}
	if !strings.Contains(body, "OTLP Proxy") || !strings.Contains(body, "Log out") {
		t.Fatalf("sidebar missing brand or logout")
	}
	if !strings.Contains(body, `aria-current="page"`) {
		t.Fatalf("sidebar missing aria-current selection")
	}
	if strings.Contains(body, "nav-inner") {
		t.Fatalf("old top navbar markup still present")
	}

	// Auth pages must remain nav-less (no sidebar).
	rec = serve(t, srv, httptest.NewRequest("GET", "/login", nil))
	if strings.Contains(rec.Body.String(), `id="sidebar"`) {
		t.Fatalf("login page must not render the sidebar")
	}
}

func TestNoHTMX(t *testing.T) {
	_, srv := newTestServer(t)
	rec := serve(t, srv, httptest.NewRequest("GET", "/login", nil))
	body := strings.ToLower(rec.Body.String())
	if strings.Contains(body, "htmx") {
		t.Fatalf("htmx reference found in rendered HTML")
	}
	if strings.Contains(body, "hx-") {
		t.Fatalf("hx- attribute found in rendered HTML")
	}
	// The static asset must not exist.
	rec = serve(t, srv, httptest.NewRequest("GET", "/static/htmx.min.js", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/static/htmx.min.js = %d, want 404", rec.Code)
	}
}
