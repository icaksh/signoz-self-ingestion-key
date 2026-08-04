package admin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/sismedika/otlp-proxy/internal/ca"
	"github.com/sismedika/otlp-proxy/internal/store"
)

// mockCAServer signs any CSR with a throwaway CA.
func mockCAServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body := make([]byte, 0)
		switch r.URL.Path {
		case "/v1/sign", "/v1/renew":
			buf := make([]byte, 8192)
			n, _ := r.Body.Read(buf)
			body = buf[:n]
			block, _ := pem.Decode(body)
			if block == nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(time.Now().UnixNano()),
				Subject:      csr.Subject,
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(90 * 24 * time.Hour),
				KeyUsage:     x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, key)
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		case "/v1/revoke":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func newCertTestServer(t *testing.T) (*httptest.Server, *store.Store, *httptest.Server) {
	t.Helper()
	mockCA := mockCAServer(t)
	t.Cleanup(mockCA.Close)

	// Build a real ca.Client pointing at the mock
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rawJWK := jwkJSON(t, key)

	caClient, err := ca.NewClient(ca.ClientConfig{
		Endpoint:        mockCA.URL,
		ProvisionerName: "test",
		ProvisionerKey:  rawJWK,
		RootCert:        []byte("root"),
		Lifetime:        90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("ca client: %v", err)
	}

	dl := ca.NewDownloadManager()
	t.Cleanup(dl.Stop)

	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv := NewServer(st, "127.0.0.1:0", []byte("0123456789abcdef0123456789abcdef"), false,
		caClient, dl, "relay.example.com", 6514, 90*24*time.Hour, nil)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	return ts, st, mockCA
}

func jwkJSON(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	jwk := jose.JSONWebKey{Key: key, Algorithm: "ES256"}
	raw, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	return raw
}

// login helper: creates admin user + session cookie
func adminLogin(t *testing.T, ts *httptest.Server) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	// Setup a user (sets the session cookie in the jar)
	resp, err := client.Post(ts.URL+"/setup", "application/x-www-form-urlencoded",
		strings.NewReader("username=admin&password=long-password-123"))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	resp.Body.Close()
	return client
}

func makeCSRForTest(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestCertificateListPage(t *testing.T) {
	ts, st, _ := newCertTestServer(t)
	client := adminLogin(t, ts)

	tenant, _ := st.CreateTenant(t.Context(), "cert-page", "", nil)
	st.AddCertificate(t.Context(), tenant.ID, "12345", "abcdef1234567890", "cn-1",
		time.Now(), time.Now().Add(24*time.Hour))

	resp, err := client.Get(ts.URL + fmt.Sprintf("/tenants/%d/certificates", tenant.ID))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	// requireAuth redirects to /login without a session cookie — with a session
	// from adminLogin the page renders (200).
	// adminLogin returns the client but setup set a session cookie on it.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestCertificateIssueCSR(t *testing.T) {
	ts, st, _ := newCertTestServer(t)
	client := adminLogin(t, ts)

	tenant, _ := st.CreateTenant(t.Context(), "issue-app", "", nil)
	csr := makeCSRForTest(t, "device-1")

	resp, err := client.Post(ts.URL+fmt.Sprintf("/tenants/%d/certificates", tenant.ID),
		"application/x-www-form-urlencoded", strings.NewReader("csr="+urlEscape(csr)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	certs, _ := st.ListCertificates(t.Context(), tenant.ID)
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert stored, got %d", len(certs))
	}
	if certs[0].SubjectCN != "device-1" {
		t.Fatalf("expected CN=device-1, got %q", certs[0].SubjectCN)
	}
}

func TestCertificateRevoke(t *testing.T) {
	ts, st, _ := newCertTestServer(t)
	client := adminLogin(t, ts)

	tenant, _ := st.CreateTenant(t.Context(), "revoke-app", "", nil)
	added, _ := st.AddCertificate(t.Context(), tenant.ID, "777", "f00df00df00d", "cn-r",
		time.Now(), time.Now().Add(24*time.Hour))

	resp, err := client.Post(ts.URL+fmt.Sprintf("/tenants/%d/certificates/%d/revoke", tenant.ID, added.ID),
		"application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	got, _ := st.LookupCertificateByID(t.Context(), added.ID)
	if !got.RevokedAt.Valid {
		t.Fatal("expected revoked_at set")
	}
}

func TestSingleUseTokenDownload(t *testing.T) {
	// Direct DownloadManager test via the handler path: create a token and consume it twice
	dl := ca.NewDownloadManager()
	defer dl.Stop()
	token := dl.Create([]byte("cert"), []byte("key"))

	// Consume once
	if _, err := dl.Consume(token); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	// Second consume must fail
	if _, err := dl.Consume(token); err == nil {
		t.Fatal("expected second consume to fail")
	}
}

func urlEscape(s string) string {
	r := strings.NewReplacer(
		"+", "%2B",
		"/", "%2F",
		"=", "%3D",
		"\n", "%0A",
		" ", "%20",
	)
	return r.Replace(s)
}

func newCertDisabledServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	// caClient == nil => CA integration disabled
	srv := NewServer(st, "127.0.0.1:0", []byte("0123456789abcdef0123456789abcdef"), false,
		nil, nil, "", 6514, 90*24*time.Hour, nil)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	return ts, st
}

func TestKeygenReturns503WhenCADisabled(t *testing.T) {
	ts, st := newCertDisabledServer(t)
	client := adminLogin(t, ts)

	tenant, _ := st.CreateTenant(t.Context(), "disabled-ca", "", nil)

	resp, err := client.Post(ts.URL+fmt.Sprintf("/tenants/%d/certificates/keygen", tenant.ID),
		"application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestCertListHidesIssueWhenCADisabled(t *testing.T) {
	ts, st := newCertDisabledServer(t)
	client := adminLogin(t, ts)

	tenant, _ := st.CreateTenant(t.Context(), "disabled-ca-2", "", nil)

	resp, err := client.Get(ts.URL + fmt.Sprintf("/tenants/%d/certificates", tenant.ID))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "Issue Certificate") {
		t.Fatal("issue button must be hidden when CA is disabled")
	}
	if !strings.Contains(string(body), "CA integration is disabled") {
		t.Fatal("expected disabled banner")
	}
}
