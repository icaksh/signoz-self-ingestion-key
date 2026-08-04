package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func testJWK(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: key, Algorithm: "ES256"}
	raw, _ := json.Marshal(jwk)
	return raw
}

func makeCSR(t *testing.T, cn string) []byte {
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// signCSRForTest signs a CSR with a throwaway CA and returns PEM cert bytes.
func signCSRForTest(t *testing.T, csrPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	certTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, certTmpl, caCert, csr.PublicKey, caKey)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func newTestClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{
		Endpoint:        endpoint,
		ProvisionerName: "test-provisioner",
		ProvisionerKey:  testJWK(t),
		RootCert:        []byte("dummy-root"),
		Lifetime:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

func newIPv4Server(t *testing.T, handler http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() {
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	return "http://" + ln.Addr().String()
}

func TestSignCertificate(t *testing.T) {
	mockCAURL := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var req struct {
			CSR string `json:"csr"`
			OTT string `json:"ott"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode sign request: %v", err)
		}
		if req.CSR == "" || req.OTT == "" {
			t.Fatalf("missing csr or ott in sign request: %#v", req)
		}
		certPEM := signCSRForTest(t, []byte(req.CSR))
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(certPEM)
	}))

	client := newTestClient(t, mockCAURL)
	csr := makeCSR(t, "test-client")

	cert, err := client.Sign(csr, 24*time.Hour)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if cert == nil {
		t.Fatal("expected certificate")
	}
	if cert.Subject.CommonName != "test-client" {
		t.Fatalf("expected CN=test-client, got %q", cert.Subject.CommonName)
	}
}

func TestRenewCertificate(t *testing.T) {
	var gotPath string
	mockCAURL := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var req struct {
			CRT string `json:"crt"`
			OTT string `json:"ott"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode renew request: %v", err)
		}
		if req.CRT == "" || req.OTT == "" {
			t.Fatalf("missing crt or ott in renew request: %#v", req)
		}
		certPEM := signCSRForTest(t, []byte(req.CRT))
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(certPEM)
	}))

	client := newTestClient(t, mockCAURL)
	csr := makeCSR(t, "renewed-client")

	cert, err := client.Renew("deadbeef", csr)
	if err != nil {
		t.Fatalf("renew failed: %v", err)
	}
	if cert == nil {
		t.Fatal("expected certificate")
	}
	if gotPath != "/renew" {
		t.Fatalf("expected /renew, got %q", gotPath)
	}
}

func TestRevokeCertificate(t *testing.T) {
	var body string
	mockCAURL := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/revoke" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(http.StatusOK)
	}))

	client := newTestClient(t, mockCAURL)
	if err := client.Revoke("abc123", "keyCompromise"); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if !strings.Contains(body, `"serial":"abc123"`) || !strings.Contains(body, `"reason":"keyCompromise"`) {
		t.Fatalf("unexpected revoke payload: %s", body)
	}
}

func TestSignAuthFailure(t *testing.T) {
	mockCAURL := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	client := newTestClient(t, mockCAURL)
	_, err := client.Sign(makeCSR(t, "x"), time.Hour)
	if err == nil {
		t.Fatal("expected auth failure error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 in error, got: %v", err)
	}
}

func TestSignServerError(t *testing.T) {
	mockCAURL := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	client := newTestClient(t, mockCAURL)
	_, err := client.Sign(makeCSR(t, "x"), time.Hour)
	if err == nil {
		t.Fatal("expected server error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected 500 in error, got: %v", err)
	}
}

func TestInvalidJWKRejected(t *testing.T) {
	_, err := NewClient(ClientConfig{
		Endpoint:        "http://localhost:1",
		ProvisionerName: "p",
		ProvisionerKey:  []byte("not-a-jwk"),
	})
	if err == nil {
		t.Fatal("expected error for invalid JWK")
	}
}
