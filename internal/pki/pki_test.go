package pki

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestDownloadTokenLifecycle(t *testing.T) {
	m := NewDownloadManager()
	defer m.Stop()

	token := m.Create([]byte("cert"), []byte("key"))
	dt, err := m.Consume(token)
	if err != nil {
		t.Fatal(err)
	}
	if string(dt.CertPEM) != "cert" || string(dt.KeyPEM) != "key" {
		t.Errorf("payload mismatch")
	}
	// Single-use: second consume fails.
	if _, err := m.Consume(token); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("second consume = %v, want ErrTokenInvalid (deleted on use)", err)
	}
	// Unknown token.
	if _, err := m.Consume("deadbeef"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("unknown = %v", err)
	}
}

func TestDownloadTokenExpiry(t *testing.T) {
	m := NewDownloadManager()
	defer m.Stop()

	token := m.Create([]byte("cert"), []byte("key"))
	m.mu.Lock()
	m.tokens[token].ExpiresAt = time.Now().Add(-time.Minute)
	m.mu.Unlock()

	if _, err := m.Consume(token); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired = %v", err)
	}
}

func TestGenerateBundleContents(t *testing.T) {
	rootPEM := []byte("-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n")
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\nkey\n-----END EC PRIVATE KEY-----\n")

	bundle, err := GenerateBundle(certPEM, keyPEM, rootPEM, "relay.example.com", 6514)
	if err != nil {
		t.Fatal(err)
	}

	zr, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = string(b)
	}
	for _, name := range []string{"ca.crt", "client.crt", "client.key", "60-signoz.conf", "install.sh"} {
		if _, ok := files[name]; !ok {
			t.Errorf("bundle missing %s", name)
		}
	}
	if !strings.Contains(files["60-signoz.conf"], "relay.example.com") {
		t.Errorf("rsyslog hostname not templated")
	}
	if !strings.Contains(files["60-signoz.conf"], "6514") {
		t.Errorf("rsyslog port not templated")
	}
	if !strings.Contains(files["60-signoz.conf"], `TCP_Framing="octet-counted"`) {
		t.Error("rsyslog config must use octet-counted framing toward the proxy")
	}
	if !strings.Contains(files["install.sh"], `SCRIPT_DIR=`) || !strings.Contains(files["install.sh"], `NEW_CERT_DIR="${SCRIPT_DIR}"`) {
		t.Error("installer must resolve bundle files relative to install.sh, not caller cwd")
	}
	if !strings.Contains(files["install.sh"], `ensure_rsyslog_tls`) {
		t.Error("installer must ensure rsyslog GnuTLS support")
	}
	for _, f := range zr.File {
		switch f.Name {
		case "install.sh":
			if f.Mode().Perm() != 0o755 {
				t.Errorf("install.sh mode = %o, want 755", f.Mode().Perm())
			}
		case "client.key":
			if f.Mode().Perm() != 0o600 {
				t.Errorf("client.key mode = %o, want 600", f.Mode().Perm())
			}
		}
	}
}

func TestBundleWithoutKey(t *testing.T) {
	bundle, err := GenerateBundle([]byte("cert"), nil, []byte("ca"), "h", 6514)
	if err != nil {
		t.Fatal(err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	for _, f := range zr.File {
		if f.Name == "client.key" {
			t.Errorf("client.key should be absent when no key supplied")
		}
	}
}

func TestProvisionerRejectsInvalidJWK(t *testing.T) {
	if _, err := NewJWKProvisioner("p", []byte(`{"kty":"EC"}`), []byte("root")); err == nil {
		t.Fatalf("expected error for keyless JWK")
	}
	if _, err := NewJWKProvisioner("p", []byte(`not json`), []byte("root")); err == nil {
		t.Fatalf("expected error for malformed JWK")
	}
}

func TestProvisionerSignsToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkBytes, err := json.Marshal(jose.JSONWebKey{Key: key, Algorithm: "ES256"})
	if err != nil {
		t.Fatal(err)
	}
	prov, err := NewJWKProvisioner("p", jwkBytes, testRootPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	token, err := prov.Token("https://ca/sign", "subject", []string{"dns.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(token, ".") {
		t.Errorf("token not compact JWT: %s", token)
	}
}

func testRootPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestRootFingerprintUsesCertificateDER(t *testing.T) {
	root := testRootPEM(t)
	fp, err := rootFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(root)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.Raw)
	if fp != hex.EncodeToString(sum[:]) {
		t.Fatalf("fingerprint = %s", fp)
	}
}

func TestNormalizeSerial(t *testing.T) {
	if got := normalizeSerial("ab12"); got != "0xab12" {
		t.Fatalf("normalizeSerial = %q", got)
	}
	if got := normalizeSerial("0xab12"); got != "0xab12" {
		t.Fatalf("normalizeSerial prefixed = %q", got)
	}
}
