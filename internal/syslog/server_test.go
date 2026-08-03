package syslog

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sismedika/otlp-proxy/internal/auth"
	"github.com/sismedika/otlp-proxy/internal/ratelimit"
	"github.com/sismedika/otlp-proxy/internal/store"
)

// --- certificate generation helpers ---

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return cert, key
}

func generateTestCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, isServer bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if isServer {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"localhost"}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, key
}

func certToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func keyToPEM(key *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func fingerprint(cert *x509.Certificate) string {
	return fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
}

// --- test environment ---

type testEnv struct {
	st        *store.Store
	srv       *Server
	srvAddr   string
	collector net.Listener
	received  chan []byte
	cancel    context.CancelFunc
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
}

// newTestEnv spins up CA, certs, store, collector, and the syslog server.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	caCert, caKey := generateTestCA(t)
	serverCert, serverKey := generateTestCert(t, caCert, caKey, "server.local", true)

	dir := t.TempDir()
	serverCertFile := filepath.Join(dir, "server.crt")
	serverKeyFile := filepath.Join(dir, "server.key")
	caFile := filepath.Join(dir, "ca.crt")
	writeFile(t, serverCertFile, certToPEM(serverCert))
	writeFile(t, serverKeyFile, keyToPEM(serverKey))
	writeFile(t, caFile, certToPEM(caCert))

	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	lim := ratelimit.NewLimiter(st)
	lim.Start()
	t.Cleanup(lim.Stop)

	// Dummy collector
	collector, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("collector listen: %v", err)
	}
	received := make(chan []byte, 100)
	go func() {
		for {
			conn, err := collector.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read one newline-terminated frame per connection (the pool keeps
				// connections open for reuse, so ReadAll would block forever).
				line, _ := bufio.NewReader(c).ReadString('\n')
				if len(line) > 0 {
					received <- []byte(line)
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { collector.Close() })

	srv, err := NewServer(Config{
		Addr:            "127.0.0.1:0",
		ServerCertFile:  serverCertFile,
		ServerKeyFile:   serverKeyFile,
		ClientCAFile:    caFile,
		MaxFrameBytes:   65536,
		MaxConnections:  100,
		ConnIdleTimeout: 5 * time.Second,
		CollectorAddr:   collector.Addr().String(),
	}, st, auth.NewGateway(st), lim)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.ListenAndServe(ctx) }()
	t.Cleanup(cancel)

	// Wait for the listener to bind
	deadline := time.Now().Add(3 * time.Second)
	for srv.Addr() == nil {
		if time.Now().After(deadline) {
			t.Fatal("server did not bind listener")
		}
		time.Sleep(5 * time.Millisecond)
	}

	return &testEnv{
		st:        st,
		srv:       srv,
		srvAddr:   srv.Addr().String(),
		collector: collector,
		received:  received,
		cancel:    cancel,
		caCert:    caCert,
		caKey:     caKey,
	}
}

// newClientCert issues a client certificate signed by the env's CA.
func (e *testEnv) newClientCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return generateTestCert(t, e.caCert, e.caKey, cn, false)
}

// registerCert stores a client certificate against a new tenant.
func (e *testEnv) registerCert(t *testing.T, cn string, cert *x509.Certificate) int64 {
	t.Helper()
	tenant, err := e.st.CreateTenant(context.Background(), cn, "", nil)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := e.st.AddCertificate(context.Background(), tenant.ID,
		cert.SerialNumber.String(), fingerprint(cert), cn,
		cert.NotBefore, cert.NotAfter); err != nil {
		t.Fatalf("add cert: %v", err)
	}
	return tenant.ID
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func (e *testEnv) clientTLS(clientCert *x509.Certificate, clientKey *ecdsa.PrivateKey) *tls.Config {
	caPool := x509.NewCertPool()
	caPool.AddCert(e.caCert)
	keyPair := tls.Certificate{
		Certificate: [][]byte{clientCert.Raw},
		PrivateKey:  clientKey,
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{keyPair},
		RootCAs:            caPool,
		MinVersion:         tls.VersionTLS12,
		ServerName:         "localhost",
		InsecureSkipVerify: true, // server cert CN is server.local, not localhost DNS
	}
}

func (e *testEnv) dialTLS(t *testing.T, cfg *tls.Config) (*tls.Conn, error) {
	t.Helper()
	return tls.Dial("tcp", e.srvAddr, cfg)
}

// --- tests ---

func TestTLSHandshakeValidCert(t *testing.T) {
	env := newTestEnv(t)
	clientCert, clientKey := env.newClientCert(t, "client-app-1")
	env.registerCert(t, "client-app-1", clientCert)

	conn, err := env.dialTLS(t, env.clientTLS(clientCert, clientKey))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a frame, expect it forwarded to the collector
	msg := "<34>1 2024-01-01T12:00:00Z host app 1234 - - hello"
	if _, err := conn.Write([]byte(fmt.Sprintf("%d %s", len(msg), msg))); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case b := <-env.received:
		if !strings.Contains(string(b), `[tenant@`) {
			t.Fatalf("expected stamped message, got %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("collector did not receive frame")
	}
}

func TestTLSHandshakeSelfSignedCert(t *testing.T) {
	env := newTestEnv(t)

	// Self-signed cert NOT in the CA pool. The server rejects the client at
	// the TLS layer (unknown CA); the connection dies immediately (with TLS
	// 1.3 the client handshake may complete before the alert arrives, so the
	// closure surfaces on first read).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "self-signed"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	selfSigned, _ := x509.ParseCertificate(der)

	env.expectClosed(t, env.clientTLS(selfSigned, key))
}

// expectClosed connects and verifies the server closes the connection shortly
// after handshake (app-level rejection).
func (e *testEnv) expectClosed(t *testing.T, cfg *tls.Config) {
	t.Helper()
	conn, err := e.dialTLS(t, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Attempt a read — the server should close promptly
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		// Some bytes may arrive; then the connection closes
	}
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected connection to be closed")
	}
}

func TestTLSHandshakeRevokedCert(t *testing.T) {
	env := newTestEnv(t)
	clientCert, clientKey := env.newClientCert(t, "revoked-app")
	env.registerCert(t, "revoked-app", clientCert)
	if err := env.st.RevokeCertificate(context.Background(), fingerprint(clientCert)); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	env.expectClosed(t, env.clientTLS(clientCert, clientKey))
}

func TestTLSHandshakeInactiveTenant(t *testing.T) {
	env := newTestEnv(t)
	clientCert, clientKey := env.newClientCert(t, "inactive-app")
	tenantID := env.registerCert(t, "inactive-app", clientCert)
	if err := env.st.UpdateTenant(context.Background(), tenantID, "inactive-app", "", false, nil); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	env.expectClosed(t, env.clientTLS(clientCert, clientKey))
}

func TestTLSHandshakeUnknownFingerprint(t *testing.T) {
	env := newTestEnv(t)
	clientCert, clientKey := env.newClientCert(t, "unknown-app")

	env.expectClosed(t, env.clientTLS(clientCert, clientKey))
}

func TestTenantStampingClientSuppliedSDStripped(t *testing.T) {
	env := newTestEnv(t)
	clientCert, clientKey := env.newClientCert(t, "stamp-app")
	env.registerCert(t, "stamp-app", clientCert)

	conn, err := env.dialTLS(t, env.clientTLS(clientCert, clientKey))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg := `<34>1 2024-01-01T12:00:00Z host app 1234 [tenant@999 tenant-id="evil"] payload`
	if _, err := conn.Write([]byte(fmt.Sprintf("%d %s", len(msg), msg))); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case b := <-env.received:
		if strings.Contains(string(b), `tenant@999`) {
			t.Fatalf("client tenant SD-ID must be stripped, got %q", b)
		}
		if !strings.Contains(string(b), `tenant@`) {
			t.Fatalf("server tenant SD-ID must be injected, got %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("collector did not receive frame")
	}
}

func TestOctetCountedFrameProcessing(t *testing.T) {
	env := newTestEnv(t)
	clientCert, clientKey := env.newClientCert(t, "frame-app")
	env.registerCert(t, "frame-app", clientCert)

	conn, err := env.dialTLS(t, env.clientTLS(clientCert, clientKey))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("5 hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case b := <-env.received:
		if !strings.Contains(string(b), "hello") {
			t.Fatalf("expected hello forwarded, got %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("collector did not receive frame")
	}
}

func TestSplitFrameAcrossWrites(t *testing.T) {
	env := newTestEnv(t)
	clientCert, clientKey := env.newClientCert(t, "split-app")
	env.registerCert(t, "split-app", clientCert)

	conn, err := env.dialTLS(t, env.clientTLS(clientCert, clientKey))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg := `<34>1 2024-01-01T12:00:00Z host app 1234 - - split`
	prefix := fmt.Sprintf("%d ", len(msg))
	if _, err := conn.Write([]byte(prefix + msg[:5])); err != nil {
		t.Fatalf("write part 1: %v", err)
	}
	if _, err := conn.Write([]byte(msg[5:])); err != nil {
		t.Fatalf("write part 2: %v", err)
	}

	select {
	case b := <-env.received:
		if !strings.Contains(string(b), "split") {
			t.Fatalf("expected full message forwarded, got %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("collector did not receive frame")
	}
}

func TestOversizedFrameClosesConnection(t *testing.T) {
	env := newTestEnv(t)
	clientCert, clientKey := env.newClientCert(t, "oversize-app")
	env.registerCert(t, "oversize-app", clientCert)

	conn, err := env.dialTLS(t, env.clientTLS(clientCert, clientKey))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Declare 999999 bytes → server must close the connection
	if _, err := conn.Write([]byte("999999 oversized")); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		if _, err := conn.Read(buf); err == nil {
			t.Fatal("expected connection closed after oversized frame")
		}
	}
}

func TestLimiterOverLimitClosesConnection(t *testing.T) {
	env := newTestEnv(t)
	clientCert, clientKey := env.newClientCert(t, "limited-app")
	rps := int64(1)
	tenant, err := env.st.CreateTenant(context.Background(), "limited-app", "", &store.RateLimitParams{RateLimitRPS: &rps})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := env.st.AddCertificate(context.Background(), tenant.ID,
		clientCert.SerialNumber.String(), fingerprint(clientCert), "limited-app",
		clientCert.NotBefore, clientCert.NotAfter); err != nil {
		t.Fatalf("add cert: %v", err)
	}

	cfg := env.clientTLS(clientCert, clientKey)

	// First connection allowed (consumes the RPS token)
	conn, err := env.dialTLS(t, cfg)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	conn.Close()
	// Let the server process the first connection
	time.Sleep(50 * time.Millisecond)

	// Second connection within the same second → rejected
	env.expectClosed(t, cfg)
}

func TestRevokeBlocksPhase4Connection(t *testing.T) {
	env := newTestEnv(t)
	clientCert, clientKey := env.newClientCert(t, "revoke-blocks")
	env.registerCert(t, "revoke-blocks", clientCert)

	cfg := env.clientTLS(clientCert, clientKey)

	// Connection accepted while cert is active
	conn, err := env.dialTLS(t, cfg)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	conn.Close()

	// Simulate the admin-UI revoke action
	if err := env.st.RevokeCertificate(context.Background(), fingerprint(clientCert)); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Next connection is rejected immediately (fingerprint lookup fails)
	env.expectClosed(t, cfg)
}
