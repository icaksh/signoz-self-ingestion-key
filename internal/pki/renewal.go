package pki

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/sismedika/otlp-proxy/internal/auth"
	"github.com/sismedika/otlp-proxy/internal/store"
)

// RenewalServer exposes POST /renew over mTLS so a device with a valid client
// cert can renew it (key change) without admin intervention.
type RenewalServer struct {
	store      *store.Store
	gateway    *auth.Gateway
	caClient   *Client
	tlsConf    *tls.Config
	listenAddr string
}

type RenewalConfig struct {
	ListenAddr     string
	ClientCAFile   string
	ServerCertFile string
	ServerKeyFile  string
}

func NewRenewalServer(cfg RenewalConfig, st *store.Store, caClient *Client) (*RenewalServer, error) {
	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA file: %w", err)
	}
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates found in client CA file %s", cfg.ClientCAFile)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		MinVersion:   tls.VersionTLS12,
	}

	addr := cfg.ListenAddr
	if addr == "" {
		addr = ":6543"
	}

	return &RenewalServer{
		store:      st,
		gateway:    auth.NewGateway(st),
		caClient:   caClient,
		tlsConf:    tlsConf,
		listenAddr: addr,
	}, nil
}

// ListenAndServe serves the renewal endpoint until ctx is cancelled.
func (r *RenewalServer) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /renew", r.handleRenew)

	httpSrv := &http.Server{
		Handler:   mux,
		TLSConfig: r.tlsConf,
	}

	ln, err := tls.Listen("tcp", r.listenAddr, r.tlsConf)
	if err != nil {
		return fmt.Errorf("renewal listen: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	return httpSrv.Serve(ln)
}

func (r *RenewalServer) handleRenew(w http.ResponseWriter, req *http.Request) {
	if len(req.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(req.TLS.PeerCertificates[0].Raw))

	tenant, err := r.gateway.ResolveTenant(req.Context(), auth.NewCertCredential(fingerprint))
	if err != nil {
		log.Printf("[pki] renewal tenant lookup error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if tenant == nil {
		http.Error(w, "certificate not registered or revoked", http.StatusUnauthorized)
		return
	}

	oldCert, err := r.store.LookupCertificateByFingerprint(req.Context(), fingerprint)
	if err != nil || oldCert == nil {
		http.Error(w, "certificate metadata not found", http.StatusUnauthorized)
		return
	}

	csrPEM, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "read CSR: "+err.Error(), http.StatusBadRequest)
		return
	}

	newCert, err := r.caClient.Renew(oldCert.SerialNumber, csrPEM)
	if err != nil {
		log.Printf("[pki] renewal failed: %v", err)
		http.Error(w, "renewal failed", http.StatusInternalServerError)
		return
	}

	newFingerprint := fmt.Sprintf("%x", sha256.Sum256(newCert.Raw))
	if _, err := r.store.AddCertificate(req.Context(), tenant.ID,
		newCert.SerialNumber.Text(16), newFingerprint, oldCert.SubjectCN,
		newCert.NotBefore, newCert.NotAfter); err != nil {
		log.Printf("[pki] store new cert metadata failed: %v", err)
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(EncodeCertPEM(newCert))
}
