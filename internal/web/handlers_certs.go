package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/sismedika/otlp-proxy/internal/pki"
)

const expiryWarnDays = 14

func (s *Server) certsPage(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tenant, err := s.store.LookupTenantByID(r.Context(), tenantID)
	if err != nil || tenant == nil {
		s.renderError(w, r, http.StatusNotFound, "Tenant Not Found", "The requested tenant does not exist or has been deleted.")
		return
	}
	certs, err := s.store.ListCertificates(r.Context(), tenantID)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Database Error", "Unable to load certificates.")
		return
	}
	v := s.baseView(r, "Certificates")
	v.Tenant = tenant
	v.TenantID = tenantID
	v.Certificates = certs
	v.CAEnabled = s.caClient != nil
	v.ExpiryWarnDays = expiryWarnDays
	v.Flash = s.consumeFlash(w, r)
	s.render(w, "cert_list", v)
}

func (s *Server) certIssueForm(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tenant, err := s.store.LookupTenantByID(r.Context(), tenantID)
	if err != nil || tenant == nil {
		s.renderError(w, r, http.StatusNotFound, "Tenant Not Found", "The requested tenant does not exist or has been deleted.")
		return
	}
	v := s.baseView(r, "Issue certificate")
	v.Tenant = tenant
	v.TenantID = tenantID
	v.CAEnabled = s.caClient != nil
	v.ExpiryWarnDays = expiryWarnDays
	s.render(w, "cert_issue", v)
}

// certIssue handles CSR-based issuance (preferred).
func (s *Server) certIssue(w http.ResponseWriter, r *http.Request) {
	if s.caClient == nil {
		http.Error(w, "certificate issuance unavailable: CA integration disabled (set CA_ENABLED=true and the CA_* variables)", http.StatusServiceUnavailable)
		return
	}
	tenantID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)

	csrPEM := r.FormValue("csr")
	if csrPEM == "" {
		http.Error(w, "CSR is required", http.StatusBadRequest)
		return
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		http.Error(w, "invalid CSR: not a PEM-encoded certificate request", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid CSR: %v", err), http.StatusBadRequest)
		return
	}

	cert, err := s.caClient.Sign([]byte(csrPEM), s.certLifetime)
	if err != nil {
		log.Printf("[web] step-ca sign failed: %v", err)
		http.Error(w, "certificate signing failed", http.StatusInternalServerError)
		return
	}

	serial := cert.SerialNumber.Text(16)
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	if _, err := s.store.AddCertificate(r.Context(), tenantID, serial, fingerprint,
		csr.Subject.CommonName, cert.NotBefore, cert.NotAfter); err != nil {
		log.Printf("[web] store cert metadata failed: %v", err)
		http.Error(w, "failed to store certificate metadata", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/tenants/"+strconv.FormatInt(tenantID, 10)+"/certificates", http.StatusSeeOther)
}

// certIssueKeygen handles server-side keypair generation (fallback).
func (s *Server) certIssueKeygen(w http.ResponseWriter, r *http.Request) {
	if s.caClient == nil {
		http.Error(w, "certificate issuance unavailable: CA integration disabled", http.StatusServiceUnavailable)
		return
	}
	tenantID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		http.Error(w, "key generation failed", http.StatusInternalServerError)
		return
	}

	subject := fmt.Sprintf("tenant-%d-%d", tenantID, time.Now().Unix())
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		http.Error(w, "CSR generation failed", http.StatusInternalServerError)
		return
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	cert, err := s.caClient.Sign(csrPEM, s.certLifetime)
	if err != nil {
		log.Printf("[web] step-ca sign (keygen) failed: %v", err)
		http.Error(w, "certificate signing failed", http.StatusInternalServerError)
		return
	}

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	serial := cert.SerialNumber.Text(16)
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	if _, err := s.store.AddCertificate(r.Context(), tenantID, serial, fingerprint,
		subject, cert.NotBefore, cert.NotAfter); err != nil {
		log.Printf("[web] store cert metadata failed: %v", err)
		http.Error(w, "failed to store certificate metadata", http.StatusInternalServerError)
		return
	}

	s.issueDownload(w, r, tenantID, certPEM, keyPEM, "Certificate Issued")
}

// certRenew issues a renewed certificate (admin-initiated, new key).
func (s *Server) certRenew(w http.ResponseWriter, r *http.Request) {
	if s.caClient == nil {
		http.Error(w, "certificate issuance unavailable: CA integration disabled", http.StatusServiceUnavailable)
		return
	}
	tenantID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	certID, _ := strconv.ParseInt(r.PathValue("certId"), 10, 64)

	cert, err := s.store.LookupCertificateByID(r.Context(), certID)
	if err != nil || cert == nil || cert.TenantID != tenantID {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}
	if cert.RevokedAt.Valid {
		http.Error(w, "cannot renew a revoked certificate", http.StatusBadRequest)
		return
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		http.Error(w, "key generation failed", http.StatusInternalServerError)
		return
	}
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cert.SubjectCN}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		http.Error(w, "CSR generation failed", http.StatusInternalServerError)
		return
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	newCert, err := s.caClient.Renew(cert.SerialNumber, csrPEM)
	if err != nil {
		log.Printf("[web] step-ca renew failed: %v", err)
		http.Error(w, "renewal failed", http.StatusInternalServerError)
		return
	}

	serial := newCert.SerialNumber.Text(16)
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(newCert.Raw))
	if _, err := s.store.AddCertificate(r.Context(), tenantID, serial, fingerprint,
		cert.SubjectCN, newCert.NotBefore, newCert.NotAfter); err != nil {
		log.Printf("[web] store renewed cert failed: %v", err)
		http.Error(w, "failed to store certificate metadata", http.StatusInternalServerError)
		return
	}

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Raw})

	s.issueDownload(w, r, tenantID, certPEM, keyPEM, "Certificate Renewed")
}

// issueDownload creates a single-use download token and redirects with the
// download URL in a flash message.
func (s *Server) issueDownload(w http.ResponseWriter, r *http.Request, tenantID int64, certPEM, keyPEM []byte, title string) {
	token := s.downloadMgr.Create(certPEM, keyPEM)
	downloadURL := "/api/certificates/" + token + "/download"
	s.flash.Set(w, FlashData{
		Kind:    "download",
		URL:     downloadURL,
		Message: title + ". Download link valid for 10 minutes; the private key will not be shown again.",
	})
	http.Redirect(w, r, "/tenants/"+strconv.FormatInt(tenantID, 10)+"/certificates", http.StatusSeeOther)
}

// certRevoke revokes via step-ca AND marks revoked_at locally.
func (s *Server) certRevoke(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	certID, _ := strconv.ParseInt(r.PathValue("certId"), 10, 64)

	cert, err := s.store.LookupCertificateByID(r.Context(), certID)
	if err != nil || cert == nil || cert.TenantID != tenantID {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}

	if s.caClient != nil {
		if err := s.caClient.Revoke(cert.SerialNumber, "unspecified"); err != nil {
			log.Printf("[web] step-ca revoke failed: %v", err)
			http.Error(w, "revocation failed in CA", http.StatusInternalServerError)
			return
		}
	}

	if err := s.store.RevokeCertificate(r.Context(), cert.FingerprintSHA256); err != nil {
		log.Printf("[web] store revoke failed: %v", err)
	}

	http.Redirect(w, r, "/tenants/"+strconv.FormatInt(tenantID, 10)+"/certificates", http.StatusSeeOther)
}

// downloadByToken serves the single-use zip bundle (public, token-scoped).
func (s *Server) downloadByToken(w http.ResponseWriter, r *http.Request) {
	if s.downloadMgr == nil || s.caClient == nil {
		http.Error(w, "download unavailable", http.StatusServiceUnavailable)
		return
	}
	token := r.PathValue("token")

	dt, err := s.downloadMgr.Consume(token)
	if err != nil {
		switch err {
		case pki.ErrTokenExpired:
			http.Error(w, "download link expired", http.StatusGone)
		case pki.ErrTokenUsed:
			http.Error(w, "download link already used", http.StatusGone)
		default:
			http.Error(w, "download link not found", http.StatusNotFound)
		}
		return
	}

	zipData, err := pki.GenerateBundle(dt.CertPEM, dt.KeyPEM,
		s.caClient.RootCert(), s.caExternalHost, s.caSyslogPort)
	if err != nil {
		log.Printf("[web] bundle generation failed: %v", err)
		http.Error(w, "bundle generation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=signoz-certs.zip")
	_, _ = w.Write(zipData)
}
