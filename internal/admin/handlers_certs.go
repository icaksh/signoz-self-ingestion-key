package admin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/sismedika/otlp-proxy/internal/ca"
	"github.com/sismedika/otlp-proxy/internal/store"
)

type CertListData struct {
	Tenant         store.Tenant
	Certificates   []store.Certificate
	ExpiryWarnDays int
	CAEnabled      bool
}

type CertRowData struct {
	Certificate    store.Certificate
	TenantID       int64
	ExpiryWarnDays int
	CAEnabled      bool
}

// CertificatesPage lists all certificates for a tenant.
func (h *Handlers) CertificatesPage(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tenant, err := h.store.LookupTenantByID(r.Context(), tenantID)
	if err != nil || tenant == nil {
		h.renderError(w, r, http.StatusNotFound, "Tenant Not Found", "The requested tenant does not exist or has been deleted.")
		return
	}
	certs, err := h.store.ListCertificates(r.Context(), tenantID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Database Error", err.Error())
		return
	}
	h.renderPage(w, r, "cert_list", CertListData{
		Tenant:         *tenant,
		Certificates:   certs,
		ExpiryWarnDays: 14,
		CAEnabled:      h.caClient != nil,
	})
}

// CertificateIssueForm renders the CSR/keygen form.
func (h *Handlers) CertificateIssueForm(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tenant, err := h.store.LookupTenantByID(r.Context(), tenantID)
	if err != nil || tenant == nil {
		h.renderError(w, r, http.StatusNotFound, "Tenant Not Found", "The requested tenant does not exist or has been deleted.")
		return
	}
	h.renderPage(w, r, "cert_issue", CertListData{Tenant: *tenant, ExpiryWarnDays: 14, CAEnabled: h.caClient != nil})
}

// CertificateIssue handles CSR-based issuance (preferred).
func (h *Handlers) CertificateIssue(w http.ResponseWriter, r *http.Request) {
	if h.caClient == nil {
		caDisabledError(w)
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

	cert, err := h.caClient.Sign([]byte(csrPEM), h.certLifetime)
	if err != nil {
		log.Printf("[admin] step-ca sign failed: %v", err)
		http.Error(w, "certificate signing failed", http.StatusInternalServerError)
		return
	}

	// ALWAYS use the certificate's actual serial number
	serial := cert.SerialNumber.Text(16)
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	dbCert, err := h.store.AddCertificate(r.Context(), tenantID, serial, fingerprint,
		csr.Subject.CommonName, cert.NotBefore, cert.NotAfter)
	if err != nil {
		log.Printf("[admin] store cert metadata failed: %v", err)
		http.Error(w, "failed to store certificate metadata", http.StatusInternalServerError)
		return
	}

	h.render(w, "cert_row", CertRowData{Certificate: *dbCert, TenantID: tenantID, ExpiryWarnDays: 14, CAEnabled: h.caClient != nil})
}

// CertificateIssueWithKeygen handles server-side keypair generation (fallback).
func (h *Handlers) CertificateIssueWithKeygen(w http.ResponseWriter, r *http.Request) {
	if h.caClient == nil {
		caDisabledError(w)
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

	cert, err := h.caClient.Sign(csrPEM, h.certLifetime)
	if err != nil {
		log.Printf("[admin] step-ca sign (keygen) failed: %v", err)
		http.Error(w, "certificate signing failed", http.StatusInternalServerError)
		return
	}

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	serial := cert.SerialNumber.Text(16)
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	if _, err := h.store.AddCertificate(r.Context(), tenantID, serial, fingerprint,
		subject, cert.NotBefore, cert.NotAfter); err != nil {
		log.Printf("[admin] store cert metadata failed: %v", err)
		http.Error(w, "failed to store certificate metadata", http.StatusInternalServerError)
		return
	}

	token := h.downloadManager.Create(certPEM, keyPEM)
	downloadURL := fmt.Sprintf("/api/certificates/%s/download", token)

	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(fmt.Sprintf(`
<div id="download-link" class="download-banner">
    <p class="download-banner-title">Certificate Issued</p>
    <p class="download-banner-detail">Download link valid for 10 minutes. The private key will not be shown again.</p>
    <a href="%s" class="btn btn-tinted btn-sm">Download Bundle</a>
</div>`, template.HTMLEscapeString(downloadURL))))
}

// caDisabledError reports that certificate operations are unavailable because
// the step-ca integration is not configured.
func caDisabledError(w http.ResponseWriter) {
	http.Error(w, "certificate issuance unavailable: CA integration disabled (set CA_ENABLED=true and the CA_* variables)", http.StatusServiceUnavailable)
}

// CertificateRevoke revokes via step-ca AND marks revoked_at locally.
func (h *Handlers) CertificateRevoke(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	certID, _ := strconv.ParseInt(r.PathValue("certId"), 10, 64)

	cert, err := h.store.LookupCertificateByID(r.Context(), certID)
	if err != nil || cert == nil || cert.TenantID != tenantID {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}

	if h.caClient != nil {
		if err := h.caClient.Revoke(cert.SerialNumber, "unspecified"); err != nil {
			log.Printf("[admin] step-ca revoke failed: %v", err)
			http.Error(w, "revocation failed in CA", http.StatusInternalServerError)
			return
		}
	}

	if err := h.store.RevokeCertificate(r.Context(), cert.FingerprintSHA256); err != nil {
		log.Printf("[admin] store revoke failed: %v", err)
	}

	dbCert, _ := h.store.LookupCertificateByID(r.Context(), certID)
	h.render(w, "cert_row", CertRowData{Certificate: *dbCert, TenantID: tenantID, ExpiryWarnDays: 14, CAEnabled: h.caClient != nil})
}

// CertificateRenew issues a renewed certificate (admin-initiated, new key).
func (h *Handlers) CertificateRenew(w http.ResponseWriter, r *http.Request) {
	if h.caClient == nil {
		caDisabledError(w)
		return
	}
	tenantID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	certID, _ := strconv.ParseInt(r.PathValue("certId"), 10, 64)

	cert, err := h.store.LookupCertificateByID(r.Context(), certID)
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

	newCert, err := h.caClient.Renew(cert.SerialNumber, csrPEM)
	if err != nil {
		log.Printf("[admin] step-ca renew failed: %v", err)
		http.Error(w, "renewal failed", http.StatusInternalServerError)
		return
	}

	serial := newCert.SerialNumber.Text(16)
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(newCert.Raw))
	if _, err := h.store.AddCertificate(r.Context(), tenantID, serial, fingerprint,
		cert.SubjectCN, newCert.NotBefore, newCert.NotAfter); err != nil {
		log.Printf("[admin] store renewed cert failed: %v", err)
		http.Error(w, "failed to store certificate metadata", http.StatusInternalServerError)
		return
	}

	// Renewal produces a new private key held only in memory; expose a
	// single-use download so the admin can install it on the device.
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Raw})
	token := h.downloadManager.Create(certPEM, keyPEM)
	downloadURL := fmt.Sprintf("/api/certificates/%s/download", token)

	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(fmt.Sprintf(`
<div id="download-link" class="download-banner">
    <p class="download-banner-title">Certificate Renewed</p>
    <p class="download-banner-detail">New key + cert. Download link valid for 10 minutes.</p>
    <a href="%s" class="btn btn-tinted btn-sm">Download Bundle</a>
</div>`, template.HTMLEscapeString(downloadURL))))
}

// CertificateDownload serves the cert metadata row for HTMX swap.
func (h *Handlers) CertificateDownload(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	certID, _ := strconv.ParseInt(r.PathValue("certId"), 10, 64)

	cert, err := h.store.LookupCertificateByID(r.Context(), certID)
	if err != nil || cert == nil || cert.TenantID != tenantID {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}
	h.render(w, "cert_row", CertRowData{Certificate: *cert, TenantID: tenantID, ExpiryWarnDays: 14, CAEnabled: h.caClient != nil})
}

// DownloadByToken serves the single-use zip bundle (public, token-scoped).
func (h *Handlers) DownloadByToken(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")

	dt, err := h.downloadManager.Consume(token)
	if err != nil {
		switch err {
		case ca.ErrTokenExpired:
			http.Error(w, "download link expired", http.StatusGone)
		case ca.ErrTokenUsed:
			http.Error(w, "download link already used", http.StatusGone)
		default:
			http.Error(w, "download link not found", http.StatusNotFound)
		}
		return
	}

	zipData, err := ca.GenerateDownloadOnlyBundle(dt.CertPEM, dt.KeyPEM,
		h.caClient.RootCert(), h.caExternalHostname, h.caSyslogPort)
	if err != nil {
		log.Printf("[admin] bundle generation failed: %v", err)
		http.Error(w, "bundle generation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=signoz-certs.zip")
	_, _ = w.Write(zipData)
}
