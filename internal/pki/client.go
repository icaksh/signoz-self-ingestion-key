// Package pki implements the optional step-ca certificate lifecycle: a
// client-only CA client, provisioner JWT signing, bundle generation, single-use
// download tokens, and the mTLS renewal server.
package pki

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a minimal step-ca REST API client. It never holds CA keys — it
// authenticates with short-lived JWK provisioner JWTs.
type Client struct {
	endpoint    string
	httpClient  *http.Client
	provisioner *JWKProvisioner
	rootCert    []byte
	lifetime    time.Duration
}

type ClientConfig struct {
	Endpoint        string
	ProvisionerName string
	ProvisionerKey  []byte
	RootCert        []byte
	Lifetime        time.Duration
}

func NewClient(cfg ClientConfig) (*Client, error) {
	prov, err := NewJWKProvisioner(cfg.ProvisionerName, cfg.ProvisionerKey, cfg.RootCert)
	if err != nil {
		return nil, fmt.Errorf("provisioner: %w", err)
	}
	pool, err := rootPool(cfg.RootCert)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return &Client{
		endpoint:    strings.TrimRight(cfg.Endpoint, "/"),
		httpClient:  &http.Client{Timeout: 30 * time.Second, Transport: transport},
		provisioner: prov,
		rootCert:    append([]byte(nil), cfg.RootCert...),
		lifetime:    cfg.Lifetime,
	}, nil
}

func (c *Client) RootCert() []byte        { return append([]byte(nil), c.rootCert...) }
func (c *Client) Lifetime() time.Duration { return c.lifetime }

// Sign submits a CSR to step-ca's JWK provisioner sign endpoint.
func (c *Client) Sign(csrPEM []byte, lifetime time.Duration) (*x509.Certificate, error) {
	subject, sans, err := csrSubjectAndSANs(csrPEM)
	if err != nil {
		return nil, err
	}
	token, err := c.provisioner.Token(c.audience("/1.0/sign"), subject, sans)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}

	if lifetime <= 0 {
		lifetime = c.lifetime
	}
	body := struct {
		CSR      string `json:"csr"`
		OTT      string `json:"ott"`
		NotAfter string `json:"notAfter,omitempty"`
	}{CSR: string(csrPEM), OTT: token}
	if lifetime > 0 {
		body.NotAfter = lifetime.String()
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal sign request: %w", err)
	}

	resp, err := c.postJSON("/1.0/sign", encoded)
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("sign failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return parseCertResponse(resp.Body)
}

// Renew creates a replacement certificate from a fresh CSR using the same JWK
// provisioner flow. Native step-ca /renew and /rekey are mTLS flows that require
// the previous device private key; the proxy intentionally does not possess it.
// The old certificate therefore remains valid until expiry or explicit revoke.
func (c *Client) Renew(_ string, csrPEM []byte) (*x509.Certificate, error) {
	return c.Sign(csrPEM, c.lifetime)
}

// Revoke tells step-ca to passively revoke a certificate by serial number.
func (c *Client) Revoke(serial, reason string) error {
	serial = normalizeSerial(serial)
	token, err := c.provisioner.Token(c.audience("/1.0/revoke"), serial, nil)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	body, err := json.Marshal(struct {
		Serial     string `json:"serial"`
		OTT        string `json:"ott"`
		ReasonCode int    `json:"reasonCode"`
		Reason     string `json:"reason"`
		Passive    bool   `json:"passive"`
	}{Serial: serial, OTT: token, ReasonCode: 0, Reason: reason, Passive: true})
	if err != nil {
		return err
	}
	resp, err := c.postJSON("/1.0/revoke", body)
	if err != nil {
		return fmt.Errorf("revoke request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("revoke failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (c *Client) postJSON(path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, c.endpointURL(path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.httpClient.Do(req)
}

func parseCertResponse(body io.Reader) (*x509.Certificate, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read cert response: %w", err)
	}
	type certResponse struct {
		CRT       string   `json:"crt"`
		CA        string   `json:"ca"`
		CertChain []string `json:"certChain"`
	}
	var resp certResponse
	if err := json.Unmarshal(raw, &resp); err == nil && resp.CRT != "" {
		block, _ := pem.Decode([]byte(resp.CRT))
		if block == nil {
			return nil, fmt.Errorf("no PEM block in sign response crt")
		}
		return x509.ParseCertificate(block.Bytes)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in sign response")
	}
	return x509.ParseCertificate(block.Bytes)
}

func (c *Client) endpointURL(path string) string { return c.endpoint + path }
func (c *Client) audience(path string) string    { return c.endpointURL(path) }

func rootPool(rootCert []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(rootCert); !ok {
		return nil, fmt.Errorf("no certificates found in root CA PEM")
	}
	return pool, nil
}

func csrSubjectAndSANs(csrPEM []byte) (string, []string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", nil, fmt.Errorf("CSR is not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", nil, fmt.Errorf("invalid CSR signature: %w", err)
	}
	subject := csr.Subject.CommonName
	sans := make([]string, 0, len(csr.DNSNames)+len(csr.EmailAddresses)+len(csr.IPAddresses)+len(csr.URIs))
	sans = append(sans, csr.DNSNames...)
	sans = append(sans, csr.EmailAddresses...)
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range csr.URIs {
		sans = append(sans, uri.String())
	}
	return subject, sans, nil
}

func normalizeSerial(serial string) string {
	s := strings.TrimSpace(serial)
	if s == "" || strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return s
	}
	// Store serials are hexadecimal. Prefix them so step-ca does not interpret a
	// digit-only hex string as decimal.
	return "0x" + s
}
