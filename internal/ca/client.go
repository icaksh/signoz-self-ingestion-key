package ca

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

// Client is a minimal step-ca REST API client. It never holds CA keys —
// it authenticates with short-lived provisioner JWTs.
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
	transport := &http.Transport{}
	if pool, err := rootPool(cfg.RootCert); err == nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &Client{
		endpoint:    cfg.Endpoint,
		httpClient:  &http.Client{Timeout: 30 * time.Second, Transport: transport},
		provisioner: prov,
		rootCert:    cfg.RootCert,
		lifetime:    cfg.Lifetime,
	}, nil
}

// RootCert returns the CA root certificate PEM (for bundle generation).
func (c *Client) RootCert() []byte {
	return c.rootCert
}

// Lifetime returns the configured certificate lifetime.
func (c *Client) Lifetime() time.Duration {
	return c.lifetime
}

// Sign submits a CSR to step-ca and returns the issued certificate.
func (c *Client) Sign(csrPEM []byte, lifetime time.Duration) (*x509.Certificate, error) {
	subject, sans := csrSubjectAndSANs(csrPEM)
	token, err := c.provisioner.Token(c.audience("/1.0/sign"), subject, sans)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}

	body, err := json.Marshal(struct {
		CSR         string `json:"csr"`
		OTT         string `json:"ott"`
		Provisioner string `json:"provisioner,omitempty"`
	}{
		CSR:         string(csrPEM),
		OTT:         token,
		Provisioner: c.provisioner.name,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal sign request: %w", err)
	}

	req, err := http.NewRequest("POST", c.endpointURL("/sign"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sign failed: status=%d body=%s", resp.StatusCode, string(body))
	}
	return parseCertResponse(resp.Body)
}

// Renew submits a CSR to step-ca for renewal (key change).
func (c *Client) Renew(serial string, csrPEM []byte) (*x509.Certificate, error) {
	subject, sans := csrSubjectAndSANs(csrPEM)
	token, err := c.provisioner.Token(c.audience("/1.0/renew"), subject, sans)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}

	body, err := json.Marshal(struct {
		CRT string `json:"crt"`
		OTT string `json:"ott"`
	}{
		CRT: string(csrPEM),
		OTT: token,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal renew request: %w", err)
	}

	req, err := http.NewRequest("POST", c.endpointURL("/renew"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("renew request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("renew failed: status=%d body=%s", resp.StatusCode, string(body))
	}
	return parseCertResponse(resp.Body)
}

// Revoke tells step-ca to revoke a certificate by serial number.
func (c *Client) Revoke(serial, reason string) error {
	token, err := c.provisioner.Token(c.audience("/1.0/revoke"), serial, nil)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}

	payload := fmt.Sprintf(`{"serial":"%s","reason":"%s"}`, serial, reason)
	req, err := http.NewRequest("POST", c.endpointURL("/revoke"), bytes.NewReader([]byte(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("revoke request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revoke failed: status=%d body=%s", resp.StatusCode, string(body))
	}
	return nil
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
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse cert: %w", err)
		}
		return cert, nil
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in sign response")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	return cert, nil
}

func (c *Client) endpointURL(path string) string {
	return strings.TrimRight(c.endpoint, "/") + path
}

func (c *Client) audience(path string) string {
	return c.endpointURL(path)
}

func rootPool(rootCert []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(rootCert); !ok {
		return nil, fmt.Errorf("no certificates found in root CA PEM")
	}
	return pool, nil
}

func csrSubjectAndSANs(csrPEM []byte) (string, []string) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return "", nil
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", nil
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
	return subject, sans
}
