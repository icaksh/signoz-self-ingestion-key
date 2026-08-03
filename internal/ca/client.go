package ca

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
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
	prov, err := NewJWKProvisioner(cfg.ProvisionerName, cfg.ProvisionerKey)
	if err != nil {
		return nil, fmt.Errorf("provisioner: %w", err)
	}
	return &Client{
		endpoint:    cfg.Endpoint,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
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
	token, err := c.provisioner.Token(c.endpoint + "/v1/sign")
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}

	req, err := http.NewRequest("POST", c.endpoint+"/v1/sign", bytes.NewReader(csrPEM))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/pkcs10")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sign failed: status=%d body=%s", resp.StatusCode, string(body))
	}
	return parseCertResponse(resp.Body)
}

// Renew submits a CSR to step-ca for renewal (key change).
func (c *Client) Renew(serial string, csrPEM []byte) (*x509.Certificate, error) {
	token, err := c.provisioner.Token(c.endpoint + "/v1/renew")
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}

	req, err := http.NewRequest("POST", c.endpoint+"/v1/renew", bytes.NewReader(csrPEM))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/pkcs10")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("renew request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("renew failed: status=%d body=%s", resp.StatusCode, string(body))
	}
	return parseCertResponse(resp.Body)
}

// Revoke tells step-ca to revoke a certificate by serial number.
func (c *Client) Revoke(serial, reason string) error {
	token, err := c.provisioner.Token(c.endpoint + "/v1/revoke")
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}

	payload := fmt.Sprintf(`{"serial":"%s","reason":"%s"}`, serial, reason)
	req, err := http.NewRequest("POST", c.endpoint+"/v1/revoke", bytes.NewReader([]byte(payload)))
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
	certPEM, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read cert response: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in sign response")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	return cert, nil
}
