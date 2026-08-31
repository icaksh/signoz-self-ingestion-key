// Package auth owns credential resolution and admin session/CSRF security.
package auth

import (
	"context"

	"github.com/sismedika/otlp-proxy/internal/store"
)

// CredentialType identifies the credential kind.
type CredentialType int

const (
	CredTypeAPIKey CredentialType = iota
	CredTypeCertFingerprint
)

// Credential identifies a tenant via an API key or a client-cert fingerprint.
type Credential struct {
	Type  CredentialType
	Value string
}

// NewAPIKeyCredential builds an API-key credential.
func NewAPIKeyCredential(key string) Credential {
	return Credential{Type: CredTypeAPIKey, Value: key}
}

// NewCertCredential builds a certificate-fingerprint credential.
func NewCertCredential(fingerprint string) Credential {
	return Credential{Type: CredTypeCertFingerprint, Value: fingerprint}
}

// Gateway resolves credentials to tenants. Both the HTTP proxy (API keys) and
// the syslog mTLS listener (cert fingerprints) authenticate through it.
type Gateway struct {
	store *store.Store
}

func NewGateway(st *store.Store) *Gateway {
	return &Gateway{store: st}
}

// ResolveTenant returns the tenant for a credential, or (nil, nil) when the
// credential is unknown, revoked, or the tenant is inactive.
func (g *Gateway) ResolveTenant(ctx context.Context, cred Credential) (*store.Tenant, error) {
	switch cred.Type {
	case CredTypeAPIKey:
		return g.store.LookupTenantByKey(ctx, cred.Value)
	case CredTypeCertFingerprint:
		return g.store.LookupTenantByFingerprint(ctx, cred.Value)
	default:
		return nil, nil
	}
}
