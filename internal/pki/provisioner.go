package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// JWKProvisioner signs short-lived JWK provisioner JWTs for step-ca API auth.
// The proxy receives only this provisioner key; it never receives CA signing keys.
type JWKProvisioner struct {
	name    string
	key     jose.JSONWebKey
	rootSHA string
	alg     jose.SignatureAlgorithm
}

func NewJWKProvisioner(name string, rawJWK []byte, rootCert []byte) (*JWKProvisioner, error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(rawJWK, &jwk); err != nil {
		return nil, fmt.Errorf("parse JWK: %w", err)
	}
	if jwk.Key == nil {
		return nil, fmt.Errorf("JWK has no key material")
	}
	if _, ok := jwk.Key.(crypto.Signer); !ok {
		return nil, fmt.Errorf("JWK key is not a signer (private key required)")
	}
	alg, err := signatureAlgorithm(jwk)
	if err != nil {
		return nil, err
	}
	fp, err := rootFingerprint(rootCert)
	if err != nil {
		return nil, fmt.Errorf("root fingerprint: %w", err)
	}
	return &JWKProvisioner{name: name, key: jwk, rootSHA: fp, alg: alg}, nil
}

// Token returns a compact JWK provisioner JWT valid for 5 minutes.
func (p *JWKProvisioner) Token(audience, subject string, sans []string) (string, error) {
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if p.key.KeyID != "" {
		opts.WithHeader("kid", p.key.KeyID)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: p.alg, Key: p.key}, opts)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}

	now := time.Now().UTC()
	claims := jwt.Claims{
		Issuer:    p.name,
		Audience:  jwt.Audience{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
		Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
		ID:        fmt.Sprintf("%x", randomBytes(16)),
	}
	if subject != "" {
		claims.Subject = subject
	}

	payload := struct {
		jwt.Claims
		SHA  string   `json:"sha,omitempty"`
		SANs []string `json:"sans,omitempty"`
	}{
		Claims: claims,
		SHA:    p.rootSHA,
		SANs:   sans,
	}

	token, err := jwt.Signed(signer).Claims(payload).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return token, nil
}

func (p *JWKProvisioner) RootFingerprint() string { return p.rootSHA }

func signatureAlgorithm(jwk jose.JSONWebKey) (jose.SignatureAlgorithm, error) {
	if jwk.Algorithm != "" {
		alg := jose.SignatureAlgorithm(jwk.Algorithm)
		switch alg {
		case jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
			return alg, nil
		}
		return "", fmt.Errorf("unsupported JWK signature algorithm %q", jwk.Algorithm)
	}
	// step-ca's default JWK provisioner is EC P-256, but derive a safe fallback
	// from the actual key type instead of hard-coding ES256 for imported keys.
	switch k := jwk.Key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return jose.ES256, nil
		case 384:
			return jose.ES384, nil
		case 521:
			return jose.ES512, nil
		}
	case ed25519.PrivateKey:
		return jose.EdDSA, nil
	case *rsa.PrivateKey:
		return jose.RS256, nil
	}
	return "", fmt.Errorf("unsupported JWK private key type %T", jwk.Key)
}

func rootFingerprint(rootCert []byte) (string, error) {
	block, _ := pem.Decode(rootCert)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("root certificate is not PEM encoded")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse root certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}
