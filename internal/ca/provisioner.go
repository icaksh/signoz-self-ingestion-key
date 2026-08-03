package ca

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// JWKProvisioner signs short-lived provisioner JWTs for step-ca API auth.
type JWKProvisioner struct {
	name string
	key  jose.JSONWebKey
}

func NewJWKProvisioner(name string, rawJWK []byte) (*JWKProvisioner, error) {
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
	return &JWKProvisioner{name: name, key: jwk}, nil
}

// Token returns a compact JWT valid for 5 minutes.
func (p *JWKProvisioner) Token(audience string) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}

	now := time.Now()
	claims := jwt.Claims{
		Issuer:    p.name,
		Audience:  jwt.Audience{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
		ID:        fmt.Sprintf("%x", randomBytes(16)),
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return token, nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}
