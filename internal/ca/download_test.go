package ca

import (
	"errors"
	"testing"
	"time"
)

func TestDownloadTokenLifecycle(t *testing.T) {
	dm := NewDownloadManager()
	defer dm.Stop()

	token := dm.Create([]byte("cert"), []byte("key"))
	if len(token) != 32 {
		t.Fatalf("expected 32-hex token, got %q", token)
	}

	// First consume succeeds
	dt, err := dm.Consume(token)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if string(dt.CertPEM) != "cert" || string(dt.KeyPEM) != "key" {
		t.Fatal("token payload mismatch")
	}

	// Second consume fails — single use
	if _, err := dm.Consume(token); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("expected ErrTokenUsed, got %v", err)
	}
}

func TestDownloadTokenInvalid(t *testing.T) {
	dm := NewDownloadManager()
	defer dm.Stop()

	if _, err := dm.Consume("ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestDownloadTokenExpired(t *testing.T) {
	dm := NewDownloadManager()
	defer dm.Stop()

	token := dm.Create([]byte("c"), nil)

	// Force expiry
	dm.mu.Lock()
	dm.tokens[token].ExpiresAt = time.Now().Add(-time.Minute)
	dm.mu.Unlock()

	if _, err := dm.Consume(token); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}
