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

	// Token must be deleted from map after consume
	dm.mu.Lock()
	_, exists := dm.tokens[token]
	dm.mu.Unlock()
	if exists {
		t.Fatal("token must be deleted from map after consume")
	}

	// Second consume fails — token is gone
	if _, err := dm.Consume(token); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestDownloadTokenDeletedOnConsume(t *testing.T) {
	dm := NewDownloadManager()
	defer dm.Stop()

	token := dm.Create([]byte("cert-payload"), []byte("key-payload"))

	// Consume — must succeed and delete from map
	if _, err := dm.Consume(token); err != nil {
		t.Fatalf("consume: %v", err)
	}

	dm.mu.Lock()
	_, exists := dm.tokens[token]
	dm.mu.Unlock()
	if exists {
		t.Fatal("token must be deleted immediately, not waiting for cleanup ticker")
	}
}

func TestDownloadTokenExpiredDeletesAndZeroes(t *testing.T) {
	dm := NewDownloadManager()
	defer dm.Stop()

	keyBytes := []byte("secret-key-material")
	origKey := string(keyBytes)
	token := dm.Create([]byte("cert"), keyBytes)

	// Force expiry
	dm.mu.Lock()
	dm.tokens[token].ExpiresAt = time.Now().Add(-time.Minute)
	dm.mu.Unlock()

	_, err := dm.Consume(token)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}

	// Key bytes must be zeroed
	if string(keyBytes) == origKey {
		t.Fatal("key bytes must be zeroed on expiry consume")
	}

	// Token must be removed
	dm.mu.Lock()
	_, exists := dm.tokens[token]
	dm.mu.Unlock()
	if exists {
		t.Fatal("expired token must be deleted")
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
