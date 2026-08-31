package pki

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrTokenUsed    = errors.New("download token already used")
	ErrTokenExpired = errors.New("download token expired")
	ErrTokenInvalid = errors.New("download token not found")
)

// DownloadToken holds an in-memory cert/key bundle payload.
type DownloadToken struct {
	CertPEM   []byte
	KeyPEM    []byte
	ExpiresAt time.Time
	Used      bool
}

// DownloadManager holds single-use download tokens (10-minute expiry) for
// keygen-issued client bundles. Private keys live only in memory here — never
// on disk or in the DB.
type DownloadManager struct {
	mu       sync.Mutex
	tokens   map[string]*DownloadToken
	done     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func NewDownloadManager() *DownloadManager {
	dm := &DownloadManager{
		tokens: make(map[string]*DownloadToken),
		done:   make(chan struct{}),
	}
	dm.wg.Add(1)
	go dm.cleanup()
	return dm
}

// Create stores a new token and returns its ID.
func (m *DownloadManager) Create(certPEM, keyPEM []byte) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)

	m.mu.Lock()
	m.tokens[token] = &DownloadToken{
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	m.mu.Unlock()
	return token
}

// Consume atomically consumes a token. The stored key bytes are zeroed before
// deletion.
func (m *DownloadManager) Consume(token string) (*DownloadToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	dt, ok := m.tokens[token]
	if !ok {
		return nil, ErrTokenInvalid
	}
	if time.Now().After(dt.ExpiresAt) {
		zero(dt.KeyPEM)
		delete(m.tokens, token)
		return nil, ErrTokenExpired
	}
	if dt.Used {
		return nil, ErrTokenUsed
	}

	result := &DownloadToken{
		CertPEM: append([]byte(nil), dt.CertPEM...),
		KeyPEM:  append([]byte(nil), dt.KeyPEM...),
	}
	zero(dt.KeyPEM)
	delete(m.tokens, token)
	return result, nil
}

// Stop joins the cleanup goroutine. Idempotent.
func (m *DownloadManager) Stop() {
	m.stopOnce.Do(func() {
		close(m.done)
		m.wg.Wait()
	})
}

func (m *DownloadManager) cleanup() {
	defer m.wg.Done()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			for token, dt := range m.tokens {
				if now.After(dt.ExpiresAt) {
					zero(dt.KeyPEM)
					delete(m.tokens, token)
				}
			}
			m.mu.Unlock()
		case <-m.done:
			return
		}
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
