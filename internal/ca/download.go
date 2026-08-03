package ca

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

type DownloadToken struct {
	CertPEM   []byte
	KeyPEM    []byte
	ExpiresAt time.Time
	Used      bool
}

// DownloadManager holds single-use download tokens (10-minute expiry) for
// keygen-issued client bundles. Private keys live only in memory here —
// never on disk or in the DB.
type DownloadManager struct {
	mu     sync.Mutex
	tokens map[string]*DownloadToken
	done   chan struct{}
}

func NewDownloadManager() *DownloadManager {
	dm := &DownloadManager{
		tokens: make(map[string]*DownloadToken),
		done:   make(chan struct{}),
	}
	go dm.cleanup()
	return dm
}

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

func (m *DownloadManager) Consume(token string) (*DownloadToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	dt, ok := m.tokens[token]
	if !ok {
		return nil, ErrTokenInvalid
	}
	if time.Now().After(dt.ExpiresAt) {
		delete(m.tokens, token)
		return nil, ErrTokenExpired
	}
	if dt.Used {
		return nil, ErrTokenUsed
	}
	dt.Used = true
	return dt, nil
}

func (m *DownloadManager) Stop() {
	close(m.done)
}

func (m *DownloadManager) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			for token, dt := range m.tokens {
				if now.After(dt.ExpiresAt) {
					delete(m.tokens, token)
				}
			}
			m.mu.Unlock()
		case <-m.done:
			return
		}
	}
}
