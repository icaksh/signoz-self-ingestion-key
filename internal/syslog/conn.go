package syslog

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/sismedika/otlp-proxy/internal/auth"
)

func (s *Server) handleConnection(conn *tls.Conn) {
	defer conn.Close()

	idleTimeout := s.cfg.ConnIdleTimeout

	// Complete the handshake explicitly so failures are observable
	if err := conn.HandshakeContext(context.Background()); err != nil {
		log.Printf("[syslog] TLS handshake error: %v", err)
		return
	}

	connState := conn.ConnectionState()
	peerCerts := connState.PeerCertificates
	if len(peerCerts) == 0 {
		log.Println("[syslog] connection without client cert — rejected at TLS layer")
		return
	}
	leafCert := peerCerts[0]
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(leafCert.Raw))

	tenant, err := s.gateway.ResolveTenant(context.Background(), auth.NewCertCredential(fingerprint))
	if err != nil {
		log.Printf("[syslog] tenant lookup error: %v", err)
		return
	}
	if tenant == nil {
		cert, _ := s.store.LookupCertificateByFingerprint(context.Background(), fingerprint)
		switch {
		case cert != nil && cert.RevokedAt.Valid:
			log.Printf("[syslog] connection rejected: cert revoked cn=%s fingerprint=%s", leafCert.Subject.CommonName, fingerprint)
		case cert != nil:
			log.Printf("[syslog] connection rejected: tenant inactive cn=%s fingerprint=%s", leafCert.Subject.CommonName, fingerprint)
		default:
			log.Printf("[syslog] connection rejected: unknown cert fingerprint=%s cn=%s", fingerprint, leafCert.Subject.CommonName)
		}
		return
	}

	// Update last seen (best-effort)
	if err := s.store.UpdateLastSeen(context.Background(), fingerprint); err != nil {
		log.Printf("[syslog] update last_seen: %v", err)
	}

	// Rate limit: each accepted connection consumes one token for the tenant
	if dec := s.limiter.AllowRPS(tenant.ID); !dec.Allowed {
		log.Printf("[syslog] connection rejected: rate limited tenant_id=%d reason=%s", tenant.ID, dec.Reason)
		return
	}

	// Refuse new connections when the collector is unreachable (backpressure)
	if !s.pool.Healthy() {
		log.Println("[syslog] collector unavailable, refusing connection")
		return
	}

	log.Printf("[syslog] connection accepted: tenant=%s cn=%s", tenant.Name, leafCert.Subject.CommonName)

	scanner := NewFrameScanner(conn, s.cfg.MaxFrameBytes)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))

		frame, err := scanner.ReadFrame()
		if err != nil {
			if err != io.EOF && !isTimeout(err) {
				log.Printf("[syslog] read error tenant=%s: %v", tenant.Name, err)
			}
			return
		}

		stamped := StampSyslogMessage(frame, tenant.ID)

		if err := s.pool.Forward(stamped); err != nil {
			log.Printf("[syslog] forward error tenant=%s: %v", tenant.Name, err)
			return
		}
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
