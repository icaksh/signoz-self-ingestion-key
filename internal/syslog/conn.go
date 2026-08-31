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
	if idleTimeout <= 0 {
		idleTimeout = 300 * time.Second
	}

	// Complete the handshake explicitly so failures are observable.
	if err := conn.HandshakeContext(context.Background()); err != nil {
		log.Printf("[syslog] TLS handshake error: %v", err)
		return
	}

	connState := conn.ConnectionState()
	if len(connState.PeerCertificates) == 0 {
		log.Println("[syslog] connection without client cert — rejected at TLS layer")
		return
	}
	leafCert := connState.PeerCertificates[0]
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

	if err := s.store.UpdateLastSeen(context.Background(), fingerprint); err != nil {
		log.Printf("[syslog] update last_seen: %v", err)
	}

	release, ok := s.acquireConnSlot(tenant.ID)
	if !ok {
		log.Printf("[syslog] connection rejected: max connections per tenant tenant=%s", tenant.Name)
		return
	}
	defer release()

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

		frameLen := int64(len(frame))
		if dec := s.limiter.AllowRPS(context.Background(), tenant.ID); !dec.Allowed {
			log.Printf("[syslog] frame rejected: tenant=%s reason=%s", tenant.Name, dec.Reason)
			s.store.RecordUsage(tenant.ID, "syslog", 429, frameLen)
			return
		}
		if dec := s.limiter.AllowBytes(context.Background(), tenant.ID, frameLen); !dec.Allowed {
			log.Printf("[syslog] frame rejected: tenant=%s reason=%s", tenant.Name, dec.Reason)
			s.store.RecordUsage(tenant.ID, "syslog", 429, frameLen)
			return
		}

		stamped := StampSyslogMessage(frame, tenant.ID, tenant.Name)

		if err := s.pool.Forward(stamped); err != nil {
			log.Printf("[syslog] forward error tenant=%s: %v", tenant.Name, err)
			s.store.RecordUsage(tenant.ID, "syslog", 502, frameLen)
			return
		}

		s.store.RecordUsage(tenant.ID, "syslog", 200, frameLen)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
