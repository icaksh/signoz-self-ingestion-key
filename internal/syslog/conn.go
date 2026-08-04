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

	// Per-tenant concurrent-connection cap
	release, ok := s.acquireConnSlot(tenant.ID)
	if !ok {
		log.Printf("[syslog] connection rejected: max connections per tenant tenant=%s", tenant.Name)
		return
	}
	defer release()

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

		// Per-frame rate limiting (replaces connect-time AllowRPS)
		frameLen := int64(len(frame))
		if dec := s.limiter.AllowRPS(tenant.ID); !dec.Allowed {
			log.Printf("[syslog] frame rejected: tenant=%s reason=%s", tenant.Name, dec.Reason)
			s.store.RecordUsage(tenant.ID, "syslog", 429, frameLen)
			return
		}
		if dec := s.limiter.AllowBytes(tenant.ID, frameLen); !dec.Allowed {
			log.Printf("[syslog] frame rejected: tenant=%s reason=%s", tenant.Name, dec.Reason)
			s.store.RecordUsage(tenant.ID, "syslog", 429, frameLen)
			return
		}

		stamped := StampSyslogMessage(frame, tenant.ID)

		if err := s.pool.Forward(stamped); err != nil {
			log.Printf("[syslog] forward error tenant=%s: %v", tenant.Name, err)
			s.store.RecordUsage(tenant.ID, "syslog", 502, frameLen)
			return
		}

		// Account the original frame bytes (pre-stamping), consistent with OTLP path
		s.store.RecordUsage(tenant.ID, "syslog", 200, frameLen)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
