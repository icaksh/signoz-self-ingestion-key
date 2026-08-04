package syslog

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sismedika/otlp-proxy/internal/auth"
	"github.com/sismedika/otlp-proxy/internal/ratelimit"
	"github.com/sismedika/otlp-proxy/internal/store"
)

type Config struct {
	Addr              string
	ServerCertFile    string
	ServerKeyFile     string
	ClientCAFile      string
	MaxFrameBytes     int
	MaxConnections    int
	MaxConnsPerTenant int
	ConnIdleTimeout   time.Duration
	CollectorAddr     string
}

type Server struct {
	cfg          Config
	store        *store.Store
	gateway      *auth.Gateway
	limiter      *ratelimit.Limiter
	tlsConf      *tls.Config
	pool         *CollectorPool
	wg           sync.WaitGroup
	connSem      chan struct{}
	connCounts   map[int64]int
	connCountsMu sync.Mutex
	listenerMu   sync.RWMutex
	listener     net.Listener
}

// Addr returns the bound listener address (after ListenAndServe started).
func (s *Server) Addr() net.Addr {
	s.listenerMu.RLock()
	defer s.listenerMu.RUnlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

func NewServer(cfg Config, st *store.Store, gw *auth.Gateway, lim *ratelimit.Limiter) (*Server, error) {
	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA file: %w", err)
	}
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates found in client CA file %s", cfg.ClientCAFile)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		MinVersion:   tls.VersionTLS12,
	}

	if cfg.MaxConnsPerTenant <= 0 {
		cfg.MaxConnsPerTenant = 50
	}

	pool := NewCollectorPool(cfg.CollectorAddr, 10, 30*time.Second)

	return &Server{
		cfg:        cfg,
		store:      st,
		gateway:    gw,
		limiter:    lim,
		tlsConf:    tlsConf,
		pool:       pool,
		connSem:    make(chan struct{}, cfg.MaxConnections),
		connCounts: make(map[int64]int),
	}, nil
}

// acquireConnSlot attempts to acquire a per-tenant connection slot. Returns
// a release function or false if at capacity.
func (s *Server) acquireConnSlot(tenantID int64) (release func(), ok bool) {
	s.connCountsMu.Lock()
	defer s.connCountsMu.Unlock()

	max := s.cfg.MaxConnsPerTenant
	if max <= 0 {
		max = 50
	}
	if s.connCounts[tenantID] >= max {
		return nil, false
	}
	s.connCounts[tenantID]++

	once := sync.Once{}
	release = func() {
		once.Do(func() {
			s.connCountsMu.Lock()
			s.connCounts[tenantID]--
			if s.connCounts[tenantID] <= 0 {
				delete(s.connCounts, tenantID)
			}
			s.connCountsMu.Unlock()
		})
	}
	return release, true
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	listener, err := tls.Listen("tcp", s.cfg.Addr, s.tlsConf)
	if err != nil {
		return fmt.Errorf("syslog listen: %w", err)
	}
	defer listener.Close()
	s.listenerMu.Lock()
	s.listener = listener
	s.listenerMu.Unlock()

	log.Printf("[syslog] listening on %s (mTLS)", s.cfg.Addr)

	go func() {
		<-ctx.Done()
		log.Println("[syslog] shutting down listener")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				s.wg.Wait()
				s.pool.Close()
				return nil
			default:
				log.Printf("[syslog] accept error: %v", err)
				continue
			}
		}

		select {
		case s.connSem <- struct{}{}:
			s.wg.Add(1)
			go func() {
				defer func() { <-s.connSem }()
				defer s.wg.Done()
				s.handleConnection(conn.(*tls.Conn))
			}()
		default:
			log.Println("[syslog] connection limit reached, rejecting")
			conn.Close()
		}
	}
}
