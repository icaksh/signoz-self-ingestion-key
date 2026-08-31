package syslog

import (
	"net"
	"strconv"
	"sync"
	"time"
)

// CollectorPool manages a small pool of plain TCP connections to the local
// OTel collector. When the collector is unreachable, Forward returns an error
// and Healthy() returns false so the server stops accepting new connections
// (backpressure instead of unbounded buffering).
type CollectorPool struct {
	addr     string
	maxConns int
	backoff  time.Duration
	mu       sync.Mutex
	conns    []*poolConn
	healthy  bool
}

type poolConn struct {
	conn net.Conn
	dead bool
}

func NewCollectorPool(addr string, maxConns int, backoff time.Duration) *CollectorPool {
	return &CollectorPool{
		addr:     addr,
		maxConns: maxConns,
		backoff:  backoff,
		healthy:  true, // optimistic until a dial fails
	}
}

func (p *CollectorPool) getConn() (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, pc := range p.conns {
		if pc != nil && !pc.dead {
			conn := pc.conn
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			return conn, nil
		}
	}

	conn, err := net.DialTimeout("tcp", p.addr, 5*time.Second)
	if err != nil {
		p.healthy = false
		return nil, err
	}
	p.healthy = true
	return conn, nil
}

func (p *CollectorPool) returnConn(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.conns) < p.maxConns {
		p.conns = append(p.conns, &poolConn{conn: conn})
	} else {
		closeGracefully(conn)
	}
}

// closeGracefully flushes queued data (FIN after writes) instead of RST.
func closeGracefully(conn net.Conn) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return
	}
	_ = tcp.CloseWrite()
	_ = tcp.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 32)
	for {
		if _, err := tcp.Read(buf); err != nil {
			break
		}
	}
	conn.Close()
}

func (p *CollectorPool) markDead(conn net.Conn) {
	conn.Close()
}

// Forward writes a stamped frame to the collector using RFC 5425
// octet-counted framing (<byte-length> <message>). Newline-delimited framing
// is not used here: a message body containing a literal newline (e.g. a
// multi-line stack trace forwarded verbatim by rsyslog) would otherwise be
// split into headerless fragments by the collector's TCP input, so the frame
// boundary must be length-prefixed rather than content-dependent. On write
// failure it retries once with a fresh connection.
func (p *CollectorPool) Forward(frame []byte) error {
	prefix := strconv.Itoa(len(frame)) + " "
	payload := make([]byte, 0, len(prefix)+len(frame))
	payload = append(payload, prefix...)
	payload = append(payload, frame...)

	conn, err := p.getConn()
	if err != nil {
		return err
	}

	if _, err := conn.Write(payload); err != nil {
		p.markDead(conn)
		conn2, err2 := p.getConn()
		if err2 != nil {
			return err2
		}
		if _, err := conn2.Write(payload); err != nil {
			p.markDead(conn2)
			return err
		}
		p.returnConn(conn2)
		return nil
	}

	p.returnConn(conn)
	return nil
}

// Healthy reports whether the collector is currently reachable.
func (p *CollectorPool) Healthy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.healthy
}

// Close closes all pooled connections.
func (p *CollectorPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pc := range p.conns {
		if pc != nil && !pc.dead {
			pc.conn.Close()
		}
	}
	p.conns = nil
	p.healthy = false
	return nil
}
