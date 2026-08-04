package syslog

import (
	"bufio"
	"net"
	"sync"
	"testing"
	"time"
)

func TestPoolForward(t *testing.T) {
	received := make(chan []byte, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		received <- []byte(line)
	}()

	pool := NewCollectorPool(ln.Addr().String(), 5, time.Second)
	defer pool.Close()

	if err := pool.Forward([]byte("hello world")); err != nil {
		t.Fatalf("forward: %v", err)
	}

	select {
	case b := <-received:
		if string(b) != "hello world\n" {
			t.Fatalf("expected 'hello world\\n', got %q", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("collector did not receive message")
	}
}

func TestPoolReconnect(t *testing.T) {
	received := make(chan []byte, 10)

	startServerOn := func(addr string) net.Listener {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					line, _ := bufio.NewReader(c).ReadString('\n')
					received <- []byte(line)
				}(conn)
			}
		}()
		return l
	}

	startServer := func() net.Listener {
		return startServerOn("127.0.0.1:0")
	}

	ln := startServer()
	addr := ln.Addr().String()
	pool := NewCollectorPool(addr, 5, 50*time.Millisecond)

	// First forward succeeds
	if err := pool.Forward([]byte("first")); err != nil {
		t.Fatalf("first forward: %v", err)
	}
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("first message not received")
	}

	// Kill the collector AND drop pooled connections so the next write cannot
	// silently buffer into a dead socket.
	ln.Close()
	pool.Close()

	// Forward now fails (dial refused)
	if err := pool.Forward([]byte("lost")); err == nil {
		t.Fatal("expected forward to fail while collector is down")
	}

	// Restart collector on the same address; forward again succeeds
	ln = startServerOn(addr)
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := pool.Forward([]byte("second"))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("forward never recovered: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case b := <-received:
		if string(b) != "second\n" {
			t.Fatalf("expected 'second\\n', got %q", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("collector did not receive recovered message")
	}
}

func TestPoolHealthyFalse(t *testing.T) {
	// Collector on a closed port
	pool := NewCollectorPool("127.0.0.1:1", 5, time.Second)
	defer pool.Close()

	// Initial state optimistic
	if !pool.Healthy() {
		t.Log("initial healthy state is false")
	}

	// Trigger a dial failure
	_ = pool.Forward([]byte("x"))

	if pool.Healthy() {
		t.Fatal("expected unhealthy after failed dial")
	}
}

func TestPoolConcurrency(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	var count int
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					if _, err := br.ReadString('\n'); err != nil {
						break
					}
					mu.Lock()
					count++
					mu.Unlock()
				}
			}(conn)
		}
	}()

	pool := NewCollectorPool(ln.Addr().String(), 10, time.Second)
	defer pool.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if err := pool.Forward([]byte("msg")); err != nil {
				t.Errorf("forward %d: %v", n, err)
			}
		}(i)
	}
	wg.Wait()

	mu.Lock()
	got := count
	mu.Unlock()
	if got != 50 {
		t.Fatalf("expected 50 messages received, got %d", got)
	}
}
