package syslog

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestForwardUsesOctetCountedFraming asserts messages are sent to the
// collector as "<len> <body>" rather than newline-delimited, so a body
// containing an embedded newline is not split into fragments.
func TestForwardUsesOctetCountedFraming(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	received := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		lenStr, err := r.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(lenStr))
		if err != nil {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return
		}
		received <- buf
	}()

	pool := NewCollectorPool(ln.Addr().String(), 1, time.Second)
	defer pool.Close()

	msg := []byte("<13>1 2026-01-15T10:00:00Z host app 1 ID - line one\nline two")
	if err := pool.Forward(msg); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-received:
		if string(got) != string(msg) {
			t.Errorf("body mismatch:\ngot:  %q\nwant: %q", got, msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for forwarded frame")
	}
}
