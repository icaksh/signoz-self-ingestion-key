package syslog

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestOctetCountingSingleFrame(t *testing.T) {
	fs := NewFrameScanner(strings.NewReader("5 hello"), 65536)
	frame, err := fs.ReadFrame()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(frame) != "hello" {
		t.Fatalf("expected 'hello', got %q", frame)
	}
}

func TestOctetCountingMultipleFrames(t *testing.T) {
	fs := NewFrameScanner(strings.NewReader("5 hello5 world"), 65536)
	f1, err := fs.ReadFrame()
	if err != nil {
		t.Fatalf("frame 1: %v", err)
	}
	f2, err := fs.ReadFrame()
	if err != nil {
		t.Fatalf("frame 2: %v", err)
	}
	if string(f1) != "hello" || string(f2) != "world" {
		t.Fatalf("expected 'hello','world', got %q,%q", f1, f2)
	}
	_, err = fs.ReadFrame()
	if err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

// slowByteReader returns one byte per Read to simulate TCP fragmentation.
type slowByteReader struct {
	data []byte
	pos  int
}

func (r *slowByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

func TestSplitFrameAcrossReads(t *testing.T) {
	// "12 Hello World!" — payload is 12 bytes, delivered one byte at a time
	fs := NewFrameScanner(&slowByteReader{data: []byte("12 Hello World!")}, 65536)
	frame, err := fs.ReadFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(frame) != "Hello World!" {
		t.Fatalf("expected 'Hello World!', got %q", string(frame))
	}
}

func TestOversizedDeclaredLength(t *testing.T) {
	fs := NewFrameScanner(strings.NewReader("999999 oversized"), 65536)
	_, err := fs.ReadFrame()
	if err == nil {
		t.Fatal("expected error for oversized declared length")
	}
	if err != ErrFrameTooLarge {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestBogusLengthPrefix(t *testing.T) {
	// Digit-starting but non-numeric prefix → invalid frame error
	fs := NewFrameScanner(strings.NewReader("5x2 hello"), 65536)
	_, err := fs.ReadFrame()
	if err == nil {
		t.Fatal("expected error for bogus length prefix")
	}
	if !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected ErrInvalidFrame, got %v", err)
	}
}

func TestNewlineDelimitedFallback(t *testing.T) {
	fs := NewFrameScanner(strings.NewReader("hello\n world\n"), 65536)
	f1, err := fs.ReadFrame()
	if err != nil {
		t.Fatalf("frame 1: %v", err)
	}
	f2, err := fs.ReadFrame()
	if err != nil {
		t.Fatalf("frame 2: %v", err)
	}
	if string(f1) != "hello" || string(f2) != " world" {
		t.Fatalf("expected 'hello',' world', got %q,%q", f1, f2)
	}
}

func TestNewlineWithoutNewlineAtEOF(t *testing.T) {
	fs := NewFrameScanner(strings.NewReader("partial"), 65536)
	frame, err := fs.ReadFrame()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(frame) != "partial" {
		t.Fatalf("expected 'partial', got %q", frame)
	}
}

func TestPartialFrameAtEOF(t *testing.T) {
	// Declares 100 bytes but stream ends at 30
	fs := NewFrameScanner(strings.NewReader("100 "+strings.Repeat("x", 30)), 65536)
	_, err := fs.ReadFrame()
	if err == nil {
		t.Fatal("expected error for partial frame")
	}
}

func TestEmptyFrame(t *testing.T) {
	fs := NewFrameScanner(strings.NewReader("0 "), 65536)
	frame, err := fs.ReadFrame()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(frame) != 0 {
		t.Fatalf("expected empty frame, got %q", frame)
	}
}

func TestLeadingZerosInLength(t *testing.T) {
	fs := NewFrameScanner(strings.NewReader("005 hello"), 65536)
	frame, err := fs.ReadFrame()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(frame) != "hello" {
		t.Fatalf("expected 'hello', got %q", frame)
	}
}

func TestOversizedNoLargeAllocation(t *testing.T) {
	// Structural proof the oversized body is never read/allocated: the scanner
	// must reject the frame before consuming the declared body, so a reader
	// that errors on the second Read never gets touched for the body.
	readCount := 0
	guarded := &funcReader{
		read: func(p []byte) (int, error) {
			readCount++
			if readCount > 1 {
				t.Fatal("scanner read beyond the length prefix for an oversized frame")
			}
			copy(p, "999999 ")
			return 7, nil
		},
	}
	fs := NewFrameScanner(guarded, 65536)
	_, err := fs.ReadFrame()
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
	_ = bytes.NewReader
}

type funcReader struct {
	read func(p []byte) (int, error)
}

func (r *funcReader) Read(p []byte) (int, error) { return r.read(p) }
