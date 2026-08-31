package syslog

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"testing"
)

func TestOctetCountedFrame(t *testing.T) {
	frame := "<13>1 2026-01-15T10:00:00Z host app 123 ID - hello"
	data := append([]byte(strconv.Itoa(len(frame))), ' ')
	data = append(data, frame...)

	fs := NewFrameScanner(bytes.NewReader(data), 65536)
	got, err := fs.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != frame {
		t.Errorf("got %q, want %q", got, frame)
	}
}

func TestNewlineFallback(t *testing.T) {
	fs := NewFrameScanner(bytes.NewReader([]byte("hello world\n")), 65536)
	got, err := fs.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Errorf("got %q", got)
	}
}

func TestOversizedFrameRejected(t *testing.T) {
	fs := NewFrameScanner(bytes.NewReader([]byte("999999 hello")), 1024)
	_, err := fs.ReadFrame()
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
}

func TestPartialFrame(t *testing.T) {
	fs := NewFrameScanner(bytes.NewReader([]byte("10 abc")), 1024)
	_, err := fs.ReadFrame()
	if !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("err = %v, want ErrInvalidFrame", err)
	}
}

func TestEOF(t *testing.T) {
	fs := NewFrameScanner(bytes.NewReader([]byte{}), 1024)
	if _, err := fs.ReadFrame(); err != io.EOF {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}
