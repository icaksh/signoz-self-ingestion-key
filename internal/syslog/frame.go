package syslog

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
)

var (
	ErrFrameTooLarge = errors.New("syslog: frame exceeds maximum allowed size")
	ErrInvalidFrame  = errors.New("syslog: invalid frame")
)

// FrameScanner reads RFC 5425 octet-counted frames from a stream, falling
// back to newline-delimited framing when the first byte is not a digit.
// Oversized declared lengths are rejected before the body is allocated.
type FrameScanner struct {
	reader        *bufio.Reader
	maxFrameBytes int
}

func NewFrameScanner(r io.Reader, maxFrameBytes int) *FrameScanner {
	return &FrameScanner{
		reader:        bufio.NewReader(r),
		maxFrameBytes: maxFrameBytes,
	}
}

func (fs *FrameScanner) ReadFrame() ([]byte, error) {
	b, err := fs.reader.Peek(1)
	if err != nil {
		return nil, err // io.EOF or read error
	}
	if b[0] >= '0' && b[0] <= '9' {
		return fs.readOctetCountedFrame()
	}
	return fs.readNewlineFrame()
}

func (fs *FrameScanner) readOctetCountedFrame() ([]byte, error) {
	lenStr, err := fs.reader.ReadString(' ')
	if err != nil {
		return nil, fmt.Errorf("%w: reading length prefix: %v", ErrInvalidFrame, err)
	}
	lenStr = lenStr[:len(lenStr)-1] // strip trailing space

	declaredLen, err := strconv.Atoi(lenStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid length prefix %q", ErrInvalidFrame, lenStr)
	}
	if declaredLen > fs.maxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	if declaredLen < 0 {
		return nil, fmt.Errorf("%w: negative length %d", ErrInvalidFrame, declaredLen)
	}

	buf := make([]byte, declaredLen)
	if _, err := io.ReadFull(fs.reader, buf); err != nil {
		return nil, fmt.Errorf("%w: reading frame body: %v", ErrInvalidFrame, err)
	}
	return buf, nil
}

func (fs *FrameScanner) readNewlineFrame() ([]byte, error) {
	line, err := fs.reader.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, err
	}
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	return line, nil
}
