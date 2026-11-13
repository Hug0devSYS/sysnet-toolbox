package logrec

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
)

// MaxLineBytes is the longest line kept; longer lines are truncated.
const MaxLineBytes = 64 << 10

// Open opens a log file ("-" is stdin), transparently decompressing gzip
// (detected by its magic bytes, so rotated "syslog.2.gz" files work).
// The returned closer must be closed by the caller.
func Open(path string, stdin io.Reader) (io.Reader, io.Closer, error) {
	var r io.Reader
	var c io.Closer = io.NopCloser(nil)
	if path == "-" {
		r = stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		st, err := f.Stat()
		if err == nil && st.IsDir() {
			f.Close()
			return nil, nil, fmt.Errorf("%s: is a directory", path)
		}
		r, c = f, f
	}
	br := bufio.NewReaderSize(r, 256<<10)
	magic, _ := br.Peek(2)
	if bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		zr, err := gzip.NewReader(br)
		if err != nil {
			c.Close()
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		zr.Multistream(true)
		return zr, multiCloser{zr, c}, nil
	}
	return br, c, nil
}

type multiCloser []io.Closer

func (m multiCloser) Close() error {
	var errs []error
	for _, c := range m {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ReadLines calls fn for every line of r (without the line terminator).
// Lines longer than MaxLineBytes are truncated and counted in the result.
// It stops early and returns fn's error when fn fails.
func ReadLines(r io.Reader, fn func(line string) error) (truncated int, err error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 256<<10)
	}
	var long []byte // pending prefix of a line longer than the buffer
	overflow := false
	appendCapped := func(b []byte) {
		if overflow {
			return
		}
		room := MaxLineBytes - len(long)
		if len(b) > room {
			b, overflow = b[:room], true
		}
		long = append(long, b...)
	}
	for {
		chunk, rerr := br.ReadSlice('\n')
		if errors.Is(rerr, bufio.ErrBufferFull) {
			appendCapped(chunk)
			continue
		}
		var line []byte
		if long == nil && len(chunk) <= MaxLineBytes+2 {
			line = chunk
		} else {
			appendCapped(bytes.TrimRight(chunk, "\r\n"))
			line = long
			if overflow {
				truncated++
			}
			long, overflow = nil, false
		}
		line = bytes.TrimRight(line, "\r\n")
		if len(line) > 0 || rerr == nil {
			if ferr := fn(string(line)); ferr != nil {
				return truncated, ferr
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return truncated, nil
			}
			return truncated, rerr
		}
	}
}
