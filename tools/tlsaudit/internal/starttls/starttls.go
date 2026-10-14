// Package starttls upgrades plaintext protocol connections to the point
// where the server expects a TLS ClientHello. No credentials are ever sent.
package starttls

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	maxLine  = 4096
	maxLines = 200
)

// Negotiate performs the STARTTLS exchange for proto on conn. The caller
// sets the connection deadline. On success the next bytes on the wire are
// the TLS handshake.
func Negotiate(conn net.Conn, proto string) error {
	// Read byte-by-byte through a 1-byte buffered reader: we must not
	// consume any byte beyond the protocol response, since the TLS
	// handshake follows on the same connection.
	r := &lineReader{r: conn}
	switch proto {
	case "smtp":
		return smtp(conn, r)
	case "imap":
		return imap(conn, r)
	case "pop3":
		return pop3(conn, r)
	case "ftp":
		return ftp(conn, r)
	case "ldap":
		return ldap(conn)
	case "postgres":
		return postgres(conn)
	case "":
		return nil
	}
	return fmt.Errorf("starttls: unsupported protocol %q", proto)
}

type lineReader struct {
	r   io.Reader
	buf [1]byte
}

func (l *lineReader) line() (string, error) {
	var b []byte
	for len(b) < maxLine {
		if _, err := io.ReadFull(l.r, l.buf[:]); err != nil {
			return "", err
		}
		if l.buf[0] == '\n' {
			return strings.TrimRight(string(b), "\r"), nil
		}
		b = append(b, l.buf[0])
	}
	return "", errors.New("starttls: response line too long")
}

// reply reads a (possibly multi-line) SMTP/FTP style reply "ddd-..." / "ddd ...".
func (l *lineReader) reply() (code string, text []string, err error) {
	for i := 0; i < maxLines; i++ {
		s, err := l.line()
		if err != nil {
			return "", nil, err
		}
		if len(s) < 3 {
			return "", nil, fmt.Errorf("starttls: malformed reply %q", s)
		}
		text = append(text, s)
		if len(s) == 3 || s[3] == ' ' {
			return s[:3], text, nil
		}
		if s[3] != '-' {
			return "", nil, fmt.Errorf("starttls: malformed reply %q", s)
		}
	}
	return "", nil, errors.New("starttls: reply too long")
}

func expect(r *lineReader, want, step string) error {
	code, text, err := r.reply()
	if err != nil {
		return fmt.Errorf("starttls %s: %w", step, err)
	}
	if code != want {
		return fmt.Errorf("starttls %s: server replied %q", step, strings.Join(text, " | "))
	}
	return nil
}

func smtp(w io.Writer, r *lineReader) error {
	if err := expect(r, "220", "greeting"); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "EHLO tlsaudit.invalid\r\n"); err != nil {
		return err
	}
	code, text, err := r.reply()
	if err != nil {
		return fmt.Errorf("starttls EHLO: %w", err)
	}
	if code != "250" {
		return fmt.Errorf("starttls EHLO: server replied %q", strings.Join(text, " | "))
	}
	advertised := false
	for _, l := range text {
		if len(l) > 4 && strings.EqualFold(strings.TrimSpace(l[4:]), "STARTTLS") {
			advertised = true
		}
	}
	if !advertised {
		return errors.New("starttls: SMTP server does not advertise STARTTLS")
	}
	if _, err := io.WriteString(w, "STARTTLS\r\n"); err != nil {
		return err
	}
	return expect(r, "220", "STARTTLS")
}

func ftp(w io.Writer, r *lineReader) error {
	if err := expect(r, "220", "greeting"); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "AUTH TLS\r\n"); err != nil {
		return err
	}
	return expect(r, "234", "AUTH TLS")
}

func imap(w io.Writer, r *lineReader) error {
	s, err := r.line()
	if err != nil {
		return fmt.Errorf("starttls greeting: %w", err)
	}
	if !strings.HasPrefix(strings.ToUpper(s), "* OK") {
		return fmt.Errorf("starttls greeting: server replied %q", s)
	}
	if _, err := io.WriteString(w, "a1 STARTTLS\r\n"); err != nil {
		return err
	}
	for i := 0; i < maxLines; i++ {
		s, err := r.line()
		if err != nil {
			return fmt.Errorf("starttls STARTTLS: %w", err)
		}
		if strings.HasPrefix(s, "a1 ") {
			if strings.HasPrefix(strings.ToUpper(s), "A1 OK") {
				return nil
			}
			return fmt.Errorf("starttls STARTTLS: server replied %q", s)
		}
	}
	return errors.New("starttls: no tagged IMAP response")
}

func pop3(w io.Writer, r *lineReader) error {
	s, err := r.line()
	if err != nil {
		return fmt.Errorf("starttls greeting: %w", err)
	}
	if !strings.HasPrefix(s, "+OK") {
		return fmt.Errorf("starttls greeting: server replied %q", s)
	}
	if _, err := io.WriteString(w, "STLS\r\n"); err != nil {
		return err
	}
	if s, err = r.line(); err != nil {
		return fmt.Errorf("starttls STLS: %w", err)
	}
	if !strings.HasPrefix(s, "+OK") {
		return fmt.Errorf("starttls STLS: server replied %q", s)
	}
	return nil
}

// ldapStartTLS is an LDAPv3 ExtendedRequest (messageID 1) for the StartTLS
// OID 1.3.6.1.4.1.1466.20037 (RFC 4511 §4.14).
var ldapStartTLS = append([]byte{0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16}, "1.3.6.1.4.1.1466.20037"...)

func ldap(conn net.Conn) error {
	if _, err := conn.Write(ldapStartTLS); err != nil {
		return err
	}
	br := bufio.NewReaderSize(io.LimitReader(conn, 1<<16), 16)
	// Outer SEQUENCE header: read exactly the message, never beyond it.
	tag, err := br.ReadByte()
	if err != nil {
		return fmt.Errorf("starttls LDAP: %w", err)
	}
	if tag != 0x30 {
		return fmt.Errorf("starttls LDAP: unexpected tag 0x%02x", tag)
	}
	n, err := berLength(br)
	if err != nil {
		return err
	}
	if n > 1<<15 {
		return errors.New("starttls LDAP: response too large")
	}
	// bufio may have read ahead only within the LDAP message as the server
	// sends nothing else before our ClientHello.
	msg := make([]byte, n)
	if _, err := io.ReadFull(br, msg); err != nil {
		return fmt.Errorf("starttls LDAP: %w", err)
	}
	// messageID INTEGER, then [APPLICATION 24] ExtendedResponse whose first
	// element is resultCode ENUMERATED.
	i := bytes.IndexByte(msg, 0x78)
	if i < 0 {
		return errors.New("starttls LDAP: no ExtendedResponse")
	}
	rest := msg[i+1:]
	lr := bufio.NewReader(bytes.NewReader(rest))
	if _, err := berLength(lr); err != nil {
		return err
	}
	b := make([]byte, 3)
	if _, err := io.ReadFull(lr, b); err != nil || b[0] != 0x0a || b[1] != 0x01 {
		return errors.New("starttls LDAP: malformed ExtendedResponse")
	}
	if b[2] != 0 {
		return fmt.Errorf("starttls LDAP: StartTLS refused (resultCode %d)", b[2])
	}
	return nil
}

func berLength(r io.ByteReader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if b < 0x80 {
		return int(b), nil
	}
	k := int(b & 0x7f)
	if k == 0 || k > 3 {
		return 0, errors.New("starttls LDAP: unsupported BER length")
	}
	n := 0
	for ; k > 0; k-- {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		n = n<<8 | int(c)
	}
	return n, nil
}

// postgresSSLRequest is the PostgreSQL SSLRequest message.
var postgresSSLRequest = []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}

func postgres(conn net.Conn) error {
	if _, err := conn.Write(postgresSSLRequest); err != nil {
		return err
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		return fmt.Errorf("starttls postgres: %w", err)
	}
	if b[0] != 'S' {
		return fmt.Errorf("starttls postgres: server refused SSL (%q)", b[0])
	}
	return nil
}
