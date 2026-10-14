package starttls

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// script runs a fake server: for each step it optionally expects a client
// line, then writes a reply. After the script it reads one byte (the
// client's first TLS byte) and reports it.
type step struct{ expect, reply string }

func fake(t *testing.T, steps []step, raw func(net.Conn)) (net.Conn, <-chan byte) {
	t.Helper()
	client, server := net.Pipe()
	got := make(chan byte, 1)
	go func() {
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(3 * time.Second))
		if raw != nil {
			raw(server)
		} else {
			br := bufio.NewReader(server)
			for _, s := range steps {
				if s.expect != "" {
					l, err := br.ReadString('\n')
					if err != nil || strings.TrimRight(l, "\r\n") != s.expect {
						t.Errorf("server expected %q, got %q (%v)", s.expect, l, err)
						return
					}
				}
				if _, err := io.WriteString(server, s.reply); err != nil {
					return
				}
			}
			server = &readerConn{Conn: server, r: br}
		}
		b := make([]byte, 1)
		if _, err := io.ReadFull(server, b); err == nil {
			got <- b[0]
		}
		close(got)
	}()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { client.Close() })
	return client, got
}

type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func finish(t *testing.T, c net.Conn, got <-chan byte) {
	t.Helper()
	if _, err := c.Write([]byte{0x16}); err != nil {
		t.Fatal(err)
	}
	if b := <-got; b != 0x16 {
		t.Fatalf("server saw 0x%02x after negotiation", b)
	}
}

func TestSMTP(t *testing.T) {
	c, got := fake(t, []step{
		{"", "220-mx.example ESMTP\r\n220 ready\r\n"},
		{"EHLO tlsaudit.invalid", "250-mx.example\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 8BITMIME\r\n"},
		{"STARTTLS", "220 2.0.0 go ahead\r\n"},
	}, nil)
	if err := Negotiate(c, "smtp"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, got)
}

func TestSMTPNoStartTLS(t *testing.T) {
	c, _ := fake(t, []step{
		{"", "220 mx ESMTP\r\n"},
		{"EHLO tlsaudit.invalid", "250-mx\r\n250 SIZE 1000\r\n"},
	}, nil)
	err := Negotiate(c, "smtp")
	if err == nil || !strings.Contains(err.Error(), "does not advertise") {
		t.Fatalf("got %v", err)
	}
}

func TestSMTPRefused(t *testing.T) {
	c, _ := fake(t, []step{{"", "554 no service\r\n"}}, nil)
	if err := Negotiate(c, "smtp"); err == nil || !strings.Contains(err.Error(), "554") {
		t.Fatalf("got %v", err)
	}
}

func TestIMAP(t *testing.T) {
	c, got := fake(t, []step{
		{"", "* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n"},
		{"a1 STARTTLS", "* note\r\na1 OK Begin TLS negotiation now\r\n"},
	}, nil)
	if err := Negotiate(c, "imap"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, got)
}

func TestPOP3AndFTP(t *testing.T) {
	c, got := fake(t, []step{{"", "+OK POP3 ready\r\n"}, {"STLS", "+OK begin\r\n"}}, nil)
	if err := Negotiate(c, "pop3"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, got)

	c, got = fake(t, []step{{"", "220 FTP\r\n"}, {"AUTH TLS", "234 AUTH TLS OK\r\n"}}, nil)
	if err := Negotiate(c, "ftp"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, got)

	c, _ = fake(t, []step{{"", "220 FTP\r\n"}, {"AUTH TLS", "500 nope\r\n"}}, nil)
	if err := Negotiate(c, "ftp"); err == nil {
		t.Fatal("refusal not reported")
	}
}

func TestPostgres(t *testing.T) {
	for _, answer := range []byte{'S', 'N'} {
		c, got := fake(t, nil, func(s net.Conn) {
			b := make([]byte, 8)
			if _, err := io.ReadFull(s, b); err != nil || !bytes.Equal(b, postgresSSLRequest) {
				t.Errorf("bad SSLRequest %x %v", b, err)
			}
			_, _ = s.Write([]byte{answer})
		})
		err := Negotiate(c, "postgres")
		if answer == 'S' {
			if err != nil {
				t.Fatal(err)
			}
			finish(t, c, got)
		} else if err == nil {
			t.Fatal("refusal not reported")
		}
	}
}

func TestLDAP(t *testing.T) {
	for code, ok := range map[byte]bool{0: true, 2: false} {
		c, got := fake(t, nil, func(s net.Conn) {
			b := make([]byte, len(ldapStartTLS))
			if _, err := io.ReadFull(s, b); err != nil || !bytes.Equal(b, ldapStartTLS) {
				t.Errorf("bad request %x %v", b, err)
			}
			// SEQUENCE { messageID 1, ExtendedResponse { resultCode, matchedDN "", diag "" } }
			_, _ = s.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, code, 0x04, 0x00, 0x04, 0x00})
		})
		err := Negotiate(c, "ldap")
		if ok {
			if err != nil {
				t.Fatal(err)
			}
			finish(t, c, got)
		} else if err == nil {
			t.Fatal("refusal not reported")
		}
	}
}

func TestUnknownAndNone(t *testing.T) {
	c, _ := net.Pipe()
	defer c.Close()
	if err := Negotiate(c, "xmpp"); err == nil {
		t.Fatal("xmpp accepted")
	}
	if err := Negotiate(c, ""); err != nil {
		t.Fatal(err)
	}
}
