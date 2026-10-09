package dnswire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Type is a DNS RR type.
type Type uint16

// RR types used by dnsdoctor.
const (
	TypeA      Type = 1
	TypeNS     Type = 2
	TypeCNAME  Type = 5
	TypeSOA    Type = 6
	TypeMX     Type = 15
	TypeTXT    Type = 16
	TypeAAAA   Type = 28
	TypeOPT    Type = 41
	TypeDS     Type = 43
	TypeRRSIG  Type = 46
	TypeNSEC   Type = 47
	TypeDNSKEY Type = 48
	TypeNSEC3  Type = 50
)

var typeNames = map[Type]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypeMX: "MX",
	TypeTXT: "TXT", TypeAAAA: "AAAA", TypeOPT: "OPT", TypeDS: "DS",
	TypeRRSIG: "RRSIG", TypeNSEC: "NSEC", TypeDNSKEY: "DNSKEY", TypeNSEC3: "NSEC3",
}

func (t Type) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", uint16(t))
}

// ClassINET is the Internet class.
const ClassINET uint16 = 1

// Response codes.
const (
	RcodeSuccess  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5
	RcodeNotAuth  = 9
	RcodeBadVers  = 16
)

var rcodeNames = map[int]string{
	0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
	5: "REFUSED", 9: "NOTAUTH", 16: "BADVERS",
}

// RcodeString returns the mnemonic for an rcode.
func RcodeString(rc int) string {
	if s, ok := rcodeNames[rc]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", rc)
}

// Header holds the DNS message header flags.
type Header struct {
	ID                 uint16
	Response           bool
	Opcode             uint8
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	AuthenticData      bool
	CheckingDisabled   bool
	// Rcode is the full (possibly EDNS-extended) response code.
	Rcode int
}

// Question is a DNS question.
type Question struct {
	Name  string
	Type  Type
	Class uint16
}

// EDNS carries the OPT pseudo-RR fields (RFC 6891).
type EDNS struct {
	UDPSize uint16
	Version uint8
	DO      bool
}

// RR is a resource record.
type RR struct {
	Name  string
	Type  Type
	Class uint16
	TTL   uint32
	Data  RData
}

// RData is implemented by every concrete RDATA type.
type RData interface {
	// pack appends the wire RDATA. Names are uncompressed; when canonical
	// is true, embedded names are lowercased where RFC 4034 section 6.2
	// (as amended by RFC 6840 section 5.1) requires it.
	pack(b []byte, canonical bool) ([]byte, error)
	String() string
}

// A is an IPv4 address record.
type A struct{ Addr netip.Addr }

// AAAA is an IPv6 address record.
type AAAA struct{ Addr netip.Addr }

// NS is a name server record.
type NS struct{ Host string }

// CNAME is a canonical name record.
type CNAME struct{ Target string }

// SOA is a start of authority record.
type SOA struct {
	MName, RName                            string
	Serial, Refresh, Retry, Expire, Minimum uint32
}

// DS is a delegation signer record (RFC 4034 section 5).
type DS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

// DNSKEY is a DNS public key record (RFC 4034 section 2).
type DNSKEY struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey []byte
}

// RRSIG is a signature record (RFC 4034 section 3).
type RRSIG struct {
	TypeCovered Type
	Algorithm   uint8
	Labels      uint8
	OrigTTL     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string
	Signature   []byte
}

// Unknown holds RDATA of a type dnsdoctor does not interpret.
type Unknown struct{ Raw []byte }

func (r *A) pack(b []byte, _ bool) ([]byte, error) {
	if !r.Addr.Is4() {
		return nil, errors.New("dnswire: A record with non-IPv4 address")
	}
	a := r.Addr.As4()
	return append(b, a[:]...), nil
}
func (r *A) String() string { return r.Addr.String() }

func (r *AAAA) pack(b []byte, _ bool) ([]byte, error) {
	if !r.Addr.Is6() || r.Addr.Is4In6() {
		return nil, errors.New("dnswire: AAAA record with non-IPv6 address")
	}
	a := r.Addr.As16()
	return append(b, a[:]...), nil
}
func (r *AAAA) String() string { return r.Addr.String() }

func (r *NS) pack(b []byte, c bool) ([]byte, error) { return appendName(b, r.Host, c) }
func (r *NS) String() string                        { return r.Host }

func (r *CNAME) pack(b []byte, c bool) ([]byte, error) { return appendName(b, r.Target, c) }
func (r *CNAME) String() string                        { return r.Target }

func (r *SOA) pack(b []byte, c bool) ([]byte, error) {
	var err error
	if b, err = appendName(b, r.MName, c); err != nil {
		return nil, err
	}
	if b, err = appendName(b, r.RName, c); err != nil {
		return nil, err
	}
	for _, v := range []uint32{r.Serial, r.Refresh, r.Retry, r.Expire, r.Minimum} {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return b, nil
}
func (r *SOA) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", r.MName, r.RName, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minimum)
}

func (r *DS) pack(b []byte, _ bool) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, r.KeyTag)
	b = append(b, r.Algorithm, r.DigestType)
	return append(b, r.Digest...), nil
}
func (r *DS) String() string {
	return fmt.Sprintf("%d %d %d %s", r.KeyTag, r.Algorithm, r.DigestType, strings.ToUpper(fmt.Sprintf("%x", r.Digest)))
}

func (r *DNSKEY) pack(b []byte, _ bool) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, r.Flags)
	b = append(b, r.Protocol, r.Algorithm)
	return append(b, r.PublicKey...), nil
}
func (r *DNSKEY) String() string {
	return fmt.Sprintf("%d %d %d (%d-byte key)", r.Flags, r.Protocol, r.Algorithm, len(r.PublicKey))
}

// PackNoSig returns the RRSIG RDATA without the signature field, with the
// signer name in canonical form, as required by RFC 4034 section 3.1.8.1.
func (r *RRSIG) PackNoSig() ([]byte, error) {
	b := binary.BigEndian.AppendUint16(nil, uint16(r.TypeCovered))
	b = append(b, r.Algorithm, r.Labels)
	b = binary.BigEndian.AppendUint32(b, r.OrigTTL)
	b = binary.BigEndian.AppendUint32(b, r.Expiration)
	b = binary.BigEndian.AppendUint32(b, r.Inception)
	b = binary.BigEndian.AppendUint16(b, r.KeyTag)
	return appendName(b, r.SignerName, true)
}

func (r *RRSIG) pack(b []byte, _ bool) ([]byte, error) {
	head, err := r.PackNoSig()
	if err != nil {
		return nil, err
	}
	b = append(b, head...)
	return append(b, r.Signature...), nil
}
func (r *RRSIG) String() string {
	return fmt.Sprintf("%s %d %d %d %d %d %d %s", r.TypeCovered, r.Algorithm, r.Labels, r.OrigTTL, r.Expiration, r.Inception, r.KeyTag, r.SignerName)
}

func (r *Unknown) pack(b []byte, _ bool) ([]byte, error) { return append(b, r.Raw...), nil }
func (r *Unknown) String() string                        { return fmt.Sprintf("\\# %d %x", len(r.Raw), r.Raw) }

func appendName(b []byte, name string, canonical bool) ([]byte, error) {
	w, err := nameWire(name, canonical)
	if err != nil {
		return nil, err
	}
	return append(b, w...), nil
}

// String renders an RR in a zone-file-like format.
func (rr RR) String() string {
	return fmt.Sprintf("%s\t%d\tIN\t%s\t%s", rr.Name, rr.TTL, rr.Type, rr.Data)
}

// PackRData returns the wire RDATA of rr, optionally in canonical form.
func PackRData(rr RR, canonical bool) ([]byte, error) {
	if rr.Data == nil {
		return nil, nil
	}
	return rr.Data.pack(nil, canonical)
}

// Msg is a DNS message.
type Msg struct {
	Header
	Question   []Question
	Answer     []RR
	Authority  []RR
	Additional []RR
	// EDNS is non-nil if the message carries an OPT record.
	EDNS *EDNS
}

// NewQuery builds a non-recursive query with EDNS0 and, optionally, the DO bit.
func NewQuery(id uint16, name string, t Type, do bool) *Msg {
	return &Msg{
		Header:   Header{ID: id},
		Question: []Question{{Name: Fqdn(name), Type: t, Class: ClassINET}},
		EDNS:     &EDNS{UDPSize: 1232, DO: do},
	}
}

// Pack encodes the message without name compression.
func (m *Msg) Pack() ([]byte, error) {
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:], m.ID)
	var flags uint16
	if m.Response {
		flags |= 1 << 15
	}
	flags |= uint16(m.Opcode&0xf) << 11
	if m.Authoritative {
		flags |= 1 << 10
	}
	if m.Truncated {
		flags |= 1 << 9
	}
	if m.RecursionDesired {
		flags |= 1 << 8
	}
	if m.RecursionAvailable {
		flags |= 1 << 7
	}
	if m.AuthenticData {
		flags |= 1 << 5
	}
	if m.CheckingDisabled {
		flags |= 1 << 4
	}
	flags |= uint16(m.Rcode & 0xf)
	binary.BigEndian.PutUint16(b[2:], flags)
	arcount := len(m.Additional)
	if m.EDNS != nil {
		arcount++
	}
	binary.BigEndian.PutUint16(b[4:], uint16(len(m.Question)))
	binary.BigEndian.PutUint16(b[6:], uint16(len(m.Answer)))
	binary.BigEndian.PutUint16(b[8:], uint16(len(m.Authority)))
	binary.BigEndian.PutUint16(b[10:], uint16(arcount))

	var err error
	for _, q := range m.Question {
		if b, err = appendName(b, q.Name, false); err != nil {
			return nil, err
		}
		b = binary.BigEndian.AppendUint16(b, uint16(q.Type))
		b = binary.BigEndian.AppendUint16(b, q.Class)
	}
	for _, sec := range [][]RR{m.Answer, m.Authority, m.Additional} {
		for _, rr := range sec {
			if b, err = appendRR(b, rr); err != nil {
				return nil, err
			}
		}
	}
	if m.EDNS != nil {
		b = append(b, 0) // root owner
		b = binary.BigEndian.AppendUint16(b, uint16(TypeOPT))
		b = binary.BigEndian.AppendUint16(b, m.EDNS.UDPSize)
		ttl := uint32(m.Rcode>>4)<<24 | uint32(m.EDNS.Version)<<16
		if m.EDNS.DO {
			ttl |= 1 << 15
		}
		b = binary.BigEndian.AppendUint32(b, ttl)
		b = binary.BigEndian.AppendUint16(b, 0) // no options
	}
	return b, nil
}

func appendRR(b []byte, rr RR) ([]byte, error) {
	var err error
	if b, err = appendName(b, rr.Name, false); err != nil {
		return nil, err
	}
	class := rr.Class
	if class == 0 {
		class = ClassINET
	}
	b = binary.BigEndian.AppendUint16(b, uint16(rr.Type))
	b = binary.BigEndian.AppendUint16(b, class)
	b = binary.BigEndian.AppendUint32(b, rr.TTL)
	lenAt := len(b)
	b = append(b, 0, 0)
	if rr.Data != nil {
		if b, err = rr.Data.pack(b, false); err != nil {
			return nil, err
		}
	}
	rdlen := len(b) - lenAt - 2
	if rdlen > 0xffff {
		return nil, errors.New("dnswire: RDATA too long")
	}
	binary.BigEndian.PutUint16(b[lenAt:], uint16(rdlen))
	return b, nil
}
