package dnswire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// ErrShort is returned when a message ends prematurely.
var ErrShort = errors.New("dnswire: message truncated")

// maxPointers bounds compression pointer chains to defeat loops.
const maxPointers = 64

// Unpack decodes a wire-format DNS message.
func Unpack(b []byte) (*Msg, error) {
	if len(b) < 12 {
		return nil, ErrShort
	}
	m := &Msg{}
	m.ID = binary.BigEndian.Uint16(b[0:])
	flags := binary.BigEndian.Uint16(b[2:])
	m.Response = flags&(1<<15) != 0
	m.Opcode = uint8(flags>>11) & 0xf
	m.Authoritative = flags&(1<<10) != 0
	m.Truncated = flags&(1<<9) != 0
	m.RecursionDesired = flags&(1<<8) != 0
	m.RecursionAvailable = flags&(1<<7) != 0
	m.AuthenticData = flags&(1<<5) != 0
	m.CheckingDisabled = flags&(1<<4) != 0
	m.Rcode = int(flags & 0xf)

	qd := int(binary.BigEndian.Uint16(b[4:]))
	an := int(binary.BigEndian.Uint16(b[6:]))
	ns := int(binary.BigEndian.Uint16(b[8:]))
	ar := int(binary.BigEndian.Uint16(b[10:]))

	off := 12
	for i := 0; i < qd; i++ {
		name, n, err := readName(b, off)
		if err != nil {
			return nil, err
		}
		off = n
		if off+4 > len(b) {
			return nil, ErrShort
		}
		m.Question = append(m.Question, Question{
			Name:  name,
			Type:  Type(binary.BigEndian.Uint16(b[off:])),
			Class: binary.BigEndian.Uint16(b[off+2:]),
		})
		off += 4
	}
	var err error
	if m.Answer, off, err = readSection(b, off, an, m); err != nil {
		return nil, fmt.Errorf("answer section: %w", err)
	}
	if m.Authority, off, err = readSection(b, off, ns, m); err != nil {
		return nil, fmt.Errorf("authority section: %w", err)
	}
	if m.Additional, _, err = readSection(b, off, ar, m); err != nil {
		return nil, fmt.Errorf("additional section: %w", err)
	}
	return m, nil
}

func readSection(b []byte, off, count int, m *Msg) ([]RR, int, error) {
	var out []RR
	for i := 0; i < count; i++ {
		name, n, err := readName(b, off)
		if err != nil {
			return nil, 0, err
		}
		off = n
		if off+10 > len(b) {
			return nil, 0, ErrShort
		}
		t := Type(binary.BigEndian.Uint16(b[off:]))
		class := binary.BigEndian.Uint16(b[off+2:])
		ttl := binary.BigEndian.Uint32(b[off+4:])
		rdlen := int(binary.BigEndian.Uint16(b[off+8:]))
		off += 10
		if off+rdlen > len(b) {
			return nil, 0, ErrShort
		}
		if t == TypeOPT {
			if m.EDNS != nil {
				return nil, 0, errors.New("dnswire: multiple OPT records")
			}
			m.EDNS = &EDNS{
				UDPSize: class,
				Version: uint8(ttl >> 16),
				DO:      ttl&(1<<15) != 0,
			}
			m.Rcode |= int(ttl>>24) << 4
			off += rdlen
			continue
		}
		data, err := readRData(b, off, rdlen, t)
		if err != nil {
			return nil, 0, fmt.Errorf("%s %s: %w", name, t, err)
		}
		out = append(out, RR{Name: name, Type: t, Class: class, TTL: ttl, Data: data})
		off += rdlen
	}
	return out, off, nil
}

func readRData(msg []byte, off, rdlen int, t Type) (RData, error) {
	end := off + rdlen
	rd := msg[off:end]
	switch t {
	case TypeA:
		if rdlen != 4 {
			return nil, errors.New("bad A length")
		}
		return &A{Addr: netip.AddrFrom4([4]byte(rd))}, nil
	case TypeAAAA:
		if rdlen != 16 {
			return nil, errors.New("bad AAAA length")
		}
		return &AAAA{Addr: netip.AddrFrom16([16]byte(rd))}, nil
	case TypeNS, TypeCNAME:
		name, n, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		if n != end {
			return nil, errors.New("trailing RDATA")
		}
		if t == TypeNS {
			return &NS{Host: name}, nil
		}
		return &CNAME{Target: name}, nil
	case TypeSOA:
		mname, n, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		rname, n, err := readName(msg, n)
		if err != nil {
			return nil, err
		}
		if end-n != 20 {
			return nil, errors.New("bad SOA length")
		}
		v := func(i int) uint32 { return binary.BigEndian.Uint32(msg[n+4*i:]) }
		return &SOA{MName: mname, RName: rname, Serial: v(0), Refresh: v(1), Retry: v(2), Expire: v(3), Minimum: v(4)}, nil
	case TypeDS:
		if rdlen < 5 {
			return nil, errors.New("bad DS length")
		}
		return &DS{
			KeyTag:     binary.BigEndian.Uint16(rd),
			Algorithm:  rd[2],
			DigestType: rd[3],
			Digest:     append([]byte(nil), rd[4:]...),
		}, nil
	case TypeDNSKEY:
		if rdlen < 5 {
			return nil, errors.New("bad DNSKEY length")
		}
		return &DNSKEY{
			Flags:     binary.BigEndian.Uint16(rd),
			Protocol:  rd[2],
			Algorithm: rd[3],
			PublicKey: append([]byte(nil), rd[4:]...),
		}, nil
	case TypeRRSIG:
		if rdlen < 19 {
			return nil, errors.New("bad RRSIG length")
		}
		// Signer name must not be compressed (RFC 4034 3.1.7), but we read
		// it with the general routine and only accept it if it stays
		// within the RDATA.
		signer, n, err := readName(msg, off+18)
		if err != nil {
			return nil, err
		}
		if n > end {
			return nil, errors.New("RRSIG signer overruns RDATA")
		}
		return &RRSIG{
			TypeCovered: Type(binary.BigEndian.Uint16(rd)),
			Algorithm:   rd[2],
			Labels:      rd[3],
			OrigTTL:     binary.BigEndian.Uint32(rd[4:]),
			Expiration:  binary.BigEndian.Uint32(rd[8:]),
			Inception:   binary.BigEndian.Uint32(rd[12:]),
			KeyTag:      binary.BigEndian.Uint16(rd[16:]),
			SignerName:  signer,
			Signature:   append([]byte(nil), msg[n:end]...),
		}, nil
	default:
		return &Unknown{Raw: append([]byte(nil), rd...)}, nil
	}
}

// readName decodes a possibly compressed name starting at off. It returns
// the name and the offset just past the name in the original position.
func readName(b []byte, off int) (string, int, error) {
	var labels [][]byte
	next := -1
	ptrs := 0
	wireLen := 0
	for {
		if off >= len(b) {
			return "", 0, ErrShort
		}
		c := int(b[off])
		switch c & 0xc0 {
		case 0x00:
			if c == 0 {
				off++
				if next < 0 {
					next = off
				}
				wireLen++
				if wireLen > maxNameLen {
					return "", 0, ErrNameTooLong
				}
				return joinLabels(labels), next, nil
			}
			if off+1+c > len(b) {
				return "", 0, ErrShort
			}
			labels = append(labels, b[off+1:off+1+c])
			wireLen += 1 + c
			if wireLen > maxNameLen {
				return "", 0, ErrNameTooLong
			}
			off += 1 + c
		case 0xc0:
			if off+1 >= len(b) {
				return "", 0, ErrShort
			}
			ptr := (c&0x3f)<<8 | int(b[off+1])
			if next < 0 {
				next = off + 2
			}
			ptrs++
			if ptrs > maxPointers {
				return "", 0, errors.New("dnswire: compression pointer loop")
			}
			// Pointers must point strictly backwards.
			if ptr >= off {
				return "", 0, errors.New("dnswire: forward compression pointer")
			}
			off = ptr
		default:
			return "", 0, errors.New("dnswire: unsupported label type")
		}
	}
}
